package verifyinboxes

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
)

const (
	pageSize    = 500
	maxPageSize = 1000
)

// ListService is lists of addresses: made from a CSV or a list of addresses, waited for, read, downloaded and
// resolved.
type ListService struct{ client *Client }

// CreateListParams are what [ListService.Create] makes a list of: exactly one of Emails, File or CSV; and, for
// [ListService.CreateFromFile], none of them.
type CreateListParams struct {
	// Emails are the addresses, sent as JSON.
	Emails []string
	// File is a CSV with a header row. One that can seek (an *os.File, a *bytes.Reader) is sent again from where it
	// was on a retry; any other is read as it is sent, so it is never sent again once its sending began. It is
	// not closed.
	File io.Reader
	// CSV is a CSV's text, with a header row.
	CSV string
	// Filename is the name the upload carries. Default: the file's name for CreateFromFile, else list.csv.
	Filename string
	// EmailColumn is the header of the CSV's column of addresses. Default email.
	EmailColumn string
	// IdempotencyKey is your own Idempotency-Key (1 to 255 visible ASCII characters); default: a new one for the
	// call. A key names one request: see the package documentation's "Retries" before reusing one.
	IdempotencyKey string
}

// ResultsParams are the options of [ListService.Results] and [ListService.ResultsPage]. A nil *ResultsParams is
// all defaults.
type ResultsParams struct {
	// PageSize is how many rows each request asks for, 1 to 1000. Default (0) 500.
	PageSize int
	// OnlySafeToSend keeps the rows safe to send to.
	OnlySafeToSend bool
	// Verdicts keeps the rows of these verdicts (valid, invalid, catch_all, risky, unknown). Not with
	// OnlySafeToSend.
	Verdicts []string
	// Partial reads a list still running, as it stands (read it again from the start once it is done).
	Partial bool
}

// DownloadParams are the options of [ListService.Download] and [ListService.DownloadFile]: which rows. A nil
// *DownloadParams is every row.
type DownloadParams struct {
	// OnlySafeToSend keeps the rows safe to send to.
	OnlySafeToSend bool
	// Verdicts keeps the rows of these verdicts. Not with OnlySafeToSend.
	Verdicts []string
	// Partial downloads a list still running, as it stands.
	Partial bool
}

// ResolveParams are the options of [ListService.Resolve]. A nil *ResolveParams is all defaults.
type ResolveParams struct {
	// Emails are only these of the job's catch_all and risky addresses; default all of them.
	Emails []string
	// IdempotencyKey is your own Idempotency-Key; default: a new one for the call.
	IdempotencyKey string
}

// Create starts a list (POST /v1/jobs) from exactly one of p.Emails, p.File or p.CSV. Wait for it with
// [ListService.Wait].
//
// When its answer is lost it is sent again, with the same Idempotency-Key: the API answers the retry with the same
// list, so it is made and charged once.
//
// When ctx ends it stops at once, even when the request has already reached the API: the list may then exist
// without its id in the error. If you may cancel it, pass your own p.IdempotencyKey, and afterwards make the same
// call with the same key (within 24 hours): the API answers with what the first request answered (the list it
// made), or, if that one never ran, makes the list now, once.
func (s *ListService) Create(ctx context.Context, p *CreateListParams) (*JobCreated, error) {
	return s.create(ctx, p, false)
}

// CreateFromFile starts a list from the CSV file at path, read again for a retry. p (nil: defaults) may give
// Filename (default: the file's name), EmailColumn and IdempotencyKey, and none of Emails, File or CSV. As
// [ListService.Create] otherwise.
func (s *ListService) CreateFromFile(ctx context.Context, path string, p *CreateListParams) (*JobCreated, error) {
	if p == nil {
		p = &CreateListParams{}
	}
	if p.Emails != nil || p.File != nil || p.CSV != "" {
		return nil, errors.New("verifyinboxes: CreateFromFile takes the file's path, and none of Emails, File or CSV")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("verifyinboxes: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("verifyinboxes: not a file: %s", path)
	}
	filename := p.Filename
	if filename == "" {
		filename = filepath.Base(path)
	}
	up := newUpload(p.EmailColumn, filename)
	up.source = func() (io.Reader, int64, func(), error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("verifyinboxes: %w", err)
		}
		size := int64(-1)
		if info, err := f.Stat(); err == nil {
			size = info.Size()
		}
		return f, size, func() { _ = f.Close() }, nil
	}
	return s.send(ctx, up, p.IdempotencyKey, false)
}

// create is Create; finishOnCancel: once sent, the POST is not cut off by ctx (VerifyMany's list).
func (s *ListService) create(ctx context.Context, p *CreateListParams, finishOnCancel bool) (*JobCreated, error) {
	if p == nil {
		p = &CreateListParams{}
	}
	given := 0
	for _, set := range []bool{p.Emails != nil, p.File != nil, p.CSV != ""} {
		if set {
			given++
		}
	}
	if given != 1 {
		return nil, errors.New("verifyinboxes: give exactly one of Emails, File or CSV")
	}
	if p.Emails != nil {
		key, err := idempotencyKey(p.IdempotencyKey)
		if err != nil {
			return nil, err
		}
		body := struct {
			Emails []string `json:"emails"`
		}{p.Emails}
		var created JobCreated
		if _, err := s.client.doJSON(ctx, &request{
			method: http.MethodPost, path: "/v1/jobs", body: body, key: key, finishOnCancel: finishOnCancel,
		}, &created); err != nil {
			return nil, err
		}
		return &created, nil
	}
	filename := p.Filename
	if filename == "" {
		filename = "list.csv"
	}
	up := newUpload(p.EmailColumn, filename)
	if p.File != nil {
		up.fromReader(p.File)
	} else {
		data := []byte(p.CSV)
		up.source = func() (io.Reader, int64, func(), error) { return bytes.NewReader(data), int64(len(data)), nil, nil }
	}
	return s.send(ctx, up, p.IdempotencyKey, finishOnCancel)
}

func (s *ListService) send(ctx context.Context, up *upload, ownKey string, finishOnCancel bool) (*JobCreated, error) {
	key, err := idempotencyKey(ownKey)
	if err != nil {
		return nil, err
	}
	var created JobCreated
	if _, err := s.client.doJSON(ctx, &request{
		method: http.MethodPost, path: "/v1/jobs", upload: up, key: key, long: true, finishOnCancel: finishOnCancel,
	}, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

// Get returns a list as it is now (GET /v1/jobs/{id}).
func (s *ListService) Get(ctx context.Context, id string) (*Job, error) {
	return s.client.getJob(ctx, id)
}

// Wait waits for a list to finish and returns it. It asks at once, then after 2, 4, 8, 16 and then every 30
// seconds. After p.Timeout (default: none but the context's) a [*WaitTimeoutError] names the list: it carries on.
// Every error names the list ([JobIDs]). A few hundred addresses take minutes, Microsoft-hosted ones longer.
func (s *ListService) Wait(ctx context.Context, id string, p *WaitParams) (*Job, error) {
	if id == "" {
		return nil, errors.New("verifyinboxes: the job id is empty")
	}
	if p == nil {
		p = &WaitParams{}
	}
	return s.wait(ctx, id, s.client.deadlineOf(p.Timeout, -1))
}

// wait asks at once, then polls a list, backing off; every error names the list.
func (s *ListService) wait(ctx context.Context, id string, d deadline) (*Job, error) {
	c, ids := s.client, []string{id}
	job, err := c.getJob(ctx, id)
	if err != nil {
		return nil, withJobs(err, ids, false)
	}
	for asked := 0; job.Status.active(); asked++ {
		now := c.now()
		if d.passed(now) {
			return nil, &WaitTimeoutError{JobIDs: ids, Waited: d.timeout, what: "list", status: string(job.Status)}
		}
		if err := c.sleep(ctx, d.pause(now, listPolls[min(asked, len(listPolls)-1)])); err != nil {
			return nil, withJobs(err, ids, false)
		}
		if job, err = c.getJob(ctx, id); err != nil {
			return nil, withJobs(err, ids, false)
		}
	}
	return job, nil
}

// Results returns every row of a finished list, in order, read a page (p.PageSize rows) at a time as you iterate;
// nothing is asked until then. ctx governs every page: give one that lasts as long as the walk. See [Iter].
func (s *ListService) Results(ctx context.Context, id string, p *ResultsParams) *Iter[ResultRow] {
	path, query, err := resultsQuery(id, p)
	if err != nil {
		return failedIter[ResultRow](err)
	}
	return &Iter[ResultRow]{
		ctx: ctx,
		fetch: func(ctx context.Context, cursor *string) ([]ResultRow, *string, error) {
			page, err := s.page(ctx, path, query, cursor)
			if err != nil {
				return nil, nil, err
			}
			return page.Data, page.NextCursor, nil
		},
		sameCursor: func(cursor string) error {
			return unexpected("", []string{id}, "the API returned the same cursor twice (%q) while listing the "+
				"results of %s", cursor, id)
		},
	}
}

// ResultsPage returns one page of results, for keeping your own cursor: "" for the first page, then each page's
// NextCursor until it is nil. A page may hold fewer rows than asked, even none, before the last one.
func (s *ListService) ResultsPage(ctx context.Context, id, cursor string, p *ResultsParams) (*ResultsPage, error) {
	path, query, err := resultsQuery(id, p)
	if err != nil {
		return nil, err
	}
	var at *string
	if cursor != "" {
		at = &cursor
	}
	return s.page(ctx, path, query, at)
}

func (s *ListService) page(ctx context.Context, path string, filters url.Values, cursor *string) (*ResultsPage, error) {
	query := url.Values{}
	for k, v := range filters {
		query[k] = v
	}
	if cursor != nil {
		query.Set("cursor", *cursor)
	}
	var page ResultsPage
	got, err := s.client.doJSON(ctx, &request{method: http.MethodGet, path: path, query: query}, &page)
	if err != nil {
		return nil, err
	}
	if page.Data == nil {
		return nil, unexpected(got.requestID, nil, "the API answered a page of results without its rows")
	}
	return &page, nil
}

func resultsQuery(id string, p *ResultsParams) (string, url.Values, error) {
	if p == nil {
		p = &ResultsParams{}
	}
	path, err := jobPath(id, "/results")
	if err != nil {
		return "", nil, err
	}
	size := p.PageSize
	if size == 0 {
		size = pageSize
	}
	if size < 1 || size > maxPageSize {
		return "", nil, errors.New("verifyinboxes: the page size is 1 to 1000")
	}
	query, err := filterQuery(p.OnlySafeToSend, p.Verdicts, p.Partial)
	if err != nil {
		return "", nil, err
	}
	query.Set("limit", strconv.Itoa(size))
	return path, query, nil
}

// filterQuery is which rows of a list's results or download: only=safe_to_send, verdicts=a,b, partial=1.
func filterQuery(onlySafe bool, verdicts []string, partial bool) (url.Values, error) {
	query := url.Values{}
	if onlySafe && len(verdicts) > 0 {
		return nil, errors.New("verifyinboxes: give OnlySafeToSend or Verdicts, not both")
	}
	if onlySafe {
		query.Set("only", "safe_to_send")
	}
	if len(verdicts) > 0 {
		query.Set("verdicts", strings.Join(verdicts, ","))
	}
	if partial {
		query.Set("partial", "1")
	}
	return query, nil
}

func downloadRequest(id string, p *DownloadParams) (*request, error) {
	if p == nil {
		p = &DownloadParams{}
	}
	path, err := jobPath(id, "/download")
	if err != nil {
		return nil, err
	}
	query, err := filterQuery(p.OnlySafeToSend, p.Verdicts, p.Partial)
	if err != nil {
		return nil, err
	}
	return &request{method: http.MethodGet, path: path, query: query, long: true, accept: "text/csv"}, nil
}

// Download writes the CSV you sent, with the results appended (GET /v1/jobs/{id}/download), to w, and returns the
// bytes written. It is sent again until w has been given its first byte; after that a failure is returned.
func (s *ListService) Download(ctx context.Context, id string, w io.Writer, p *DownloadParams) (int64, error) {
	if w == nil {
		return 0, errors.New("verifyinboxes: Download needs a writer")
	}
	r, err := downloadRequest(id, p)
	if err != nil {
		return 0, err
	}
	var written int64
	err = s.client.roundTrip(ctx, r, func(resp *http.Response) error {
		n, err := copyBody(w, resp)
		written += n
		var cut *bodyCut
		if errors.As(err, &cut) && written > 0 {
			cut.final = true
		}
		return err
	})
	return written, err
}

// DownloadFile writes the download of [ListService.Download] to path, and returns the bytes written. It is written
// to a part file beside path, renamed over it once whole: a failed download leaves the file there was untouched and
// no part file behind, and is made again from the start.
func (s *ListService) DownloadFile(ctx context.Context, id, path string, p *DownloadParams) (int64, error) {
	if path == "" {
		return 0, errors.New("verifyinboxes: DownloadFile needs a path")
	}
	r, err := downloadRequest(id, p)
	if err != nil {
		return 0, err
	}
	var written int64
	err = s.client.roundTrip(ctx, r, func(resp *http.Response) error {
		part, err := openPart(path)
		if err != nil {
			return err
		}
		n, err := copyBody(part, resp)
		if err == nil {
			err = part.Sync()
		}
		if closeErr := part.Close(); err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Rename(part.Name(), path)
		}
		if err != nil {
			_ = os.Remove(part.Name())
			return err
		}
		written = n
		return nil
	})
	return written, err
}

// openPart makes the part file beside path: <path>.part-<random>.
func openPart(path string) (*os.File, error) {
	for i := 0; ; i++ {
		var b [6]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path+".part-"+hex.EncodeToString(b[:]), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
		if err == nil || !errors.Is(err, os.ErrExist) || i == 9 {
			if err != nil {
				return nil, fmt.Errorf("verifyinboxes: %w", err)
			}
			return f, nil
		}
	}
}

// copyBody copies an answer's body to w. A failure to read it is a *bodyCut (the answer stopped coming); a failure
// to write is returned as it is.
func copyBody(w io.Writer, resp *http.Response) (int64, error) {
	reader := &readFailure{r: resp.Body}
	n, err := io.Copy(w, reader)
	if reader.err != nil {
		return n, &bodyCut{err: reader.err}
	}
	if err != nil {
		return n, err
	}
	if resp.ContentLength >= 0 && !resp.Uncompressed && n != resp.ContentLength {
		return n, &bodyCut{err: fmt.Errorf("the answer ended after %d of its %d bytes", n, resp.ContentLength)}
	}
	return n, nil
}

// readFailure keeps the error of its reader, to tell it from the writer's.
type readFailure struct {
	r   io.Reader
	err error
}

func (r *readFailure) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if err != nil && err != io.EOF {
		r.err = err
	}
	return n, err
}

// Resolve sends a finished job's catch_all and risky addresses (all of them, or those in p.Emails) to be settled by
// a test email (POST /v1/jobs/{id}/resolve): most are settled within about 3 days of sending, some take up to 7. It
// is a job of its own: wait for it with [ListService.Wait].
//
// When ctx ends it stops at once, even when the request has already reached the API: as for [ListService.Create],
// pass your own p.IdempotencyKey if you may cancel it, and make the same call with the same key afterwards.
func (s *ListService) Resolve(ctx context.Context, id string, p *ResolveParams) (*ResolveCreated, error) {
	if p == nil {
		p = &ResolveParams{}
	}
	path, err := jobPath(id, "/resolve")
	if err != nil {
		return nil, err
	}
	key, err := idempotencyKey(p.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	r := &request{method: http.MethodPost, path: path, key: key}
	if p.Emails != nil {
		r.body = struct {
			Emails []string `json:"emails"`
		}{p.Emails}
	}
	var created ResolveCreated
	if _, err := s.client.doJSON(ctx, r, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

// ---- uploads -------------------------------------------------------------------------------------------------------

// upload is a CSV sent as multipart/form-data: the field email_column, then the file, typed text/csv. Its body is
// made again for every attempt: a path is opened again, a reader that seeks is rewound, and one that does not is
// sent once.
type upload struct {
	head, tail  []byte
	contentType string
	// source gives the file's bytes for one attempt, their length (-1: unknown) and what to do once it is over.
	source func() (io.Reader, int64, func(), error)
	// rewinds: the file is one reader, rewound for each attempt.
	rewinds bool
	// oneWay: the file is read as it is sent, so it cannot be sent again once its sending began (started).
	oneWay  bool
	started atomic.Bool
}

func newUpload(emailColumn, filename string) *upload {
	if emailColumn == "" {
		emailColumn = "email"
	}
	boundary := "verifyinboxes-" + strings.ReplaceAll(newKey(), "-", "")
	head := "--" + boundary + "\r\nContent-Disposition: form-data; name=\"email_column\"\r\n\r\n" + emailColumn + "\r\n" +
		"--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + formQuote(filename) +
		"\"\r\nContent-Type: text/csv\r\n\r\n"
	return &upload{
		head:        []byte(head),
		tail:        []byte("\r\n--" + boundary + "--\r\n"),
		contentType: "multipart/form-data; boundary=" + boundary,
	}
}

// formQuote makes a value safe inside a quoted Content-Disposition parameter.
func formQuote(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, "%22", "\r", "%0D", "\n", "%0A").Replace(value)
}

// fromReader sends r: rewound for a retry when it can seek, else sent once.
func (u *upload) fromReader(r io.Reader) {
	if seeker, ok := r.(io.Seeker); ok {
		if start, err := seeker.Seek(0, io.SeekCurrent); err == nil {
			if end, err := seeker.Seek(0, io.SeekEnd); err == nil {
				if _, err := seeker.Seek(start, io.SeekStart); err == nil {
					u.rewinds = true
					u.source = func() (io.Reader, int64, func(), error) {
						if _, err := seeker.Seek(start, io.SeekStart); err != nil {
							return nil, 0, nil, fmt.Errorf("verifyinboxes: rewinding the file: %w", err)
						}
						return r, end - start, nil, nil
					}
					return
				}
			}
		}
	}
	u.oneWay = true
	u.source = func() (io.Reader, int64, func(), error) {
		return &startedReader{r: r, started: &u.started}, -1, nil, nil
	}
}

// resendable reports whether a failed attempt can be made again: always, but for a reader sent once that began.
func (u *upload) resendable() bool { return !u.oneWay || !u.started.Load() }

// open is the body of one attempt and its length (-1: unknown).
func (u *upload) open() (io.ReadCloser, int64, error) {
	file, n, done, err := u.source()
	if err != nil {
		return nil, 0, err
	}
	length := int64(-1)
	if n >= 0 {
		length = int64(len(u.head)) + n + int64(len(u.tail))
	}
	return newBody(io.MultiReader(bytes.NewReader(u.head), file, bytes.NewReader(u.tail)), u.rewinds, done), length, nil
}

// startedReader notes the first read of a reader that can be read once.
type startedReader struct {
	r       io.Reader
	started *atomic.Bool
}

func (s *startedReader) Read(p []byte) (int, error) {
	s.started.Store(true)
	return s.r.Read(p)
}
