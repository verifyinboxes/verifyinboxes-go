package verifyinboxes_test

// A scripted fake of the VerifyInboxes API on 127.0.0.1, for the tests, and what the tests share with it.
//
// It serves the exchanges of one conformance scenario (the format is in testdata/conformance and is described in
// conformance_test.go): in order, or, when unordered, each request matched to the first unused exchange with the same
// method, path and body. It records every request, and can drop a connection ("drop": true) or cut an answer short
// ("cut_after": <bytes>), both through http.Hijacker.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	verifyinboxes "github.com/verifyinboxes/verifyinboxes-go"
)

// ---- JSON, told apart by type --------------------------------------------------------------------------------------

// decodeStrict reads JSON so that true, 1 and 1.0 stay three different things: numbers become json.Number, which
// keeps the number as it was written.
func decodeStrict(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("more than one JSON value")
	}
	return out, nil
}

// whole reports whether a JSON number was written as a whole number: 1 is, 1.0 and 1e3 are not, as JSON's own
// types say.
func whole(n json.Number) bool { return !strings.ContainsAny(string(n), ".eE") }

func sameNumber(a, b json.Number) bool {
	x, errA := a.Float64()
	y, errB := b.Float64()
	return errA == nil && errB == nil && x == y
}

// strictEqual is the equality of two values read by decodeStrict: a whole number never equals a boolean or a
// fractional one, and an object has exactly the same keys.
func strictEqual(got, want any) bool {
	switch w := want.(type) {
	case json.Number:
		g, ok := got.(json.Number)
		return ok && whole(g) == whole(w) && sameNumber(g, w)
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if !strictEqual(g[i], w[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for k, v := range w {
			gv, ok := g[k]
			if !ok || !strictEqual(gv, v) {
				return false
			}
		}
		return true
	default:
		return got == want
	}
}

// wire is what a call returned, as the API names it: its JSON, read by decodeStrict.
func wire[T any](v T, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return decodeStrict(data)
}

// ---- the scenario format -------------------------------------------------------------------------------------------

type scenarioFile struct {
	Format     int               `json:"format"`
	APIKey     string            `json:"api_key"`
	Scenarios  []scenario        `json:"scenarios"`
	Signatures []signatureVector `json:"signatures"`
}

type scenario struct {
	Name   string `json:"name"`
	About  string `json:"about"`
	Client struct {
		MaxRetries *int   `json:"max_retries"`
		APIKey     string `json:"api_key"`
	} `json:"client"`
	Call struct {
		Op   string         `json:"op"`
		Args map[string]any `json:"args"`
	} `json:"call"`
	Unordered bool            `json:"unordered"`
	Exchanges []exchange      `json:"exchanges"`
	Sleeps    json.RawMessage `json:"sleeps"`
	Outcome   struct {
		Returns json.RawMessage `json:"returns"`
		Raises  *raises         `json:"raises"`
		File    string          `json:"file"`
	} `json:"outcome"`
}

type raises struct {
	Kind                string          `json:"kind"`
	Status              *int            `json:"status"`
	Code                json.RawMessage `json:"code"`
	RequestID           *string         `json:"request_id"`
	RetryAfter          *float64        `json:"retry_after"`
	JobIDs              []string        `json:"job_ids"`
	MessageHasRequestID bool            `json:"message_has_request_id"`
}

type signatureVector struct {
	Name      string `json:"name"`
	Secret    string `json:"secret"`
	Body      string `json:"body"`
	Header    string `json:"header"`
	Now       int64  `json:"now"`
	Tolerance int64  `json:"tolerance"`
	Valid     bool   `json:"valid"`
}

type exchange struct {
	Request  expectedRequest  `json:"request"`
	Response scriptedResponse `json:"response"`
}

// part is one part of a multipart/form-data body: a field, or a file when it has a filename.
type part struct {
	Name        string  `json:"name"`
	Filename    *string `json:"filename,omitempty"`
	ContentType *string `json:"content_type,omitempty"`
	Value       string  `json:"value"`
}

type expectedRequest struct {
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	Query          map[string]string `json:"query"`
	JSON           json.RawMessage   `json:"json"`
	Multipart      []part            `json:"multipart"`
	Headers        map[string]string `json:"headers"`
	IdempotencyKey json.RawMessage   `json:"idempotency_key"`
}

type scriptedResponse struct {
	Operation *string           `json:"operation"`
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers"`
	JSON      json.RawMessage   `json:"json"`
	Text      *string           `json:"text"`
	Drop      bool              `json:"drop"`
	CutAfter  *int              `json:"cut_after"`
}

// readScenarios reads the shared scenario file.
func readScenarios(t testing.TB) *scenarioFile {
	t.Helper()
	data, err := readTestdata("conformance/scenarios.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var file scenarioFile
	if err := dec.Decode(&file); err != nil {
		t.Fatalf("reading the scenarios: %v", err)
	}
	return &file
}

// ---- the server ----------------------------------------------------------------------------------------------------

// unexpectedStatus is what the server answers to a request the scenario does not have: a status no API gives.
const unexpectedStatus = 599

// warmPath answers 204 and is never recorded: a client asks it first, so that its next request goes out on a
// connection already used once (net/http treats such a connection differently when it fails).
const warmPath = "/__warm"

// recorded is one request as the fake server read it.
type recorded struct {
	Method string
	// Path is the path as it was sent, still escaped, without the query.
	Path     string
	RawQuery string
	Header   http.Header
	Body     []byte
	// JSON is the body read by decodeStrict, when it was sent as JSON.
	JSON      any
	Multipart []part
}

func (r *recorded) idempotencyKey() (string, bool) {
	values := r.Header.Values("Idempotency-Key")
	if len(values) == 0 {
		return "", false
	}
	return values[0], true
}

// sameRequest reports whether got is the request want describes: its method, path and body (how unordered matches).
func sameRequest(got *recorded, want *expectedRequest) bool {
	if got.Method != want.Method || got.Path != want.Path {
		return false
	}
	switch {
	case want.JSON != nil:
		w, err := decodeStrict(want.JSON)
		return err == nil && got.JSON != nil && strictEqual(got.JSON, w)
	case want.Multipart != nil:
		return reflect.DeepEqual(got.Multipart, want.Multipart)
	default:
		return len(got.Body) == 0
	}
}

type fakeOptions struct {
	unordered bool
	// holdUntil holds every answer until this many requests are in flight at once (or 10 seconds pass).
	holdUntil int
	// gated holds every answer, the requests read whole, until release (or 10 seconds pass).
	gated bool
}

type fakeAPI struct {
	URL       string
	exchanges []exchange
	opts      fakeOptions
	server    *httptest.Server

	mu          sync.Mutex
	requests    []*recorded
	matched     []*recorded
	unexpected  []*recorded
	inFlight    int
	maxInFlight int
	heldOut     bool
	waiting     []chan struct{}
	gate        chan struct{}
	gateOnce    sync.Once
}

// newFakeAPI serves exchanges on 127.0.0.1 until the test ends.
func newFakeAPI(t testing.TB, exchanges []exchange, opts fakeOptions) *fakeAPI {
	t.Helper()
	api := &fakeAPI{exchanges: exchanges, opts: opts, matched: make([]*recorded, len(exchanges)), gate: make(chan struct{})}
	api.server = httptest.NewServer(api)
	api.URL = api.server.URL
	t.Cleanup(func() {
		api.release()
		api.server.CloseClientConnections()
		api.server.Close()
	})
	return api
}

// release lets the answers held by gated go, and every later one straight away.
func (f *fakeAPI) release() { f.gateOnce.Do(func() { close(f.gate) }) }

func (f *fakeAPI) recordedRequests() []*recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*recorded(nil), f.requests...)
}

// seen is what the server saw, read under its lock: the request each exchange was used for (nil: never), the
// requests no exchange was left for, whether holdUntil gave up waiting, and the most requests in flight at once.
func (f *fakeAPI) seen() (matched, unexpected []*recorded, heldOut bool, maxInFlight int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*recorded(nil), f.matched...), append([]*recorded(nil), f.unexpected...), f.heldOut, f.maxInFlight
}

func (f *fakeAPI) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeAPI) record(r *http.Request) *recorded {
	body, _ := io.ReadAll(r.Body)
	path, rawQuery, _ := strings.Cut(r.RequestURI, "?")
	rec := &recorded{Method: r.Method, Path: path, RawQuery: rawQuery, Header: r.Header.Clone(), Body: body}
	contentType := r.Header.Get("Content-Type")
	if len(body) > 0 && strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		if v, err := decodeStrict(body); err == nil {
			rec.JSON = v
		}
	}
	rec.Multipart = parseMultipart(body, contentType)
	return rec
}

func (f *fakeAPI) take(rec *recorded) *exchange {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, rec)
	index := -1
	if f.opts.unordered {
		for i := range f.exchanges {
			if f.matched[i] == nil && sameRequest(rec, &f.exchanges[i].Request) {
				index = i
				break
			}
		}
	} else {
		used := 0
		for _, m := range f.matched {
			if m != nil {
				used++
			}
		}
		if used < len(f.exchanges) {
			index = used
		}
	}
	if index < 0 {
		f.unexpected = append(f.unexpected, rec)
		return nil
	}
	f.matched[index] = rec
	return &f.exchanges[index]
}

func (f *fakeAPI) hold() {
	f.mu.Lock()
	f.inFlight++
	if f.inFlight > f.maxInFlight {
		f.maxInFlight = f.inFlight
	}
	if f.maxInFlight >= f.opts.holdUntil || f.heldOut {
		for _, ch := range f.waiting {
			close(ch)
		}
		f.waiting = nil
		f.mu.Unlock()
		return
	}
	ch := make(chan struct{})
	f.waiting = append(f.waiting, ch)
	f.mu.Unlock()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		f.mu.Lock()
		f.heldOut = true
		for _, w := range f.waiting {
			close(w)
		}
		f.waiting = nil
		f.mu.Unlock()
	}
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == warmPath {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rec := f.record(r)
	ex := f.take(rec)
	f.hold()
	defer func() {
		f.mu.Lock()
		f.inFlight--
		f.mu.Unlock()
	}()
	if f.opts.gated {
		select {
		case <-f.gate:
		case <-time.After(10 * time.Second):
		}
	}
	if ex == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(unexpectedStatus)
		_, _ = io.WriteString(w, `{"error":{"code":"unexpected_request","message":"not in the scenario"}}`)
		return
	}
	resp := ex.Response
	if resp.Drop {
		// The request was read whole; the connection closes with no answer.
		hijackAndClose(w, nil)
		return
	}
	headers := map[string]string{}
	for k, v := range resp.Headers {
		headers[k] = v
	}
	var data []byte
	if resp.JSON != nil {
		data = resp.JSON
		if _, ok := headers["content-type"]; !ok {
			headers["content-type"] = "application/json; charset=utf-8"
		}
	} else if resp.Text != nil {
		data = []byte(*resp.Text)
	}
	status := resp.Status
	if status == 0 {
		status = http.StatusOK
	}
	if resp.CutAfter != nil {
		// The headers promise the whole body; only its first bytes come before the connection closes.
		var raw bytes.Buffer
		fmt.Fprintf(&raw, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
		keys := make([]string, 0, len(headers))
		for k := range headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&raw, "%s: %s\r\n", k, headers[k])
		}
		fmt.Fprintf(&raw, "content-length: %d\r\n\r\n", len(data))
		raw.Write(data[:*resp.CutAfter])
		hijackAndClose(w, raw.Bytes())
		return
	}
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	if status != http.StatusNoContent {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	}
	w.WriteHeader(status)
	if status != http.StatusNoContent {
		_, _ = w.Write(data)
	}
}

// hijackAndClose writes raw (if any) straight to the connection, then closes it.
func hijackAndClose(w http.ResponseWriter, raw []byte) {
	conn, buf, err := w.(http.Hijacker).Hijack()
	if err != nil {
		panic(err)
	}
	if raw != nil {
		_, _ = buf.Write(raw)
		_ = buf.Flush()
	}
	_ = conn.Close()
}

// parseMultipart is the parts of a multipart/form-data body, in order; nil when the body is not multipart.
func parseMultipart(body []byte, contentType string) []part {
	media, params, err := mime.ParseMediaType(contentType)
	if err != nil || media != "multipart/form-data" || params["boundary"] == "" {
		return nil
	}
	reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	parts := []part{}
	for {
		p, err := reader.NextRawPart()
		if err != nil {
			return parts
		}
		value, _ := io.ReadAll(p)
		_, disposition, _ := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
		got := part{Name: disposition["name"], Value: string(value)}
		if filename, ok := disposition["filename"]; ok {
			contentType := p.Header.Get("Content-Type")
			got.Filename, got.ContentType = &filename, &contentType
		}
		parts = append(parts, got)
	}
}

// ---- what the tests share ------------------------------------------------------------------------------------------

const (
	// testKey is made up: the API refuses it.
	testKey   = "bv_testtesttesttesttesttesttesttest"
	jobID     = "019a3b71-3c4d-7e5f-8a6b-7c8d9e0f1a2b"
	requestID = "019a7e00-0000-7000-8000-0000000000aa"
	secret    = "6f1d0c9e8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e"
)

// answerWith is a scripted answer: status, a JSON body (nil: none), and the headers given (an x-request-id always).
func answerWith(status int, body any, headers ...string) scriptedResponse {
	h := map[string]string{"x-request-id": requestID}
	for i := 0; i+1 < len(headers); i += 2 {
		h[strings.ToLower(headers[i])] = headers[i+1]
	}
	resp := scriptedResponse{Status: status, Headers: h}
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			panic(err)
		}
		resp.JSON = data
	}
	return resp
}

// textAnswer is a scripted answer with a body that is not JSON.
func textAnswer(status int, contentType, text string) scriptedResponse {
	return scriptedResponse{Status: status, Headers: map[string]string{"x-request-id": requestID, "content-type": contentType}, Text: &text}
}

var dropped = scriptedResponse{Drop: true}

// on is an exchange: what the server expects (method, path, and a JSON body if given) and what it answers.
func on(method, path string, resp scriptedResponse, body ...any) exchange {
	req := expectedRequest{Method: method, Path: path}
	if len(body) == 1 {
		data, err := json.Marshal(body[0])
		if err != nil {
			panic(err)
		}
		req.JSON = data
	}
	return exchange{Request: req, Response: resp}
}

func apiError(code, message string) map[string]any {
	return map[string]any{"error": map[string]any{"code": code, "message": message}}
}

func resultJSON(email, verdict string) map[string]any {
	return map[string]any{
		"email": email, "verdict": verdict, "score": nil, "safe_to_send": false, "flags": []string{},
		"provider": "google", "catch_all_domain": false, "verified_at": "2026-11-18T10:12:00.123Z", "source": "smtp",
		"reason": "mailbox_not_found",
	}
}

func withJob(result map[string]any, id string) map[string]any {
	out := map[string]any{"job_id": id}
	for k, v := range result {
		out[k] = v
	}
	return out
}

func singleJobID(n int) string { return fmt.Sprintf("019a3b6e-8f0c-7d2e-9a41-5c3e2f1b0b%02d", n) }

func runningJob(id, kind string) map[string]any {
	return map[string]any{
		"id": id, "kind": kind, "status": "running", "total": 1, "done": 0, "created_at": "2026-11-18T10:00:00Z",
		"finished_at": nil, "counts": nil, "purged": false,
	}
}

// paperClock is the client's sleep and clock for a test: each sleep is written down and moves the clock, and nothing
// waits.
type paperClock struct {
	mu    sync.Mutex
	now   time.Time
	slept []time.Duration
}

func newPaperClock() *paperClock { return &paperClock{now: time.Unix(1_000_000_000, 0)} }

func (p *paperClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.slept = append(p.slept, d)
	p.now = p.now.Add(d)
	return nil
}

func (p *paperClock) clock() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.now
}

func (p *paperClock) sleeps() []time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]time.Duration(nil), p.slept...)
}

// realSleep waits as the client's own sleep does: d, or until ctx is done.
func realSleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// newHTTPClient is an HTTP client with a connection pool of its own, closed when the test ends.
func newHTTPClient(t testing.TB) *http.Client {
	transport := &http.Transport{}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

// clientOf is a client of api with the made-up key; with clock, its sleeps and clock are the paper ones (and its
// jitter the largest, so that a backoff is at its ceiling).
func clientOf(t testing.TB, api *fakeAPI, clock *paperClock, opts ...verifyinboxes.Option) (*verifyinboxes.Client, *http.Client) {
	t.Helper()
	hc := newHTTPClient(t)
	all := append([]verifyinboxes.Option{
		verifyinboxes.WithAPIKey(testKey), verifyinboxes.WithBaseURL(api.URL), verifyinboxes.WithHTTPClient(hc),
	}, opts...)
	client, err := verifyinboxes.NewClient(all...)
	if err != nil {
		t.Fatal(err)
	}
	if clock != nil {
		verifyinboxes.SetHooks(client, clock.sleep, clock.clock, nil)
	}
	return client, hc
}

// warm makes one request to api on hc and reads its answer, so that hc's next request reuses that connection.
func warm(t testing.TB, hc *http.Client, api *fakeAPI) {
	t.Helper()
	resp, err := hc.Get(api.URL + warmPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// until waits for ok (at most 5 seconds).
func until(t testing.TB, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("waited 5 seconds for %s", what)
}

// errorOf runs fn and returns its error, failing the test when it has none.
func errorOf(t testing.TB, err error) error {
	t.Helper()
	if err == nil {
		t.Fatal("no error")
	}
	return err
}
