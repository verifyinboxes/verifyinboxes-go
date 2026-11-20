package verifyinboxes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// checkTimeout is how long Verify and Checks.Wait wait by default.
	checkTimeout = 60 * time.Second
	// manyTimeout is how long VerifyMany waits by default.
	manyTimeout = 10 * time.Minute
	// pollInterval: a check's job is asked every 2 seconds.
	pollInterval = 2 * time.Second
	// singlesAtMost: VerifyMany checks up to this many addresses one by one, together...
	singlesAtMost = 10
	// singlesApart: ... started 100 ms apart.
	singlesApart = 100 * time.Millisecond
)

// listPolls are the pauses between asks for a list: 2, 4, 8, 16, then every 30 seconds.
var listPolls = []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}

// VerifyParams are the options of [Client.Verify] and [CheckService.Start]. A nil *VerifyParams is all defaults.
type VerifyParams struct {
	// ForceRecheck checks again rather than answer from the cache.
	ForceRecheck bool
	// Timeout is how long Verify waits for the result, from the call: 0 is 60 seconds, a negative value as long as
	// the context allows. Past it, a [*WaitTimeoutError] names the check's job: the check carries on. Start does
	// not wait, and does not use it.
	Timeout time.Duration
	// IdempotencyKey is your own Idempotency-Key for the check (1 to 255 visible ASCII characters); default: a new
	// one for the call. See the package documentation's "Retries".
	IdempotencyKey string
}

// VerifyManyParams are the options of [Client.VerifyMany]. A nil *VerifyManyParams is all defaults.
type VerifyManyParams struct {
	// Timeout is how long to wait for every result, from the call: 0 is 10 minutes, a negative value as long as the
	// context allows.
	Timeout time.Duration
}

// WaitParams are the options of [CheckService.Wait] and [ListService.Wait]. A nil *WaitParams is all defaults.
type WaitParams struct {
	// Timeout is how long to wait, from the call. For a check, 0 is 60 seconds; for a list, 0 is as long as the
	// context allows. A negative value is as long as the context allows. Past it, a [*WaitTimeoutError] is
	// returned: the job carries on.
	Timeout time.Duration
}

// deadline is when a wait gives up; a zero one never does (but for the context).
type deadline struct {
	at      time.Time
	timeout time.Duration
	set     bool
}

func (c *Client) deadlineOf(timeout, fallback time.Duration) deadline {
	if timeout == 0 {
		timeout = fallback
	}
	if timeout <= 0 {
		return deadline{}
	}
	return deadline{at: c.now().Add(timeout), timeout: timeout, set: true}
}

// pause is how long to sleep before the next ask: want, cut to the deadline.
func (d deadline) pause(now time.Time, want time.Duration) time.Duration {
	if d.set {
		if left := d.at.Sub(now); left < want {
			return left
		}
	}
	return want
}

func (d deadline) passed(now time.Time) bool { return d.set && !now.Before(d.at) }

// CheckService is one check by its job: started, as it is now, or waited for. [Client.Verify] starts a check and
// waits for it.
type CheckService struct{ client *Client }

// Verify checks one address and returns its result; JobID names the check's job.
//
// The API answers within about 5 seconds, or says the check is still running: then it is asked every 2 seconds until
// done. After p.Timeout (default 60 seconds) a [*WaitTimeoutError] names the job: the check carries on, and
// [CheckService.Wait] picks it up. When ctx ends, the request that starts the check, if it was already sent, is let
// finish, so that the error names the check it made ([JobIDs]).
//
// For many addresses use [Client.VerifyMany] or a list, never a loop of Verify.
func (c *Client) Verify(ctx context.Context, email string, p *VerifyParams) (*Result, error) {
	if p == nil {
		p = &VerifyParams{}
	}
	return c.verify(ctx, email, p, c.deadlineOf(p.Timeout, checkTimeout), nil)
}

// verify starts a check and waits for it; made is told its job as soon as the API names it.
func (c *Client) verify(ctx context.Context, email string, p *VerifyParams, d deadline, made func(string)) (*Result, error) {
	check, err := c.Checks.start(ctx, email, p, made)
	if err != nil {
		return nil, err
	}
	if !check.Pending {
		return check.Result, nil
	}
	return c.Checks.wait(ctx, check.JobID, d, false)
}

// Start checks one address without waiting: it returns the result when the API has it within about 5 seconds, or
// the check's job (Pending), to wait for with [CheckService.Wait]. p.Timeout is not used.
func (s *CheckService) Start(ctx context.Context, email string, p *VerifyParams) (*Check, error) {
	if p == nil {
		p = &VerifyParams{}
	}
	return s.start(ctx, email, p, nil)
}

// start sends POST /v1/verify. Once sent, it is let finish even if ctx ends, so the check it made is known: made is
// told its job, and the error names it.
func (s *CheckService) start(ctx context.Context, email string, p *VerifyParams, made func(string)) (*Check, error) {
	if strings.TrimSpace(email) == "" {
		return nil, errors.New("verifyinboxes: the address is empty")
	}
	key, err := idempotencyKey(p.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	body := struct {
		Email        string `json:"email"`
		ForceRecheck bool   `json:"force_recheck,omitempty"`
	}{email, p.ForceRecheck}
	got, err := s.client.doJSON(ctx, &request{
		method: http.MethodPost, path: "/v1/verify", body: body, key: key, finishOnCancel: true,
	}, nil)
	if err != nil {
		return nil, err
	}
	check, err := checkOf(got)
	if err != nil {
		return nil, err
	}
	var ids []string
	if check.JobID != "" {
		ids = []string{check.JobID}
		if made != nil {
			made(check.JobID)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, withJobs(err, ids, false)
	}
	return check, nil
}

// checkOf reads the answer to POST /v1/verify: a result, or a check still running (202).
func checkOf(a *answer) (*Check, error) {
	if a.status == http.StatusAccepted {
		var pending struct {
			JobID string `json:"job_id"`
		}
		if err := decode(a, &pending); err != nil {
			return nil, err
		}
		if pending.JobID == "" {
			return nil, unexpected(a.requestID, nil, "the API answered 202 to a check without its job_id")
		}
		return &Check{JobID: pending.JobID, Pending: true}, nil
	}
	var result Result
	if err := decode(a, &result); err != nil {
		return nil, err
	}
	return &Check{JobID: result.JobID, Result: &result}, nil
}

// Get returns a check's job as it is now (GET /v1/jobs/{id}); its Result once it is done.
func (s *CheckService) Get(ctx context.Context, jobID string) (*Job, error) {
	return s.client.getJob(ctx, jobID)
}

// Wait waits for a check that is still running (a pending [Check], or one a [*WaitTimeoutError] named) and returns
// its result. It asks at once, then every 2 seconds; after p.Timeout (default 60 seconds) a [*WaitTimeoutError] is
// returned: the check carries on. Every error names the check ([JobIDs]).
func (s *CheckService) Wait(ctx context.Context, jobID string, p *WaitParams) (*Result, error) {
	if jobID == "" {
		return nil, errors.New("verifyinboxes: the job id is empty")
	}
	if p == nil {
		p = &WaitParams{}
	}
	return s.wait(ctx, jobID, s.client.deadlineOf(p.Timeout, checkTimeout), true)
}

// wait polls a check's job until it is done, every 2 seconds; every error names the job.
func (s *CheckService) wait(ctx context.Context, jobID string, d deadline, askFirst bool) (*Result, error) {
	c, ids := s.client, []string{jobID}
	status := "pending"
	ask := func() (*Result, bool, error) {
		job, err := c.getJob(ctx, jobID)
		if err != nil {
			return nil, false, withJobs(err, ids, false)
		}
		if job.Status.active() {
			status = string(job.Status)
			return nil, false, nil
		}
		if job.Result == nil {
			return nil, false, unexpected("", ids, "the check %s ended %s without a result", job.ID, job.Status)
		}
		result := *job.Result
		result.JobID = job.ID
		return &result, true, nil
	}
	if askFirst {
		if result, done, err := ask(); err != nil || done {
			return result, err
		}
	}
	for {
		now := c.now()
		if d.passed(now) {
			return nil, &WaitTimeoutError{JobIDs: ids, Waited: d.timeout, what: "check", status: status}
		}
		if err := c.sleep(ctx, d.pause(now, pollInterval)); err != nil {
			return nil, withJobs(err, ids, false)
		}
		if result, done, err := ask(); err != nil || done {
			return result, err
		}
	}
}

// getJob is GET /v1/jobs/{id}.
func (c *Client) getJob(ctx context.Context, id string) (*Job, error) {
	path, err := jobPath(id, "")
	if err != nil {
		return nil, err
	}
	var job Job
	got, err := c.doJSON(ctx, &request{method: http.MethodGet, path: path}, &job)
	if err != nil {
		return nil, err
	}
	if job.ID == "" {
		return nil, unexpected(got.requestID, nil, "the API answered a job without its id")
	}
	return &job, nil
}

func jobPath(id, tail string) (string, error) {
	escaped, err := segment("job id", id)
	if err != nil {
		return "", err
	}
	return "/v1/jobs/" + escaped + tail, nil
}

// VerifyMany checks several addresses and returns their results in the same order.
//
// Up to 10 are checked one by one, together, started 100 ms apart. More go as one list (one POST /v1/jobs), waited
// for and read back: each result's JobID is then the list's. A few hundred addresses take minutes, Microsoft-hosted
// ones longer; raise p.Timeout (default 10 minutes) to match, or use a list yourself. Many addresses go through
// VerifyMany or a list, never a loop of [Client.Verify]: past 10 running checks, an owner's checks wait behind other
// work.
//
// An empty list, or an empty address, is refused before any request. An error, ctx's end included, names every job
// the call made, in input order ([JobIDs]): wait for them with [CheckService.Wait] or [ListService.Wait]. When ctx
// ends, the requests that start checks (or the list) and were already sent are let finish, so that their jobs are
// named; nothing more is started or waited for.
func (c *Client) VerifyMany(ctx context.Context, emails []string, p *VerifyManyParams) ([]Result, error) {
	if len(emails) == 0 {
		return nil, errors.New("verifyinboxes: no addresses: give one or more")
	}
	for i, email := range emails {
		if strings.TrimSpace(email) == "" {
			return nil, fmt.Errorf("verifyinboxes: emails[%d] is empty", i)
		}
	}
	if p == nil {
		p = &VerifyManyParams{}
	}
	d := c.deadlineOf(p.Timeout, manyTimeout)
	if len(emails) > singlesAtMost {
		return c.manyAsList(ctx, emails, d)
	}

	results := make([]Result, len(emails))
	errs := make([]error, len(emails))
	made := make([]string, len(emails))
	var (
		mu          sync.Mutex
		wg          sync.WaitGroup
		interrupted error
	)
	for i, email := range emails {
		if i > 0 {
			if err := c.sleep(ctx, singlesApart); err != nil {
				interrupted = err
				break
			}
		}
		wg.Add(1)
		go func(i int, email string) {
			defer wg.Done()
			result, err := c.verify(ctx, email, &VerifyParams{}, d, func(jobID string) {
				mu.Lock()
				defer mu.Unlock()
				made[i] = jobID
			})
			if err != nil {
				errs[i] = err
				return
			}
			results[i] = *result
		}(i, email)
	}
	// Every check started ends (by its result, its error or ctx) before anything is returned, so every job id made
	// is known.
	wg.Wait()
	var ids []string
	for _, id := range made {
		if id != "" {
			ids = append(ids, id)
		}
	}
	if interrupted != nil {
		return nil, withJobs(interrupted, ids, true)
	}
	for _, err := range errs {
		if err != nil {
			// The first error in input order, naming every job the call made.
			return nil, withJobs(err, ids, true)
		}
	}
	return results, nil
}

// manyAsList is VerifyMany of 11 addresses or more: one list, waited for and read back.
func (c *Client) manyAsList(ctx context.Context, emails []string, d deadline) ([]Result, error) {
	created, err := c.Lists.create(ctx, &CreateListParams{Emails: emails}, true)
	if err != nil {
		return nil, err
	}
	ids := []string{created.ID}
	if err := ctx.Err(); err != nil {
		return nil, withJobs(err, ids, true)
	}
	job, err := c.Lists.wait(ctx, created.ID, d)
	if err != nil {
		return nil, withJobs(err, ids, true)
	}
	if job.Status != JobDone {
		return nil, unexpected("", ids, "the list %s ended %s", created.ID, job.Status)
	}
	rows := map[int]ResultRow{}
	it := c.Lists.Results(ctx, created.ID, nil)
	for it.Next() {
		row := it.Current()
		rows[row.Row] = row
	}
	if err := it.Err(); err != nil {
		return nil, withJobs(err, ids, true)
	}
	results := make([]Result, len(emails))
	for i, email := range emails {
		// Row i is emails[i-1].
		row, ok := rows[i+1]
		if !ok {
			return nil, unexpected("", ids, "the list %s has no result for row %d (%s)", created.ID, i+1, email)
		}
		results[i] = row.Result
		results[i].JobID = created.ID
	}
	return results, nil
}
