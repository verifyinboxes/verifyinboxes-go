package verifyinboxes

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The kinds of error. An error returned by this package matches one of them with [errors.Is]:
//
//	if errors.Is(err, verifyinboxes.ErrInsufficientCredits) { ... }
//
// An answer of the API is an [*APIError], which matches the sentinel of its status; a request that got no answer is
// a [*ConnectionError] ([ErrConnection], and [ErrTimeout] when the time ran out); a wait that ran out is a
// [*WaitTimeoutError] ([ErrWaitTimeout]). A wrong argument (an empty address, a page size of 0) is a plain error,
// returned before anything is sent.
var (
	// ErrMissingAPIKey is returned by [NewClient] when no key was given and VERIFYINBOXES_API_KEY is not set.
	ErrMissingAPIKey = errors.New("verifyinboxes: no API key: pass verifyinboxes.WithAPIKey(...) or set the " +
		EnvAPIKey + " environment variable; an organisation admin makes keys in the VerifyInboxes app under " +
		"Developers -> API keys")

	// ErrInvalidRequest is 400, 413, 414, 415 or 422: the request does not fit (invalid_request, consumer_list,
	// empty_list, ...).
	ErrInvalidRequest = errors.New("verifyinboxes: invalid request")
	// ErrAuthentication is 401: the key or token is missing, mistyped, revoked, or (a personal access token) past
	// its hour.
	ErrAuthentication = errors.New("verifyinboxes: not authenticated")
	// ErrInsufficientCredits is 402 insufficient_credits: the balance does not cover the request. Nothing was
	// charged.
	ErrInsufficientCredits = errors.New("verifyinboxes: insufficient credits")
	// ErrPermissionDenied is 403: allowed for nobody with this credential (forbidden, review_required,
	// account_suspended, ...).
	ErrPermissionDenied = errors.New("verifyinboxes: permission denied")
	// ErrNotFound is 404 not_found, or 410 gone (a list whose data was deleted).
	ErrNotFound = errors.New("verifyinboxes: not found")
	// ErrConflict is 409: not_ready (the list has not finished), idempotency_conflict (the key was used for
	// another request).
	ErrConflict = errors.New("verifyinboxes: conflict")
	// ErrRateLimited is 429: too many requests or lists at once. It is retried on its own, unless its Retry-After
	// is over 60 seconds.
	ErrRateLimited = errors.New("verifyinboxes: rate limited")
	// ErrServer is any 5xx: something went wrong on the API's side. It is retried on its own; the error returned is
	// the last answer's.
	ErrServer = errors.New("verifyinboxes: server error")

	// ErrConnection matches every [*ConnectionError]: the request got no answer.
	ErrConnection = errors.New("verifyinboxes: no answer")
	// ErrTimeout matches a [*ConnectionError] whose attempt ran out of time ([WithTimeout]).
	ErrTimeout = errors.New("verifyinboxes: no answer in time")
	// ErrWaitTimeout matches every [*WaitTimeoutError]: a check or a list was still running when the time to wait
	// ran out.
	ErrWaitTimeout = errors.New("verifyinboxes: still running")
	// ErrUnexpectedAnswer is an answer that breaks the API's own rules: a success that is not JSON, a job without
	// its id, a page of results that sends back the cursor it was asked for.
	ErrUnexpectedAnswer = errors.New("verifyinboxes: unexpected answer")
)

// APIError is an answer of the API with an error status (4xx or 5xx).
//
// Code is the API's stable error code (unauthorized, not_ready, consumer_list, ...): match on it, and treat one you
// do not know by its status. The message reads "<status> <code>: <what the API said> (request id <id>)": show it or
// log it, never parse it. RequestID is the answer's X-Request-Id: quote it when you write to support.
//
// It matches the sentinel of its status with [errors.Is]: [ErrInvalidRequest], [ErrAuthentication],
// [ErrInsufficientCredits], [ErrPermissionDenied], [ErrNotFound], [ErrConflict], [ErrRateLimited] or [ErrServer];
// any other status matches none.
type APIError struct {
	// StatusCode is the HTTP status.
	StatusCode int
	// Code is the API's error code; empty when the answer was not the API's (a proxy's error page).
	Code string
	// Message is what the API said, for a person; "The API answered <status>" when the answer was not the API's.
	Message string
	// RequestID is the answer's X-Request-Id. After retries, the last answer's.
	RequestID string
	// RetryAfter is the answer's Retry-After; zero when it had none.
	RetryAfter time.Duration
	// JobIDs are the jobs the call had made when it failed (see [JobIDs]).
	JobIDs []string
	// Body is the answer's body as it came.
	Body []byte

	retryAfterSet bool
}

// Error returns "<status> <code>: <message> (request id <id>)".
func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d", e.StatusCode)
	if e.Code != "" {
		b.WriteString(" " + e.Code)
	}
	b.WriteString(": " + e.Message)
	if e.RequestID != "" {
		b.WriteString(" (request id " + e.RequestID + ")")
	}
	return b.String()
}

// Is reports whether target is the sentinel of the error's status.
func (e *APIError) Is(target error) bool {
	s := e.StatusCode
	switch target {
	case ErrInvalidRequest:
		return s == 400 || s == 413 || s == 414 || s == 415 || s == 422
	case ErrAuthentication:
		return s == 401
	case ErrInsufficientCredits:
		return s == 402
	case ErrPermissionDenied:
		return s == 403
	case ErrNotFound:
		return s == 404 || s == 410
	case ErrConflict:
		return s == 409
	case ErrRateLimited:
		return s == 429
	case ErrServer:
		return s >= 500
	}
	return false
}

func (e *APIError) jobIDList() []string { return e.JobIDs }

// apiErrorOf is the error of an answer of 4xx or 5xx. The API's errors are {"error": {"code", "message"}}; a body
// that is not one (a proxy's HTML page) keeps its status, with no code.
func apiErrorOf(resp *http.Response, body []byte, now time.Time) *APIError {
	e := &APIError{StatusCode: resp.StatusCode, RequestID: resp.Header.Get("X-Request-Id"), Body: body}
	var shaped struct {
		Error *struct {
			Code    any `json:"code"`
			Message any `json:"message"`
		} `json:"error"`
	}
	if jsonUnmarshal(body, &shaped) == nil && shaped.Error != nil {
		e.Code, _ = shaped.Error.Code.(string)
		e.Message, _ = shaped.Error.Message.(string)
	}
	if e.Message == "" {
		e.Message = fmt.Sprintf("The API answered %d", resp.StatusCode)
	}
	e.RetryAfter, e.retryAfterSet = retryAfter(resp.Header.Get("Retry-After"), now)
	return e
}

// retryAfter reads a Retry-After header: seconds, or an HTTP date.
func retryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := parseSeconds(value); err == nil {
		return seconds, true
	}
	if at, err := http.ParseTime(value); err == nil {
		if d := at.Sub(now); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}

// ConnectionError is a request that got no answer: the connection could not be made, or it was closed or reset
// before the whole answer came, or the attempt ran out of time ([WithTimeout]; then Timeout is true). It matches
// [ErrConnection], and [ErrTimeout] when Timeout is true; Unwrap gives the cause.
//
// A request the API may have run is sent again only when that is safe: see the package documentation's "Retries".
type ConnectionError struct {
	// Err is the cause.
	Err error
	// Timeout says the attempt ran out of time.
	Timeout bool
	// JobIDs are the jobs the call had made when it failed (see [JobIDs]).
	JobIDs []string

	method, path string
	after        time.Duration
}

// Error says which request got no answer, and why.
func (e *ConnectionError) Error() string {
	where := ""
	if e.method != "" {
		where = " (" + e.method + " " + e.path + ")"
	}
	if e.Timeout {
		if e.after > 0 {
			return fmt.Sprintf("verifyinboxes: the API did not answer within %v%s", e.after, where)
		}
		return "verifyinboxes: the API did not answer in time" + where
	}
	return fmt.Sprintf("verifyinboxes: no answer from the API%s: %v", where, cause(e.Err))
}

// Unwrap returns the cause.
func (e *ConnectionError) Unwrap() error { return e.Err }

// Is reports whether target is [ErrConnection], or [ErrTimeout] for an attempt that ran out of time.
func (e *ConnectionError) Is(target error) bool {
	return target == ErrConnection || (e.Timeout && target == ErrTimeout)
}

func (e *ConnectionError) jobIDList() []string { return e.JobIDs }

// cause is the error under a failed HTTP request's *url.Error, which says the most: the error itself repeats the
// method and the whole address.
func cause(err error) error {
	var u *url.Error
	if errors.As(err, &u) && u.Err != nil {
		return u.Err
	}
	return err
}

// WaitTimeoutError says that a check or a list was still running when the time given to wait ran out. It carries
// on, and its credits are held: wait for it again by its id with [CheckService.Wait] or [ListService.Wait]. It
// matches [ErrWaitTimeout].
type WaitTimeoutError struct {
	// JobIDs are the jobs still running: every job the call made, in the order of its input.
	JobIDs []string
	// Waited is the time that was given to wait.
	Waited time.Duration

	what, status string
}

// Error names the jobs still running, and how to wait for them again.
func (e *WaitTimeoutError) Error() string {
	what, status, resume := e.what, e.status, "Checks.Wait or Lists.Wait"
	switch what {
	case "check":
		resume = "Checks.Wait"
	case "list":
		resume = "Lists.Wait"
	default:
		what = "job"
	}
	if status == "" {
		status = "running"
	}
	if len(e.JobIDs) == 1 {
		return fmt.Sprintf("verifyinboxes: the %s %s was still %s after %v; it carries on, and its credits are held: "+
			"wait for it again with %s", what, e.JobIDs[0], status, e.Waited, resume)
	}
	return fmt.Sprintf("verifyinboxes: still running after %v; the jobs %s carry on, and their credits are held: "+
		"wait for them again with %s", e.Waited, strings.Join(e.JobIDs, ", "), resume)
}

// Is reports whether target is [ErrWaitTimeout].
func (e *WaitTimeoutError) Is(target error) bool { return target == ErrWaitTimeout }

func (e *WaitTimeoutError) jobIDList() []string { return e.JobIDs }

// unexpectedError is an answer that breaks the API's own rules ([ErrUnexpectedAnswer]).
type unexpectedError struct {
	message   string
	requestID string
	jobIDs    []string
}

func unexpected(requestID string, jobIDs []string, format string, a ...any) *unexpectedError {
	return &unexpectedError{message: fmt.Sprintf(format, a...), requestID: requestID, jobIDs: jobIDs}
}

func (e *unexpectedError) Error() string {
	s := "verifyinboxes: " + e.message
	if e.requestID != "" {
		s += " (request id " + e.requestID + ")"
	}
	return s
}

func (e *unexpectedError) Is(target error) bool { return target == ErrUnexpectedAnswer }

func (e *unexpectedError) jobIDList() []string { return e.jobIDs }

// jobsError names the jobs a call had made on an error that cannot carry them itself: the context's, a file's.
type jobsError struct {
	err    error
	jobIDs []string
}

func (e *jobsError) Error() string {
	if len(e.jobIDs) == 1 {
		return fmt.Sprintf("%v; the job %s carries on, and its credits are held: wait for it again with Checks.Wait "+
			"or Lists.Wait", e.err, e.jobIDs[0])
	}
	return fmt.Sprintf("%v; the jobs %s carry on, and their credits are held: wait for them again with Checks.Wait "+
		"or Lists.Wait", e.err, strings.Join(e.jobIDs, ", "))
}

func (e *jobsError) Unwrap() error { return e.err }

func (e *jobsError) jobIDList() []string { return e.jobIDs }

// refreshError is a 401 whose token could not be refreshed.
type refreshError struct {
	refresh error
	api     *APIError
}

func (e *refreshError) Error() string {
	return fmt.Sprintf("verifyinboxes: refreshing the token: %v; %v", e.refresh, e.api)
}

func (e *refreshError) Unwrap() []error { return []error{e.api, e.refresh} }

// JobIDs returns the jobs a call had made when it failed, as far as it knows, in the order of its input: a check
// that outlived its wait, a list being waited for, the checks of [Client.VerifyMany], a [Client.Verify] whose
// context ended. Those jobs carry on, and the credits they hold are spent on them: wait for them again with
// [CheckService.Wait] or [ListService.Wait] instead of starting again. It returns nil for an error that names none
// (a [ListService.Create] or [ListService.Resolve] stopped by its context does not know its own: see the package
// documentation's "Cancellation").
func JobIDs(err error) []string {
	var named interface{ jobIDList() []string }
	if errors.As(err, &named) {
		if ids := named.jobIDList(); len(ids) > 0 {
			return append([]string(nil), ids...)
		}
	}
	return nil
}

// withJobs names jobIDs on err, so that they are never lost. An error of this package that names none yet gets
// them (replace: gets them whatever it named); any other error is wrapped.
func withJobs(err error, jobIDs []string, replace bool) error {
	if err == nil || len(jobIDs) == 0 {
		return err
	}
	ids := append([]string(nil), jobIDs...)
	set := func(field *[]string) error {
		if replace || len(*field) == 0 {
			*field = ids
		}
		return err
	}
	var (
		wait  *WaitTimeoutError
		api   *APIError
		conn  *ConnectionError
		other *unexpectedError
		jobs  *jobsError
	)
	switch {
	case errors.As(err, &wait):
		return set(&wait.JobIDs)
	case errors.As(err, &api):
		return set(&api.JobIDs)
	case errors.As(err, &conn):
		return set(&conn.JobIDs)
	case errors.As(err, &other):
		return set(&other.jobIDs)
	case errors.As(err, &jobs):
		return set(&jobs.jobIDs)
	}
	return &jobsError{err: err, jobIDs: ids}
}
