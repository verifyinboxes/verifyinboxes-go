package verifyinboxes

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	userAgent = "verifyinboxes-go/" + Version
	// longTimeout is an upload's or a download's: the API's own limit for a whole request.
	longTimeout = 10 * time.Minute
	// maxRetryAfter: a longer Retry-After is not waited for; the error is returned, with RetryAfter on it.
	maxRetryAfter    = 60 * time.Second
	firstRetryDelay  = 500 * time.Millisecond
	maxRetryDelay    = 8 * time.Second
	maxKeyLength     = 255
	keyHeader        = "idempotency-key"
	requestIDHeader  = "X-Request-Id"
	invalidTokenHint = `error="invalid_token"`
)

// Client calls the VerifyInboxes API. Make one with [NewClient] and share it: it is safe for use by several
// goroutines at once, and keeps its connections open between calls.
//
// The services mirror the API. Every method takes a [context.Context] first: when it is cancelled or its deadline
// passes, the call stops (see the package documentation's "Cancellation").
type Client struct {
	// Account is the organisation's name, balance and switches.
	Account *AccountService
	// Checks is one check by its job: started, as it is now, or waited for. [Client.Verify] starts and waits.
	Checks *CheckService
	// Lists is lists of addresses: made, waited for, read, downloaded and resolved.
	Lists *ListService
	// Domains is what is known about a domain.
	Domains *DomainService
	// Suppressions is the addresses and domains never to check.
	Suppressions *SuppressionService
	// Webhooks is where the API sends events.
	Webhooks *WebhookService
	// Notices is the verdicts you bought, overturned since.
	Notices *NoticeService
	// Feedback is what became of the mail you sent.
	Feedback *FeedbackService
	// Integrations is the addresses that let Instantly or Smartlead report what became of your mail.
	Integrations *IntegrationService

	baseURL    string
	auth       *credential // a pointer, so that the fmt package never prints it
	http       *http.Client
	timeout    time.Duration
	maxRetries int
	userAgent  string

	// The waits between attempts and polls, the clock they are measured on, and the jitter of a backoff; replaced
	// by the tests only.
	sleep  func(ctx context.Context, d time.Duration) error
	now    func() time.Time
	jitter func() float64
}

// credential is the key, or the source of tokens. It is kept behind a pointer and never formatted.
type credential struct {
	key    string
	source TokenSource
	// refreshing is held while a refused token is being renewed, so that requests refused together renew it once.
	refreshing chan struct{}
}

// NewClient makes a client. The credential comes from [WithAPIKey] or [WithTokenSource], else from the
// VERIFYINBOXES_API_KEY environment variable; without one it returns [ErrMissingAPIKey]. The address comes from
// [WithBaseURL], else VERIFYINBOXES_BASE_URL, else [DefaultBaseURL].
func NewClient(opts ...Option) (*Client, error) {
	cfg := config{timeout: DefaultTimeout, maxRetries: DefaultMaxRetries}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	auth, err := credentialOf(&cfg)
	if err != nil {
		return nil, err
	}
	base, err := baseURLOf(cfg.baseURL)
	if err != nil {
		return nil, err
	}
	if cfg.timeout <= 0 {
		return nil, errors.New("verifyinboxes: the timeout must be above 0")
	}
	if cfg.maxRetries < 0 {
		return nil, errors.New("verifyinboxes: the number of retries must be 0 or more")
	}
	ua := userAgent
	if cfg.userAgent != "" {
		if !visibleASCII(cfg.userAgent) {
			return nil, errors.New("verifyinboxes: the User-Agent product must be visible ASCII with no space, " +
				"such as my-app/1.2")
		}
		ua = cfg.userAgent + " " + userAgent
	}
	hc := &http.Client{}
	if cfg.httpClient != nil {
		copied := *cfg.httpClient
		hc = &copied
	}
	// A redirect is not followed: the API does not send one, and the credential is never sent elsewhere.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c := &Client{
		baseURL:    base,
		auth:       auth,
		http:       hc,
		timeout:    cfg.timeout,
		maxRetries: cfg.maxRetries,
		userAgent:  ua,
		sleep:      sleepContext,
		now:        time.Now,
		jitter:     mathrand.Float64,
	}
	c.Account = &AccountService{client: c}
	c.Checks = &CheckService{client: c}
	c.Lists = &ListService{client: c}
	c.Domains = &DomainService{client: c}
	c.Suppressions = &SuppressionService{client: c}
	c.Webhooks = &WebhookService{client: c}
	c.Notices = &NoticeService{client: c}
	c.Feedback = &FeedbackService{client: c}
	c.Integrations = &IntegrationService{client: c}
	return c, nil
}

// Format prints the client's address and, of its key, only the first 6 characters, whatever the verb. (It takes a
// Client, not a pointer, so that a copy of one prints the same.)
func (c Client) Format(f fmt.State, _ rune) {
	shown := "a token source"
	if c.auth != nil && c.auth.source == nil {
		shown = fmt.Sprintf("%q", prefix(c.auth.key, 6)+"...")
	}
	fmt.Fprintf(f, "verifyinboxes.Client{baseURL: %q, key: %s}", c.baseURL, shown)
}

func prefix(s string, n int) string {
	if len(s) <= n {
		return ""
	}
	return s[:n]
}

func credentialOf(cfg *config) (*credential, error) {
	if cfg.tokenSource != nil {
		if strings.TrimSpace(cfg.apiKey) != "" {
			return nil, errors.New("verifyinboxes: give an API key or a token source, not both")
		}
		return &credential{source: cfg.tokenSource, refreshing: make(chan struct{}, 1)}, nil
	}
	key := strings.TrimSpace(cfg.apiKey)
	if key == "" {
		key = strings.TrimSpace(os.Getenv(EnvAPIKey))
	}
	if key == "" {
		return nil, ErrMissingAPIKey
	}
	if !visibleASCII(key) {
		// A key and a token are visible ASCII: anything else (a space, a control or zero-width character, a letter
		// with an accent) is half of a copy and paste, and would fail on the first request instead. It is not
		// echoed.
		return nil, errors.New("verifyinboxes: the API key holds a space, a control character or a character " +
			"that is not ASCII: copy it again, whole")
	}
	return &credential{key: key}, nil
}

func baseURLOf(given string) (string, error) {
	value := strings.TrimSpace(given)
	if value == "" {
		value = strings.TrimSpace(os.Getenv(EnvBaseURL))
	}
	if value == "" {
		value = DefaultBaseURL
	}
	value = strings.TrimSuffix(value, "/")
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("verifyinboxes: the base URL %q is not an http:// or https:// address", value)
	}
	return value, nil
}

// visibleASCII reports whether s is one or more of the characters ! to ~: no space, no control character, no
// character outside ASCII.
func visibleASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '!' || s[i] > '~' {
			return false
		}
	}
	return true
}

// ---- requests ------------------------------------------------------------------------------------------------------

// retryMode is how a request may be sent again after a failed attempt.
type retryMode int

const (
	// retryAlways: GET and DELETE, and the POSTs the API answers again from the same Idempotency-Key.
	retryAlways retryMode = iota
	// retryUnsent: a POST the API never replays (its answer holds a secret shown once), sent again only when it
	// surely did not arrive (the connection was never made) or was refused before it ran (429).
	retryUnsent
)

// request is one call of the API, as the services describe it to the transport.
type request struct {
	method string
	// path is the path, its segments already escaped.
	path  string
	query url.Values
	// body is marshalled as JSON; nil: no body.
	body   any
	upload *upload
	// key is the Idempotency-Key of a POST.
	key   string
	retry retryMode
	// long: an upload or a download, given the longer timeout.
	long bool
	// goneIsDone: a DELETE whose earlier attempt got no answer, answered 404 on a retry, was done by that attempt.
	goneIsDone bool
	accept     string
	// finishOnCancel: a POST that may make a job (a check, a list). Once an attempt is sent, the caller's context
	// does not cut it off: it finishes within its timeout, so the job it made is known; the context stops anything
	// after it.
	finishOnCancel bool
}

// answer is a successful answer read whole.
type answer struct {
	status    int
	requestID string
	body      []byte
}

// bodyCut says that the body of an answer stopped coming: the attempt got no (whole) answer. final: it must not be
// sent again (a download already handed over some of its bytes).
type bodyCut struct {
	err   error
	final bool
}

func (b *bodyCut) Error() string { return b.err.Error() }

// outcome is what one attempt came to.
type outcome struct {
	err error
	// unanswered: no (whole) answer came.
	unanswered bool
	// neverSent: the connection was never made, so the request surely never reached the API.
	neverSent bool
	// final: the attempt must not be made again.
	final bool
	// refresh: a 401 that says the token is invalid.
	refresh bool
	// token is the credential the attempt sent.
	token string
}

// do sends r, retrying as it allows, and returns its answer read whole.
func (c *Client) do(ctx context.Context, r *request) (*answer, error) {
	var got *answer
	err := c.roundTrip(ctx, r, func(resp *http.Response) error {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return &bodyCut{err: err}
		}
		got = &answer{status: resp.StatusCode, requestID: resp.Header.Get(requestIDHeader), body: body}
		return nil
	})
	return got, err
}

// doJSON sends r and decodes its answer into out (nil: the body is not read for anything).
func (c *Client) doJSON(ctx context.Context, r *request, out any) (*answer, error) {
	got, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	if out != nil {
		if err := decode(got, out); err != nil {
			return nil, err
		}
	}
	return got, nil
}

// decode reads an answer's JSON body into out.
func decode(a *answer, out any) error {
	if len(bytes.TrimSpace(a.body)) == 0 || jsonUnmarshal(a.body, out) != nil {
		return unexpected(a.requestID, nil, "the API answered %d with something that is not JSON", a.status)
	}
	return nil
}

func jsonUnmarshal(data []byte, out any) error { return json.Unmarshal(data, out) }

// roundTrip sends r, retrying as it allows. handle reads a 2xx answer within its attempt's time: a *bodyCut it
// returns is that attempt's failure to get an answer; any other error is returned as it is.
func (c *Client) roundTrip(ctx context.Context, r *request, handle func(*http.Response) error) error {
	attempt, unanswered, refreshed := 0, false, false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		o := c.attempt(ctx, r, handle, r.goneIsDone && unanswered)
		if o.err == nil {
			return nil
		}
		unanswered = unanswered || o.unanswered
		if o.refresh && !refreshed {
			if refresher, ok := c.auth.source.(Refresher); ok {
				refreshed = true
				if err := c.refresh(ctx, refresher, o.token); err != nil {
					return &refreshError{refresh: err, api: o.err.(*APIError)}
				}
				if r.upload != nil && !r.upload.resendable() {
					// The token is renewed for the next call, but an upload read as it was sent cannot be sent again:
					// its file would go empty, under the same key.
					return o.err
				}
				continue
			}
		}
		if ctx.Err() != nil {
			// Nothing is sent again once the caller's context has ended; an answer that came is told as it is.
			if o.unanswered {
				return ctx.Err()
			}
			return o.err
		}
		delay, ok := c.retryDelay(r, o, attempt)
		if !ok {
			return o.err
		}
		if err := c.sleep(ctx, delay); err != nil {
			return err
		}
		attempt++
	}
}

// refresh renews the token an attempt was refused with, once for all the requests refused with it: one goroutine
// at a time, and not at all when the source already gives another token (another request renewed it meanwhile).
func (c *Client) refresh(ctx context.Context, refresher Refresher, refused string) error {
	select {
	case c.auth.refreshing <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-c.auth.refreshing }()
	if current, err := c.token(ctx); err == nil && current != refused {
		return nil
	}
	return refresher.Refresh(ctx)
}

// retryDelay is the wait before sending r again after the failed attempt number attempt (from 0), or false to give
// up with its error.
func (c *Client) retryDelay(r *request, o outcome, attempt int) (time.Duration, bool) {
	if attempt >= c.maxRetries || o.final {
		return 0, false
	}
	if r.upload != nil && !r.upload.resendable() {
		return 0, false
	}
	var conn *ConnectionError
	if errors.As(o.err, &conn) {
		if r.retry == retryUnsent && !o.neverSent {
			return 0, false
		}
		return c.backoff(attempt), true
	}
	var api *APIError
	if !errors.As(o.err, &api) {
		return 0, false
	}
	inProgress := api.StatusCode == http.StatusConflict && api.Code == "idempotency_in_progress"
	if api.StatusCode != http.StatusTooManyRequests && api.StatusCode < 500 && !inProgress {
		return 0, false
	}
	if r.retry == retryUnsent && api.StatusCode != http.StatusTooManyRequests {
		return 0, false
	}
	if api.retryAfterSet {
		if api.RetryAfter > maxRetryAfter {
			return 0, false
		}
		return api.RetryAfter, true
	}
	return c.backoff(attempt), true
}

// backoff is the wait before the n-th retry (n from 0): uniform between half of min(8 s, 0.5 s × 2^n) and all of
// it.
func (c *Client) backoff(n int) time.Duration {
	ceiling := maxRetryDelay
	if n < 5 {
		ceiling = min(maxRetryDelay, firstRetryDelay<<n)
	}
	return ceiling/2 + time.Duration(c.jitter()*float64(ceiling/2))
}

// attempt sends r once. goneOK: a 404 counts as done.
func (c *Client) attempt(ctx context.Context, r *request, handle func(*http.Response) error, goneOK bool) outcome {
	timeout := c.timeout
	if r.long && timeout < longTimeout {
		timeout = longTimeout
	}
	base := ctx
	if r.finishOnCancel {
		base = context.WithoutCancel(ctx)
	}
	actx, cancel := context.WithTimeout(base, timeout)
	defer cancel()
	var connected atomic.Bool
	actx = httptrace.WithClientTrace(actx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { connected.Store(true) }})

	req, body, err := c.newRequest(ctx, actx, r)
	if err != nil {
		return outcome{err: err}
	}
	if body != nil {
		// Whatever the transport still reads of the body once the attempt is over is cut off, so that the next
		// attempt may read it again from its start.
		defer body.Close()
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return c.noAnswer(ctx, actx, r, err, timeout, !connected.Load() && dialFailed(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := handle(resp); err != nil {
			var cut *bodyCut
			if errors.As(err, &cut) {
				o := c.noAnswer(ctx, actx, r, cut.err, timeout, false)
				o.final = o.final || cut.final
				return o
			}
			return outcome{err: err, final: true}
		}
		return outcome{}
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return c.noAnswer(ctx, actx, r, err, timeout, false)
	}
	if goneOK && resp.StatusCode == http.StatusNotFound {
		return outcome{}
	}
	apiErr := apiErrorOf(resp, data, c.now())
	refresh := resp.StatusCode == http.StatusUnauthorized &&
		strings.Contains(strings.Join(resp.Header.Values("WWW-Authenticate"), ","), invalidTokenHint)
	return outcome{err: apiErr, refresh: refresh, token: strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")}
}

// noAnswer is the outcome of an attempt that got no (whole) answer.
func (c *Client) noAnswer(ctx, actx context.Context, r *request, err error, timeout time.Duration, neverSent bool) outcome {
	if !r.finishOnCancel && ctx.Err() != nil {
		return outcome{err: ctx.Err(), unanswered: true}
	}
	connErr := &ConnectionError{Err: err, method: r.method, path: r.path}
	if errors.Is(actx.Err(), context.DeadlineExceeded) && (r.finishOnCancel || ctx.Err() == nil) {
		connErr.Timeout, connErr.after = true, timeout
	}
	return outcome{err: connErr, unanswered: true, neverSent: neverSent}
}

// dialFailed reports whether err says the connection could not be made (refused, no route, no such host): the
// request never left.
func dialFailed(err error) bool {
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return true
	}
	var dns *net.DNSError
	return errors.As(err, &dns)
}

// newRequest builds one attempt of r. Its body, when it has one, is returned to be closed once the attempt is over.
func (c *Client) newRequest(ctx, actx context.Context, r *request) (*http.Request, io.ReadCloser, error) {
	target := c.baseURL + r.path
	if len(r.query) > 0 {
		target += "?" + r.query.Encode()
	}
	var (
		body        io.ReadCloser
		length      int64
		contentType string
	)
	switch {
	case r.upload != nil:
		reader, n, err := r.upload.open()
		if err != nil {
			return nil, nil, err
		}
		body, length, contentType = reader, n, r.upload.contentType
	case r.body != nil:
		data, err := json.Marshal(r.body)
		if err != nil {
			return nil, nil, fmt.Errorf("verifyinboxes: encoding the request: %w", err)
		}
		body, length, contentType = newBody(bytes.NewReader(data), false, nil), int64(len(data)), "application/json"
	}
	var reqBody io.Reader
	if body != nil {
		reqBody = body
	}
	req, err := http.NewRequestWithContext(actx, r.method, target, reqBody)
	if err != nil {
		if body != nil {
			_ = body.Close()
		}
		return nil, nil, fmt.Errorf("verifyinboxes: %s %s: %w", r.method, r.path, err)
	}
	if body != nil {
		req.ContentLength = length
		if length < 0 {
			req.ContentLength = 0 // unknown: sent chunked
		}
		// Without GetBody, net/http never sends the body again by itself.
		req.GetBody = nil
		req.Header.Set("Content-Type", contentType)
	}
	token, err := c.token(ctx)
	if err != nil {
		if body != nil {
			_ = body.Close()
		}
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	accept := r.accept
	if accept == "" {
		accept = "application/json"
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", c.userAgent)
	if r.key != "" {
		// Not "Idempotency-Key": net/http takes a request whose header map has that entry for one it may send again
		// on its own, and the client decides every resend itself.
		req.Header[keyHeader] = []string{r.key}
	}
	return req, body, nil
}

// token is the credential of one attempt.
func (c *Client) token(ctx context.Context) (string, error) {
	if c.auth.source == nil {
		return c.auth.key, nil
	}
	token, err := c.auth.source.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("verifyinboxes: the token source: %w", err)
	}
	token = strings.TrimSpace(token)
	if !visibleASCII(token) {
		return "", errors.New("verifyinboxes: the token source gave a token that is empty, or holds a space, a " +
			"control character or a character that is not ASCII")
	}
	return token, nil
}

// requestBody is a request's body that stops being read once it is closed. For a reader the next attempt rewinds
// (rewind), closing it also waits for a read in progress, so that no read of the transport's is left running when the
// reader is rewound.
type requestBody struct {
	mu      sync.Mutex
	rewind  bool
	r       io.Reader
	closed  atomic.Bool
	onClose func()
}

func newBody(r io.Reader, rewind bool, onClose func()) *requestBody {
	return &requestBody{r: r, rewind: rewind, onClose: onClose}
}

func (b *requestBody) Read(p []byte) (int, error) {
	if b.rewind {
		b.mu.Lock()
		defer b.mu.Unlock()
	}
	if b.closed.Load() {
		return 0, errors.New("verifyinboxes: the attempt is over")
	}
	return b.r.Read(p)
}

func (b *requestBody) Close() error {
	if b.rewind {
		b.mu.Lock()
		defer b.mu.Unlock()
	}
	if b.closed.CompareAndSwap(false, true) && b.onClose != nil {
		b.onClose()
	}
	return nil
}

// ---- small things --------------------------------------------------------------------------------------------------

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// newKey is a random UUID (version 4), an Idempotency-Key.
func newKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("verifyinboxes: no randomness: " + err.Error())
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// idempotencyKey is the caller's own key, checked, or a new one.
func idempotencyKey(given string) (string, error) {
	if given == "" {
		return newKey(), nil
	}
	if len(given) > maxKeyLength || !visibleASCII(given) {
		return "", errors.New("verifyinboxes: an Idempotency-Key is 1 to 255 visible ASCII characters")
	}
	return given, nil
}

// segment is a value as one segment of a path: an id with a / or a ? in it never reaches another address.
func segment(what, value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("verifyinboxes: the %s is empty", what)
	}
	return url.PathEscape(value), nil
}

// parseSeconds reads a number of seconds, 0 or more.
func parseSeconds(value string) (time.Duration, error) {
	f, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, errors.New("not a number of seconds")
	}
	if f <= 0 {
		return 0, nil
	}
	if f > float64(math.MaxInt64/int64(time.Second)) {
		return time.Duration(math.MaxInt64), nil
	}
	return time.Duration(f * float64(time.Second)), nil
}
