package verifyinboxes

import (
	"context"
	"net/http"
	"time"
)

const (
	// DefaultBaseURL is where the API is served.
	DefaultBaseURL = "https://api.verifyinboxes.com"
	// EnvAPIKey is the environment variable [NewClient] reads the API key from, when none is given.
	EnvAPIKey = "VERIFYINBOXES_API_KEY"
	// EnvBaseURL is the environment variable [NewClient] reads the API's address from, when none is given.
	EnvBaseURL = "VERIFYINBOXES_BASE_URL"
	// DefaultTimeout is the time one attempt of one request may take. An upload ([ListService.Create] with a file
	// or a CSV) and a download are given at least 10 minutes, the API's own limit for a whole request.
	DefaultTimeout = 60 * time.Second
	// DefaultMaxRetries is how many times a request that failed in a way worth retrying is sent again.
	DefaultMaxRetries = 2
)

// TokenSource gives the bearer credential of each request, for one that changes (a personal access token lives an
// hour). Token is called before every attempt; what it returns is sent as "Authorization: Bearer <token>". It is
// called from several goroutines at once (a client is shared, and [Client.VerifyMany] runs up to 10 checks
// together), so it must be safe for that.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Refresher is a [TokenSource] that can renew its credential. On a 401 whose WWW-Authenticate has
// error="invalid_token", the client renews the token and sends the request again, once, with the same
// Idempotency-Key; a second 401 is returned.
//
// The client calls Refresh from one goroutine at a time, and only while Token still gives the token the API
// refused: when several requests are refused together, the first renews it and the others are sent again with the
// new token, so a refresh token that may be used only once is used once. An upload read from a reader that cannot
// seek is not sent again (its file would go empty): the token is renewed, and its 401 is returned.
type Refresher interface {
	Refresh(ctx context.Context) error
}

// Option configures a [Client]. A wrong value makes [NewClient] return an error.
type Option func(*config)

type config struct {
	apiKey      string
	tokenSource TokenSource
	baseURL     string
	httpClient  *http.Client
	timeout     time.Duration
	maxRetries  int
	userAgent   string
}

// WithAPIKey sets the credential: an API key (bv_...) or a personal access token (vi_at_...), sent as
// "Authorization: Bearer <key>". Without it, or with an empty one, the key is read from VERIFYINBOXES_API_KEY.
// Surrounding spaces are dropped; a key that is not visible ASCII (a space or a control character inside, an
// accented letter) is refused, as half of a copy and paste.
func WithAPIKey(key string) Option { return func(c *config) { c.apiKey = key } }

// WithTokenSource takes each request's credential from ts instead of a fixed key: for a personal access token,
// which lives an hour. If ts is also a [Refresher], a 401 that says the token is invalid is refreshed for once.
// It cannot be given with [WithAPIKey].
func WithTokenSource(ts TokenSource) Option { return func(c *config) { c.tokenSource = ts } }

// WithBaseURL sets the API's address, http or https. Without it, VERIFYINBOXES_BASE_URL, else [DefaultBaseURL].
// One trailing slash is dropped.
func WithBaseURL(url string) Option { return func(c *config) { c.baseURL = url } }

// WithHTTPClient sets the HTTP client requests are sent with (its Transport, proxy and TLS settings). The client
// never follows a redirect, and it decides every resend itself: a POST carries its Idempotency-Key under the header
// map's key "idempotency-key" (lower case), so that net/http never sends it again on its own. The HTTP client's own
// Timeout, if any, applies to every attempt besides [WithTimeout]. Default: a client of http.DefaultTransport.
func WithHTTPClient(client *http.Client) Option { return func(c *config) { c.httpClient = client } }

// WithTimeout sets the time one attempt of one request may take (default [DefaultTimeout]); it must be above 0.
// Uploads and downloads are given at least 10 minutes. How long a whole call may take is the context's to say.
func WithTimeout(timeout time.Duration) Option {
	return func(c *config) { c.timeout = timeout }
}

// WithMaxRetries sets how many times a request that failed in a way worth retrying is sent again (default
// [DefaultMaxRetries]); 0 never. It must not be negative.
func WithMaxRetries(n int) Option {
	return func(c *config) { c.maxRetries = n }
}

// WithUserAgent puts your product's token, such as "my-app/1.2", in front of the library's own in the User-Agent:
// "my-app/1.2 verifyinboxes-go/0.1.0". It must be visible ASCII with no space; an empty one adds nothing.
func WithUserAgent(product string) Option { return func(c *config) { c.userAgent = product } }
