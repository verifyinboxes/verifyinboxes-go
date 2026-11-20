package verifyinboxes_test

// The client's configuration, credentials, cancellation, uploads, downloads, errors and transport, beyond what the
// conformance scenarios hold it to.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	verifyinboxes "github.com/verifyinboxes/verifyinboxes-go"
)

var account = map[string]any{"name": "acme", "balance": 10, "reviewed": false, "test_emails": false, "safe_to_send_threshold": 0.8}

func tenEmails() []string {
	out := make([]string, 10)
	for i := range out {
		out[i] = fmt.Sprintf("p%d@example.com", i+1)
	}
	return out
}

// ---- configuration -------------------------------------------------------------------------------------------------

func TestMissingKey(t *testing.T) {
	t.Setenv(verifyinboxes.EnvAPIKey, "")
	for name, opts := range map[string][]verifyinboxes.Option{
		"none":         nil,
		"blank":        {verifyinboxes.WithAPIKey("   ")},
		"blank in env": nil,
	} {
		if name == "blank in env" {
			t.Setenv(verifyinboxes.EnvAPIKey, " \n")
		}
		_, err := verifyinboxes.NewClient(opts...)
		if !errors.Is(err, verifyinboxes.ErrMissingAPIKey) {
			t.Fatalf("%s: %v, not ErrMissingAPIKey", name, err)
		}
		for _, says := range []string{"VERIFYINBOXES_API_KEY", "admin", "Developers", "API keys"} {
			if !strings.Contains(err.Error(), says) {
				t.Errorf("%s: the error does not say %q: %v", name, says, err)
			}
		}
	}
}

func TestKeyAndBaseURLFromTheEnvironment(t *testing.T) {
	api := newFakeAPI(t, []exchange{on("GET", "/v1/account", answerWith(200, account))}, fakeOptions{})
	t.Setenv(verifyinboxes.EnvAPIKey, "  "+testKey+"\n")
	t.Setenv(verifyinboxes.EnvBaseURL, api.URL+"/")
	client, err := verifyinboxes.NewClient(verifyinboxes.WithHTTPClient(newHTTPClient(t)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Account.Get(context.Background())
	if err != nil || got.Balance != 10 || got.Name != "acme" {
		t.Fatalf("%+v %v", got, err)
	}
	sent := api.recordedRequests()[0].Header
	for name, want := range map[string]string{
		"Authorization": "Bearer " + testKey, "Accept": "application/json", "User-Agent": "verifyinboxes-go/" + verifyinboxes.Version,
	} {
		if sent.Get(name) != want {
			t.Errorf("%s: %q, not %q", name, sent.Get(name), want)
		}
	}

	// A personal access token goes the same way, and what is given beats the environment.
	token := "vi_at_testtesttesttesttesttesttesttesttesttest"
	given := newFakeAPI(t, []exchange{on("GET", "/v1/account", answerWith(200, account))}, fakeOptions{})
	c, _ := clientOf(t, given, nil, verifyinboxes.WithAPIKey(token))
	if _, err := c.Account.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	if auth := given.recordedRequests()[0].Header.Get("Authorization"); auth != "Bearer "+token {
		t.Errorf("Authorization: %q", auth)
	}
	if api.count() != 1 {
		t.Errorf("the environment's server got %d requests", api.count())
	}
}

func TestDefaults(t *testing.T) {
	t.Setenv(verifyinboxes.EnvBaseURL, "")
	client, err := verifyinboxes.NewClient(verifyinboxes.WithAPIKey(testKey))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fmt.Sprint(client), verifyinboxes.DefaultBaseURL) {
		t.Errorf("not the default base URL: %v", client)
	}
	if verifyinboxes.DefaultBaseURL != "https://api.verifyinboxes.com" || verifyinboxes.Version != "0.1.0" ||
		verifyinboxes.EnvAPIKey != "VERIFYINBOXES_API_KEY" || verifyinboxes.EnvBaseURL != "VERIFYINBOXES_BASE_URL" {
		t.Error("the constants changed")
	}
}

func TestRefusesAKeyThatIsNotVisibleASCIIWithoutEchoingIt(t *testing.T) {
	for _, bad := range []string{
		testKey + "\nX-Other: 1", "bv_test test", testKey + "\x00", "bv_\ttest", testKey + "​", " " + testKey + "x y", "bv_tést",
	} {
		_, err := verifyinboxes.NewClient(verifyinboxes.WithAPIKey(bad))
		if err == nil {
			t.Fatalf("%q was taken", bad)
		}
		if !strings.Contains(err.Error(), "copy it again") {
			t.Errorf("%q: %v", bad, err)
		}
		for _, shown := range []string{fmt.Sprint(err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
			if strings.Contains(shown, "bv_") || strings.Contains(shown, "test") {
				t.Errorf("the error shows the key: %s", shown)
			}
		}
	}
}

func TestOptionsThatMakeNoSense(t *testing.T) {
	for name, opt := range map[string]verifyinboxes.Option{
		"ftp":            verifyinboxes.WithBaseURL("ftp://api.example.com"),
		"no scheme":      verifyinboxes.WithBaseURL("api.example.com"),
		"file":           verifyinboxes.WithBaseURL("file:///etc/passwd"),
		"zero timeout":   verifyinboxes.WithTimeout(0),
		"negative":       verifyinboxes.WithMaxRetries(-1),
		"product spaces": verifyinboxes.WithUserAgent("my app/1.0"),
		"product ctrl":   verifyinboxes.WithUserAgent("app/1\r\nX-Other: 1"),
		"product utf8":   verifyinboxes.WithUserAgent("appé/1"),
		"token and key":  verifyinboxes.WithTokenSource(&tokens{tokens: []string{"vi_at_testtesttesttesttesttesttesttesttesttest"}}),
	} {
		if _, err := verifyinboxes.NewClient(verifyinboxes.WithAPIKey(testKey), opt); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	client, err := verifyinboxes.NewClient(verifyinboxes.WithAPIKey(testKey), verifyinboxes.WithBaseURL("http://127.0.0.1:8080/"))
	if err != nil || !strings.Contains(fmt.Sprint(client), `"http://127.0.0.1:8080"`) {
		t.Errorf("one trailing slash is dropped: %v %v", client, err)
	}
}

func TestUserAgentProduct(t *testing.T) {
	api := newFakeAPI(t, []exchange{on("GET", "/v1/account", answerWith(200, account))}, fakeOptions{})
	client, _ := clientOf(t, api, nil, verifyinboxes.WithUserAgent("verifyinboxes-cli/1.2.3"))
	if _, err := client.Account.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := "verifyinboxes-cli/1.2.3 verifyinboxes-go/" + verifyinboxes.Version
	if ua := api.recordedRequests()[0].Header.Get("User-Agent"); ua != want {
		t.Errorf("User-Agent %q, not %q", ua, want)
	}
}

func TestTheClientNeverShowsTheKey(t *testing.T) {
	client, err := verifyinboxes.NewClient(verifyinboxes.WithAPIKey(testKey))
	if err != nil {
		t.Fatal(err)
	}
	type holder struct{ C *verifyinboxes.Client }
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T", "%p"} {
		for _, value := range []any{client, *client, holder{client}, []*verifyinboxes.Client{client}, client.Checks} {
			shown := fmt.Sprintf(format, value)
			if strings.Contains(shown, testKey[:7]) || strings.Contains(shown, "testtest") {
				t.Errorf("%s of %T shows the key: %s", format, value, shown)
			}
		}
	}
	data, _ := json.Marshal(client)
	if bytes.Contains(data, []byte("bv_")) {
		t.Errorf("JSON shows the key: %s", data)
	}
	if !strings.Contains(fmt.Sprint(client), "bv_tes") {
		t.Errorf("the client should show the key's first 6 characters: %v", client)
	}
}

func TestErrorsNeverShowTheKey(t *testing.T) {
	refused := answerWith(401, apiError("unauthorized", "missing, malformed or revoked API key"))
	refused.Headers["x-request-id"] = "019a7e00-0000-7000-8000-0000000000bb"
	api := newFakeAPI(t, []exchange{on("GET", "/v1/account", refused)}, fakeOptions{})
	client, _ := clientOf(t, api, nil)
	err := errorOf(t, second(client.Account.Get(context.Background())))
	if !errors.Is(err, verifyinboxes.ErrAuthentication) {
		t.Fatalf("%v", err)
	}
	for _, shown := range []string{fmt.Sprint(err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		if !strings.Contains(shown, "019a7e00-0000-7000-8000-0000000000bb") && !strings.Contains(shown, "RequestID") {
			t.Errorf("no request id: %s", shown)
		}
		if strings.Contains(shown, "bv_") {
			t.Errorf("the error shows the key: %s", shown)
		}
	}
}

func second[T any](_ T, err error) error { return err }

func TestSecretsShownOnceAreHiddenFromFormattingAndKeptInJSON(t *testing.T) {
	hook := "https://api.verifyinboxes.com/hooks/instantly/whk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	api := newFakeAPI(t, []exchange{
		on("POST", "/v1/webhooks", answerWith(201, map[string]any{
			"id": "019a4f10-2b3c-7d4e-8f5a-6b7c8d9e0f12", "url": "https://example.com/hook", "events": []string{"job.completed"},
			"secret": secret, "created_at": "2026-11-18T10:00:00Z",
		})),
		on("POST", "/v1/integrations", answerWith(201, map[string]any{
			"id": "019a4f22-7c1d-7e2f-9a3b-4c5d6e7f8a90", "provider": "instantly", "label": nil, "url": hook,
			"created_at": "2026-11-18T10:00:00Z",
		})),
	}, fakeOptions{})
	client, _ := clientOf(t, api, nil)
	ctx := context.Background()
	created, err := client.Webhooks.Create(ctx, &verifyinboxes.WebhookParams{URL: "https://example.com/hook", Events: []string{"job.completed"}})
	if err != nil {
		t.Fatal(err)
	}
	integration, err := client.Integrations.Create(ctx, &verifyinboxes.IntegrationParams{Provider: "instantly"})
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		for _, value := range []any{created, *created, []verifyinboxes.WebhookCreated{*created}, integration, *integration} {
			shown := fmt.Sprintf(format, value)
			if strings.Contains(shown, secret[:16]) || strings.Contains(shown, "whk_") ||
				strings.Contains(shown, fmt.Sprintf("%x", secret[:8])) {
				t.Errorf("%s of %T shows the secret: %s", format, value, shown)
			}
		}
	}
	if created.Secret != secret || integration.URL != hook {
		t.Error("the secrets are not on the values")
	}
	data, _ := json.Marshal(created)
	if !bytes.Contains(data, []byte(secret)) {
		t.Errorf("JSON drops the secret: %s", data)
	}
	data, _ = json.Marshal(integration)
	if !bytes.Contains(data, []byte(hook)) {
		t.Errorf("JSON drops the url: %s", data)
	}
}

func TestUnknownFieldsAndValuesAreKept(t *testing.T) {
	result := withJob(resultJSON("ann@example.com", "spam_trap"), jobID)
	result["reason"], result["flags"], result["something_new"] = "new_reason", []string{"new_flag"}, map[string]any{"nested": 1}
	api := newFakeAPI(t, []exchange{on("POST", "/v1/verify", answerWith(200, result))}, fakeOptions{})
	client, _ := clientOf(t, api, nil)
	got, err := client.Verify(context.Background(), "ann@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != "spam_trap" || got.Reason != "new_reason" || fmt.Sprint(got.Flags) != "[new_flag]" || got.JobID != jobID {
		t.Errorf("%+v", got)
	}
}

func TestASuccessThatIsNotJSONNamesItsRequest(t *testing.T) {
	api := newFakeAPI(t, []exchange{on("GET", "/v1/account", textAnswer(200, "text/html", "<html>"))}, fakeOptions{})
	client, _ := clientOf(t, api, nil)
	err := errorOf(t, second(client.Account.Get(context.Background())))
	if !errors.Is(err, verifyinboxes.ErrUnexpectedAnswer) || !strings.HasSuffix(err.Error(), "(request id "+requestID+")") {
		t.Errorf("%v", err)
	}
}

// ---- errors --------------------------------------------------------------------------------------------------------

func TestErrorsIs(t *testing.T) {
	cases := []struct {
		status int
		code   string
		is     error
	}{
		{400, "invalid_request", verifyinboxes.ErrInvalidRequest}, {413, "too_large", verifyinboxes.ErrInvalidRequest},
		{414, "uri_too_long", verifyinboxes.ErrInvalidRequest}, {415, "unsupported", verifyinboxes.ErrInvalidRequest},
		{422, "consumer_list", verifyinboxes.ErrInvalidRequest}, {401, "unauthorized", verifyinboxes.ErrAuthentication},
		{402, "insufficient_credits", verifyinboxes.ErrInsufficientCredits}, {403, "forbidden", verifyinboxes.ErrPermissionDenied},
		{404, "not_found", verifyinboxes.ErrNotFound}, {410, "gone", verifyinboxes.ErrNotFound},
		{409, "not_ready", verifyinboxes.ErrConflict}, {429, "rate_limited", verifyinboxes.ErrRateLimited},
		{500, "internal", verifyinboxes.ErrServer}, {503, "unavailable", verifyinboxes.ErrServer},
		{418, "teapot", nil},
	}
	all := []error{
		verifyinboxes.ErrInvalidRequest, verifyinboxes.ErrAuthentication, verifyinboxes.ErrInsufficientCredits,
		verifyinboxes.ErrPermissionDenied, verifyinboxes.ErrNotFound, verifyinboxes.ErrConflict,
		verifyinboxes.ErrRateLimited, verifyinboxes.ErrServer, verifyinboxes.ErrConnection, verifyinboxes.ErrTimeout,
		verifyinboxes.ErrWaitTimeout, verifyinboxes.ErrUnexpectedAnswer, verifyinboxes.ErrMissingAPIKey,
	}
	for _, c := range cases {
		api := newFakeAPI(t, []exchange{on("GET", "/v1/account", answerWith(c.status, apiError(c.code, "no")))}, fakeOptions{})
		client, _ := clientOf(t, api, newPaperClock(), verifyinboxes.WithMaxRetries(0))
		err := errorOf(t, second(client.Account.Get(context.Background())))
		var apiErr *verifyinboxes.APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != c.status || apiErr.Code != c.code || apiErr.RequestID != requestID {
			t.Fatalf("%d: %#v", c.status, err)
		}
		for _, sentinel := range all {
			if errors.Is(err, sentinel) != (sentinel == c.is) {
				t.Errorf("%d: errors.Is(err, %v) = %v", c.status, sentinel, errors.Is(err, sentinel))
			}
		}
		want := fmt.Sprintf("%d %s: no (request id %s)", c.status, c.code, requestID)
		if err.Error() != want {
			t.Errorf("%q, not %q", err.Error(), want)
		}
		if !strings.Contains(string(apiErr.Body), c.code) {
			t.Errorf("Body: %s", apiErr.Body)
		}
	}
}

func TestErrorKindsOfNoAnswer(t *testing.T) {
	conn := &verifyinboxes.ConnectionError{Err: io.EOF}
	timeout := &verifyinboxes.ConnectionError{Err: context.DeadlineExceeded, Timeout: true}
	wait := &verifyinboxes.WaitTimeoutError{JobIDs: []string{jobID}, Waited: 5 * time.Second}
	if !errors.Is(conn, verifyinboxes.ErrConnection) || errors.Is(conn, verifyinboxes.ErrTimeout) || !errors.Is(conn, io.EOF) {
		t.Error("a ConnectionError")
	}
	if !errors.Is(timeout, verifyinboxes.ErrConnection) || !errors.Is(timeout, verifyinboxes.ErrTimeout) {
		t.Error("a ConnectionError that timed out")
	}
	if !errors.Is(wait, verifyinboxes.ErrWaitTimeout) || !strings.Contains(wait.Error(), jobID) {
		t.Errorf("a WaitTimeoutError: %v", wait)
	}
	if got := verifyinboxes.JobIDs(fmt.Errorf("wrapped: %w", wait)); fmt.Sprint(got) != fmt.Sprint([]string{jobID}) {
		t.Errorf("JobIDs: %v", got)
	}
	if verifyinboxes.JobIDs(io.EOF) != nil || verifyinboxes.JobIDs(nil) != nil {
		t.Error("JobIDs of an error that names none")
	}
}

// ---- token sources -------------------------------------------------------------------------------------------------

// renewedToken is what a token source hands out after a Refresh: made up, like the first, and refused by the API.
const renewedToken = "bv_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

// tokens is a TokenSource that hands out its tokens in turn, a new one after each Refresh.
type tokens struct {
	mu        sync.Mutex
	tokens    []string
	at        int
	refreshes int
}

func (s *tokens) Token(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens[s.at], nil
}

func (s *tokens) Refresh(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshes++
	if s.at+1 < len(s.tokens) {
		s.at++
	}
	return nil
}

func TestTokenSourceRefreshesOnceOnInvalidToken(t *testing.T) {
	first, renewed := "vi_at_testtesttesttesttesttesttesttesttesttest", renewedToken
	expired := answerWith(401, apiError("unauthorized", "the access token is invalid, expired or revoked"),
		"WWW-Authenticate", `Bearer error="invalid_token"`)
	pending := map[string]any{"status": "pending", "job_id": jobID}

	// A 401 that says the token is invalid: refreshed once, and sent again with the new token and the same key.
	api := newFakeAPI(t, []exchange{
		on("POST", "/v1/jobs/"+jobID+"/resolve", expired),
		on("POST", "/v1/jobs/"+jobID+"/resolve", answerWith(201, map[string]any{
			"id": "019a3c01-5d2e-7f3a-8b4c-9d0e1f2a3b4c", "status": "running", "total": 3,
			"skipped": map[string]int{"ineligible": 0, "excluded": 0, "already_requested": 0, "duplicate": 0},
		})),
	}, fakeOptions{})
	source := &tokens{tokens: []string{first, renewed}}
	client, err := verifyinboxes.NewClient(verifyinboxes.WithTokenSource(source), verifyinboxes.WithBaseURL(api.URL),
		verifyinboxes.WithHTTPClient(newHTTPClient(t)))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := client.Lists.Resolve(context.Background(), jobID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Status != verifyinboxes.JobRunning { // a JobStatus, as a Job's is
		t.Errorf("status %q", resolved.Status)
	}
	sent := api.recordedRequests()
	if len(sent) != 2 || source.refreshes != 1 {
		t.Fatalf("%d requests, %d refreshes", len(sent), source.refreshes)
	}
	if sent[0].Header.Get("Authorization") != "Bearer "+first || sent[1].Header.Get("Authorization") != "Bearer "+renewed {
		t.Error("the retry does not carry the new token")
	}
	k0, _ := sent[0].idempotencyKey()
	k1, _ := sent[1].idempotencyKey()
	if k0 == "" || k0 != k1 {
		t.Errorf("Idempotency-Key %q then %q", k0, k1)
	}

	// A second 401 is returned, after one refresh; a 401 that does not say so is never refreshed for.
	api = newFakeAPI(t, []exchange{on("POST", "/v1/verify", expired), on("POST", "/v1/verify", expired)}, fakeOptions{})
	source = &tokens{tokens: []string{first, renewed}}
	client, _ = verifyinboxes.NewClient(verifyinboxes.WithTokenSource(source), verifyinboxes.WithBaseURL(api.URL),
		verifyinboxes.WithHTTPClient(newHTTPClient(t)))
	err = errorOf(t, second(client.Verify(context.Background(), "ann@example.com", nil)))
	if !errors.Is(err, verifyinboxes.ErrAuthentication) || api.count() != 2 || source.refreshes != 1 {
		t.Errorf("%v: %d requests, %d refreshes", err, api.count(), source.refreshes)
	}

	plain := answerWith(401, apiError("unauthorized", "missing, malformed or revoked API key"))
	api = newFakeAPI(t, []exchange{on("POST", "/v1/verify", plain), on("POST", "/v1/verify", answerWith(202, pending))}, fakeOptions{})
	source = &tokens{tokens: []string{first, renewed}}
	client, _ = verifyinboxes.NewClient(verifyinboxes.WithTokenSource(source), verifyinboxes.WithBaseURL(api.URL),
		verifyinboxes.WithHTTPClient(newHTTPClient(t)))
	if err := second(client.Verify(context.Background(), "ann@example.com", nil)); !errors.Is(err, verifyinboxes.ErrAuthentication) ||
		api.count() != 1 || source.refreshes != 0 {
		t.Errorf("%v: %d requests, %d refreshes", err, api.count(), source.refreshes)
	}
}

func TestARefreshDoesNotResendAnUploadReadOnce(t *testing.T) {
	expired := answerWith(401, apiError("unauthorized", "the access token is invalid, expired or revoked"),
		"WWW-Authenticate", `Bearer error="invalid_token"`)
	newClient := func(api *fakeAPI, source verifyinboxes.TokenSource) *verifyinboxes.Client {
		client, err := verifyinboxes.NewClient(verifyinboxes.WithTokenSource(source), verifyinboxes.WithBaseURL(api.URL),
			verifyinboxes.WithHTTPClient(newHTTPClient(t)))
		if err != nil {
			t.Fatal(err)
		}
		verifyinboxes.SetHooks(client, newPaperClock().sleep, nil, nil)
		return client
	}

	// A reader that can be read only once: the token is refreshed, for the next call, but the upload is not sent
	// again (its file part would be empty); the 401 is returned.
	api := newFakeAPI(t, uploadExchanges(expired, "list.csv")[:1], fakeOptions{})
	source := &tokens{tokens: []string{"vi_at_testtesttesttesttesttesttesttesttesttest", renewedToken}}
	reader := &oneWay{chunks: [][]byte{[]byte(csvText[:10]), []byte(csvText[10:])}}
	err := errorOf(t, second(newClient(api, source).Lists.Create(context.Background(), &verifyinboxes.CreateListParams{File: reader})))
	if !errors.Is(err, verifyinboxes.ErrAuthentication) || api.count() != 1 || source.refreshes != 1 {
		t.Errorf("%v: %d requests, %d refreshes", err, api.count(), source.refreshes)
	}
	if _, unexpected, _, _ := api.seen(); len(unexpected) != 0 {
		t.Errorf("%d requests the scenario does not have", len(unexpected))
	}

	// A reader that seeks is sent again, whole, with the new token and the same key.
	api = newFakeAPI(t, uploadExchanges(expired, "list.csv"), fakeOptions{})
	source = &tokens{tokens: []string{"vi_at_testtesttesttesttesttesttesttesttesttest", renewedToken}}
	created, err := newClient(api, source).Lists.Create(context.Background(), &verifyinboxes.CreateListParams{File: strings.NewReader(csvText)})
	if err != nil || created.ID != jobID || fmt.Sprint(sentFiles(api)) != fmt.Sprint([]string{csvText, csvText}) {
		t.Fatalf("%+v %v %q", created, err, sentFiles(api))
	}
	sent := api.recordedRequests()
	k0, _ := sent[0].idempotencyKey()
	k1, _ := sent[1].idempotencyKey()
	if sent[1].Header.Get("Authorization") != "Bearer "+renewedToken || k0 == "" || k0 != k1 {
		t.Errorf("the retry: %q, keys %q %q", sent[1].Header.Get("Authorization"), k0, k1)
	}
}

// rotatingTokens is a TokenSource whose Refresh takes a while and may be used once per token: a second Refresh of
// the same token fails, as a refresh token used twice is refused.
type rotatingTokens struct {
	mu         sync.Mutex
	token      string
	refreshes  atomic.Int32
	inRefresh  atomic.Int32
	overlapped atomic.Bool
}

func (s *rotatingTokens) Token(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token, nil
}

func (s *rotatingTokens) Refresh(context.Context) error {
	if s.inRefresh.Add(1) > 1 {
		s.overlapped.Store(true)
	}
	defer s.inRefresh.Add(-1)
	time.Sleep(20 * time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refreshes.Add(1) > 1 {
		return errors.New("the refresh token was already used")
	}
	s.token = renewedToken
	return nil
}

func TestConcurrentRequestsRefreshTheTokenOnce(t *testing.T) {
	expired := answerWith(401, apiError("unauthorized", "the access token is invalid, expired or revoked"),
		"WWW-Authenticate", `Bearer error="invalid_token"`)
	emails := tenEmails()
	var exchanges []exchange
	for i, email := range emails {
		body := map[string]string{"email": email}
		exchanges = append(exchanges,
			on("POST", "/v1/verify", expired, body),
			on("POST", "/v1/verify", answerWith(200, withJob(resultJSON(email, "invalid"), singleJobID(i+1))), body))
	}
	// Every first answer waits until the ten requests are in flight: all ten are refused with the same token.
	api := newFakeAPI(t, exchanges, fakeOptions{unordered: true, holdUntil: 10})
	source := &rotatingTokens{token: "vi_at_testtesttesttesttesttesttesttesttesttest"}
	client, err := verifyinboxes.NewClient(verifyinboxes.WithTokenSource(source), verifyinboxes.WithBaseURL(api.URL),
		verifyinboxes.WithHTTPClient(newHTTPClient(t)))
	if err != nil {
		t.Fatal(err)
	}
	verifyinboxes.SetHooks(client, newPaperClock().sleep, nil, nil)
	results, err := client.VerifyMany(context.Background(), emails, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, heldOut, most := api.seen(); heldOut {
		t.Fatalf("only %d requests were in flight at once", most)
	}
	if n := source.refreshes.Load(); n != 1 || source.overlapped.Load() {
		t.Errorf("Refresh was called %d times (overlapping: %v)", n, source.overlapped.Load())
	}
	for i, r := range results {
		if r.Email != emails[i] || r.JobID != singleJobID(i+1) {
			t.Errorf("result %d: %s %s", i, r.Email, r.JobID)
		}
	}
	byEmail := map[string][]*recorded{}
	for _, r := range api.recordedRequests() {
		email := r.JSON.(map[string]any)["email"].(string)
		byEmail[email] = append(byEmail[email], r)
	}
	for _, email := range emails {
		sent := byEmail[email]
		if len(sent) != 2 {
			t.Errorf("%s: %d requests", email, len(sent))
			continue
		}
		k0, _ := sent[0].idempotencyKey()
		k1, _ := sent[1].idempotencyKey()
		if sent[0].Header.Get("Authorization") != "Bearer vi_at_testtesttesttesttesttesttesttesttesttest" ||
			sent[1].Header.Get("Authorization") != "Bearer "+renewedToken || k0 == "" || k0 != k1 {
			t.Errorf("%s: %q then %q, keys %q %q", email, sent[0].Header.Get("Authorization"),
				sent[1].Header.Get("Authorization"), k0, k1)
		}
	}
}

// failingSource is a TokenSource whose token is refused before anything is sent.
type failingSource struct{ token string }

func (s failingSource) Token(context.Context) (string, error) {
	if s.token == "" {
		return "", errors.New("signed out")
	}
	return s.token, nil
}

func TestATokenSourceThatFailsSendsNothing(t *testing.T) {
	api := newFakeAPI(t, nil, fakeOptions{})
	for _, source := range []failingSource{{}, {token: "vi_at_ test"}} {
		client, err := verifyinboxes.NewClient(verifyinboxes.WithTokenSource(source), verifyinboxes.WithBaseURL(api.URL))
		if err != nil {
			t.Fatal(err)
		}
		err = errorOf(t, second(client.Account.Get(context.Background())))
		if strings.Contains(err.Error(), "vi_at_") {
			t.Errorf("the error shows the token: %v", err)
		}
	}
	if api.count() != 0 {
		t.Errorf("%d requests", api.count())
	}
}

// ---- verify and verify many ----------------------------------------------------------------------------------------

func TestVerifyManyConcurrent(t *testing.T) {
	emails := tenEmails()
	var exchanges []exchange
	for i, email := range emails {
		exchanges = append(exchanges, on("POST", "/v1/verify", answerWith(200, withJob(resultJSON(email, "invalid"), singleJobID(i+1))),
			map[string]string{"email": email}))
	}
	api := newFakeAPI(t, exchanges, fakeOptions{unordered: true, holdUntil: 10})
	clock := newPaperClock()
	client, _ := clientOf(t, api, clock)
	results, err := client.VerifyMany(context.Background(), emails, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, heldOut, most := api.seen(); heldOut {
		t.Fatalf("only %d checks were in flight at once", most)
	}
	for i, r := range results {
		if r.Email != emails[i] || r.JobID != singleJobID(i+1) {
			t.Errorf("result %d: %s %s", i, r.Email, r.JobID)
		}
	}
	slept := clock.sleeps()
	if len(slept) != 9 {
		t.Fatalf("slept %v", slept)
	}
	for _, d := range slept {
		if d != 100*time.Millisecond {
			t.Errorf("slept %v between starts", d)
		}
	}
	keys := map[string]bool{}
	for _, r := range api.recordedRequests() {
		key, _ := r.idempotencyKey()
		keys[key] = true
	}
	if len(keys) != 10 {
		t.Errorf("%d keys for 10 checks", len(keys))
	}
}

func TestVerifyManyNamesEveryJobItMadeWhenOneFails(t *testing.T) {
	// p3 is still running when the time runs out, p7 is refused (402), the others answer at once.
	emails := tenEmails()
	var exchanges []exchange
	for i, email := range emails {
		n := i + 1
		resp := answerWith(200, withJob(resultJSON(email, "invalid"), singleJobID(n)))
		switch n {
		case 3:
			resp = answerWith(202, map[string]any{"status": "pending", "job_id": singleJobID(3)})
		case 7:
			resp = answerWith(402, apiError("insufficient_credits", "top up"))
		}
		exchanges = append(exchanges, on("POST", "/v1/verify", resp, map[string]string{"email": email}))
	}
	for i := 0; i < 20; i++ {
		exchanges = append(exchanges, on("GET", "/v1/jobs/"+singleJobID(3), answerWith(200, runningJob(singleJobID(3), "single"))))
	}
	api := newFakeAPI(t, exchanges, fakeOptions{unordered: true})
	client, _ := clientOf(t, api, newPaperClock())
	err := errorOf(t, second(client.VerifyMany(context.Background(), emails, &verifyinboxes.VerifyManyParams{Timeout: 5 * time.Second})))
	// The first error in input order (p3's wait), naming every job the call made, in input order.
	var waitErr *verifyinboxes.WaitTimeoutError
	if !errors.As(err, &waitErr) {
		t.Fatalf("%T %v", err, err)
	}
	var want []string
	for n := 1; n <= 10; n++ {
		if n != 7 {
			want = append(want, singleJobID(n))
		}
	}
	if fmt.Sprint(waitErr.JobIDs) != fmt.Sprint(want) || fmt.Sprint(verifyinboxes.JobIDs(err)) != fmt.Sprint(want) {
		t.Errorf("job ids %v, not %v", waitErr.JobIDs, want)
	}
}

func TestVerifyManyRefusesBadInputBeforeAnyRequest(t *testing.T) {
	api := newFakeAPI(t, nil, fakeOptions{})
	client, _ := clientOf(t, api, nil)
	for _, bad := range [][]string{nil, {}, {"ann@example.com", ""}, {"ann@example.com", "  "}} {
		if _, err := client.VerifyMany(context.Background(), bad, nil); err == nil {
			t.Errorf("%q was taken", bad)
		}
	}
	if _, err := client.Verify(context.Background(), " ", nil); err == nil {
		t.Error("an empty address was taken")
	}
	if _, err := client.Verify(context.Background(), "ann@example.com", &verifyinboxes.VerifyParams{IdempotencyKey: "has space"}); err == nil {
		t.Error("a key with a space was taken")
	}
	if api.count() != 0 {
		t.Errorf("%d requests", api.count())
	}
}

func TestStartDoesNotWait(t *testing.T) {
	api := newFakeAPI(t, []exchange{
		on("POST", "/v1/verify", answerWith(202, map[string]any{"status": "pending", "job_id": jobID})),
		on("POST", "/v1/verify", answerWith(200, withJob(resultJSON("bob@example.com", "valid"), singleJobID(2)))),
	}, fakeOptions{})
	client, _ := clientOf(t, api, newPaperClock())
	check, err := client.Checks.Start(context.Background(), "ann@example.com", nil)
	if err != nil || !check.Pending || check.JobID != jobID || check.Result != nil {
		t.Fatalf("%+v %v", check, err)
	}
	check, err = client.Checks.Start(context.Background(), "bob@example.com", nil)
	if err != nil || check.Pending || check.JobID != singleJobID(2) || check.Result == nil || check.Result.Verdict != verifyinboxes.VerdictValid {
		t.Fatalf("%+v %v", check, err)
	}
}

// ---- cancellation --------------------------------------------------------------------------------------------------

// cancellingAt is a sleep that cancels when a pause of d begins, then waits as the client's own does.
func cancellingAt(d time.Duration, cancel context.CancelFunc) func(context.Context, time.Duration) error {
	return func(ctx context.Context, pause time.Duration) error {
		if pause == d {
			cancel()
			return realSleep(ctx, time.Minute)
		}
		return realSleep(ctx, pause)
	}
}

// returned reports whether done has been closed within 50 milliseconds.
func returned(done chan struct{}) bool {
	select {
	case <-done:
		return true
	case <-time.After(50 * time.Millisecond):
		return false
	}
}

func TestCancelledBeforeAnythingIsSent(t *testing.T) {
	api := newFakeAPI(t, nil, fakeOptions{})
	client, _ := clientOf(t, api, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Account.Get(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("%v", err)
	}
	if _, err := client.Verify(ctx, "ann@example.com", nil); !errors.Is(err, context.Canceled) {
		t.Errorf("%v", err)
	}
	if api.count() != 0 {
		t.Errorf("%d requests", api.count())
	}
}

func TestCancellingAWaitNamesTheCheck(t *testing.T) {
	api := newFakeAPI(t, []exchange{
		on("POST", "/v1/verify", answerWith(202, map[string]any{"status": "pending", "job_id": jobID})),
		on("GET", "/v1/jobs/"+jobID, answerWith(200, runningJob(jobID, "single"))),
	}, fakeOptions{})
	client, _ := clientOf(t, api, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	verifyinboxes.SetHooks(client, cancellingAt(2*time.Second, cancel), nil, nil)
	err := errorOf(t, second(client.Verify(ctx, "ann@example.com", nil)))
	if !errors.Is(err, context.Canceled) || fmt.Sprint(verifyinboxes.JobIDs(err)) != "["+jobID+"]" || !strings.Contains(err.Error(), jobID) {
		t.Errorf("%v: %v", err, verifyinboxes.JobIDs(err))
	}

	again := newFakeAPI(t, []exchange{on("GET", "/v1/jobs/"+jobID, answerWith(200, runningJob(jobID, "single")))}, fakeOptions{})
	waiting, _ := clientOf(t, again, nil)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	verifyinboxes.SetHooks(waiting, cancellingAt(2*time.Second, cancel2), nil, nil)
	err = errorOf(t, second(waiting.Checks.Wait(ctx2, jobID, nil)))
	if !errors.Is(err, context.Canceled) || fmt.Sprint(verifyinboxes.JobIDs(err)) != "["+jobID+"]" {
		t.Errorf("%v", err)
	}
}

func TestACheckAlreadySentFinishesWhenCancelledAndIsNamed(t *testing.T) {
	api := newFakeAPI(t, []exchange{
		on("POST", "/v1/verify", answerWith(202, map[string]any{"status": "pending", "job_id": jobID})),
	}, fakeOptions{gated: true})
	client, _ := clientOf(t, api, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var err error
	go func() {
		defer close(done)
		_, err = client.Verify(ctx, "ann@example.com", nil)
	}()
	until(t, "the check to be sent", func() bool { return api.count() == 1 })
	cancel()
	if returned(done) {
		t.Fatal("the check sent was cut off")
	}
	api.release()
	<-done
	if !errors.Is(err, context.Canceled) || fmt.Sprint(verifyinboxes.JobIDs(err)) != "["+jobID+"]" {
		t.Errorf("%v: %v", err, verifyinboxes.JobIDs(err))
	}
	if api.count() != 1 {
		t.Errorf("%d requests: something was sent after the cancellation", api.count())
	}
}

func TestVerifyManyLetsTheChecksAlreadySentFinishAndNamesEveryOne(t *testing.T) {
	// Even checks answer at once (200), odd ones are still running (202): either way the server made a job.
	emails := tenEmails()
	var exchanges []exchange
	for i, email := range emails {
		resp := answerWith(200, withJob(resultJSON(email, "invalid"), singleJobID(i+1)))
		if i%2 == 1 {
			resp = answerWith(202, map[string]any{"status": "pending", "job_id": singleJobID(i + 1)})
		}
		exchanges = append(exchanges, on("POST", "/v1/verify", resp, map[string]string{"email": email}))
	}
	api := newFakeAPI(t, exchanges, fakeOptions{unordered: true, gated: true})
	client, _ := clientOf(t, api, nil)
	var starts atomic.Int32
	verifyinboxes.SetHooks(client, func(ctx context.Context, d time.Duration) error {
		if d == 100*time.Millisecond && starts.Add(1) < 4 {
			return nil // 4 start, the 5th waits
		}
		return realSleep(ctx, time.Minute)
	}, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var err error
	go func() {
		defer close(done)
		_, err = client.VerifyMany(ctx, emails, nil)
	}()
	until(t, "4 checks to be sent", func() bool { return api.count() == 4 })
	cancel()
	if returned(done) {
		t.Fatal("the checks sent were cut off")
	}
	api.release()
	<-done
	want := fmt.Sprint([]string{singleJobID(1), singleJobID(2), singleJobID(3), singleJobID(4)})
	if !errors.Is(err, context.Canceled) || fmt.Sprint(verifyinboxes.JobIDs(err)) != want {
		t.Errorf("%v: %v, not %s", err, verifyinboxes.JobIDs(err), want)
	}
	if api.count() != 4 {
		t.Errorf("%d requests: a check was started or polled after the cancellation", api.count())
	}
}

func TestVerifyManyLetsItsListFinishAndNamesIt(t *testing.T) {
	emails := append(tenEmails(), "p11@example.com")
	api := newFakeAPI(t, []exchange{
		on("POST", "/v1/jobs", answerWith(201, map[string]any{"id": jobID, "status": "running", "total": 11}), map[string]any{"emails": emails}),
	}, fakeOptions{gated: true})
	client, _ := clientOf(t, api, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var err error
	go func() {
		defer close(done)
		_, err = client.VerifyMany(ctx, emails, nil)
	}()
	until(t, "the list to be sent", func() bool { return api.count() == 1 })
	cancel()
	if returned(done) {
		t.Fatal("the list sent was cut off")
	}
	api.release()
	<-done
	if !errors.Is(err, context.Canceled) || fmt.Sprint(verifyinboxes.JobIDs(err)) != "["+jobID+"]" {
		t.Errorf("%v: %v", err, verifyinboxes.JobIDs(err))
	}
	if api.count() != 1 {
		t.Errorf("%d requests", api.count())
	}

	// Cancelled while waiting for the list: named too.
	api = newFakeAPI(t, []exchange{
		on("POST", "/v1/jobs", answerWith(201, map[string]any{"id": jobID, "status": "running", "total": 11}), map[string]any{"emails": emails}),
		on("GET", "/v1/jobs/"+jobID, answerWith(200, runningJob(jobID, "bulk"))),
	}, fakeOptions{})
	client, _ = clientOf(t, api, nil)
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	verifyinboxes.SetHooks(client, cancellingAt(2*time.Second, cancel), nil, nil)
	err = errorOf(t, second(client.VerifyMany(ctx, emails, nil)))
	if !errors.Is(err, context.Canceled) || fmt.Sprint(verifyinboxes.JobIDs(err)) != "["+jobID+"]" {
		t.Errorf("%v: %v", err, verifyinboxes.JobIDs(err))
	}
}

func TestAListCreatedOnItsOwnStopsAtOnce(t *testing.T) {
	api := newFakeAPI(t, []exchange{
		on("POST", "/v1/jobs", answerWith(201, map[string]any{"id": jobID, "status": "running", "total": 1})),
	}, fakeOptions{gated: true})
	client, _ := clientOf(t, api, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var err error
	go func() {
		defer close(done)
		_, err = client.Lists.Create(ctx, &verifyinboxes.CreateListParams{Emails: []string{"ann@example.com"}})
	}()
	until(t, "the list to be sent", func() bool { return api.count() == 1 })
	cancel()
	if !returned(done) {
		t.Fatal("Lists.Create did not stop at once")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("%v", err)
	}
}

// ---- results -------------------------------------------------------------------------------------------------------

func page(emails []string, start int, next any) map[string]any {
	rows := []map[string]any{}
	for i, email := range emails {
		row := resultJSON(email, "invalid")
		row["row"] = start + i
		rows = append(rows, row)
	}
	return map[string]any{"data": rows, "next_cursor": next, "complete": true}
}

func TestResultsReadNothingUntilIteratedThenEveryRowOnce(t *testing.T) {
	path := "/v1/jobs/" + jobID + "/results"
	exchanges := []exchange{
		on("GET", path, answerWith(200, page([]string{"a@example.com", "b@example.com"}, 1, "c1"))),
		on("GET", path, answerWith(200, page(nil, 3, "c2"))),
		on("GET", path, answerWith(200, page([]string{"c@example.com"}, 3, nil))),
	}
	exchanges[0].Request.Query = map[string]string{"limit": "2"}
	exchanges[1].Request.Query = map[string]string{"limit": "2", "cursor": "c1"}
	exchanges[2].Request.Query = map[string]string{"limit": "2", "cursor": "c2"}
	api := newFakeAPI(t, exchanges, fakeOptions{})
	client, _ := clientOf(t, api, nil)
	rows := client.Lists.Results(context.Background(), jobID, &verifyinboxes.ResultsParams{PageSize: 2})
	if api.count() != 0 {
		t.Fatal("asked before iterating")
	}
	var seen []string
	rows.All()(func(row verifyinboxes.ResultRow, err error) bool {
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, fmt.Sprintf("%d %s", row.Row, row.Email))
		return true
	})
	if fmt.Sprint(seen) != "[1 a@example.com 2 b@example.com 3 c@example.com]" {
		t.Errorf("%v", seen)
	}
	for i, r := range api.recordedRequests() {
		if q, _ := parseQuery(r.RawQuery); fmt.Sprint(q) != fmt.Sprint(exchanges[i].Request.Query) {
			t.Errorf("request %d: %v", i, q)
		}
	}
}

func TestResultsStopWhenAPageWithRowsRepeatsTheCursor(t *testing.T) {
	path := "/v1/jobs/" + jobID + "/results"
	repeated := page([]string{"a@example.com"}, 1, "c1")
	api := newFakeAPI(t, []exchange{on("GET", path, answerWith(200, repeated)), on("GET", path, answerWith(200, repeated))}, fakeOptions{})
	client, _ := clientOf(t, api, nil)
	rows := client.Lists.Results(context.Background(), jobID, nil)
	var seen []string
	for rows.Next() {
		seen = append(seen, rows.Current().Email)
	}
	err := rows.Err()
	if !errors.Is(err, verifyinboxes.ErrUnexpectedAnswer) || !strings.Contains(err.Error(), "same cursor") {
		t.Errorf("%v", err)
	}
	if fmt.Sprint(seen) != "[a@example.com a@example.com]" || api.count() != 2 {
		t.Errorf("%v, %d requests", seen, api.count())
	}
	if rows.Next() || api.count() != 2 {
		t.Error("asked again after the error")
	}
}

func TestIterAllStopsWhenTold(t *testing.T) {
	path := "/v1/jobs/" + jobID + "/results"
	api := newFakeAPI(t, []exchange{
		on("GET", path, answerWith(200, page([]string{"a@example.com", "b@example.com"}, 1, "c1"))),
		on("GET", path, answerWith(404, apiError("not_found", "no such job"))),
	}, fakeOptions{})
	client, _ := clientOf(t, api, nil)
	var seen []string
	client.Lists.Results(context.Background(), jobID, nil).All()(func(row verifyinboxes.ResultRow, err error) bool {
		seen = append(seen, row.Email)
		return false
	})
	if fmt.Sprint(seen) != "[a@example.com]" || api.count() != 1 {
		t.Errorf("%v, %d requests", seen, api.count())
	}
	var last error
	client.Lists.Results(context.Background(), jobID, nil).All()(func(row verifyinboxes.ResultRow, err error) bool {
		last = err
		return true
	})
	if !errors.Is(last, verifyinboxes.ErrNotFound) {
		t.Errorf("the last pair does not carry the error: %v", last)
	}
	if _, err := client.Lists.Results(context.Background(), jobID, &verifyinboxes.ResultsParams{PageSize: 1001}).Collect(); err == nil {
		t.Error("a page size of 1001 was taken")
	}
}

// ---- uploads -------------------------------------------------------------------------------------------------------

const csvText = "email\nann@example.com\nbob@example.com\n"

var listCreated = map[string]any{"id": jobID, "status": "running", "total": 2}

func uploadExchanges(first scriptedResponse, filename string) []exchange {
	parts := []part{{Name: "email_column", Value: "email"}, {Name: "file", Filename: &filename, ContentType: ptr("text/csv"), Value: csvText}}
	return []exchange{
		{Request: expectedRequest{Method: "POST", Path: "/v1/jobs", Multipart: parts}, Response: first},
		{Request: expectedRequest{Method: "POST", Path: "/v1/jobs", Multipart: parts}, Response: answerWith(201, listCreated)},
	}
}

func ptr[T any](v T) *T { return &v }

func sentFiles(api *fakeAPI) []string {
	var out []string
	for _, r := range api.recordedRequests() {
		if len(r.Multipart) == 2 {
			out = append(out, r.Multipart[1].Value)
		}
	}
	return out
}

// oneWay is a reader that can be read only once, in two pieces.
type oneWay struct{ chunks [][]byte }

func (r *oneWay) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks[0] = r.chunks[0][n:]
	if len(r.chunks[0]) == 0 {
		r.chunks = r.chunks[1:]
	}
	return n, nil
}

func TestReaderNotResent(t *testing.T) {
	ctx := context.Background()
	unavailable := answerWith(503, apiError("unavailable", "try again"), "Retry-After", "1")

	// A path: opened again for the retry, and named by its file name.
	dir := t.TempDir()
	file := filepath.Join(dir, "prospects.csv")
	if err := os.WriteFile(file, []byte(csvText), 0o600); err != nil {
		t.Fatal(err)
	}
	api := newFakeAPI(t, uploadExchanges(dropped, "prospects.csv"), fakeOptions{})
	client, hc := clientOf(t, api, newPaperClock())
	warm(t, hc, api)
	created, err := client.Lists.CreateFromFile(ctx, file, nil)
	if err != nil || created.ID != jobID || fmt.Sprint(sentFiles(api)) != fmt.Sprint([]string{csvText, csvText}) {
		t.Fatalf("%+v %v %q", created, err, sentFiles(api))
	}
	reqs := api.recordedRequests()
	k0, _ := reqs[0].idempotencyKey()
	k1, _ := reqs[1].idempotencyKey()
	if k0 == "" || k0 != k1 {
		t.Errorf("keys %q %q", k0, k1)
	}

	// A reader that can be read again (it seeks), the CSV's text, and its bytes: sent again whole.
	for name, params := range map[string]*verifyinboxes.CreateListParams{
		"seeker": {File: bytes.NewReader([]byte(csvText))},
		"text":   {CSV: csvText},
	} {
		api := newFakeAPI(t, uploadExchanges(unavailable, "list.csv"), fakeOptions{})
		clock := newPaperClock()
		client, _ := clientOf(t, api, clock)
		if created, err := client.Lists.Create(ctx, params); err != nil || created.ID != jobID || created.Status != verifyinboxes.JobRunning {
			t.Fatalf("%s: %+v %v", name, created, err)
		}
		if fmt.Sprint(sentFiles(api)) != fmt.Sprint([]string{csvText, csvText}) || fmt.Sprint(clock.sleeps()) != "[1s]" {
			t.Errorf("%s: %q, slept %v", name, sentFiles(api), clock.sleeps())
		}
	}

	// A reader that can be read only once: never sent again once its sending began.
	api = newFakeAPI(t, uploadExchanges(dropped, "list.csv"), fakeOptions{})
	clock := newPaperClock()
	client, hc = clientOf(t, api, clock)
	warm(t, hc, api)
	reader := &oneWay{chunks: [][]byte{[]byte(csvText[:10]), []byte(csvText[10:])}}
	err = errorOf(t, second(client.Lists.Create(ctx, &verifyinboxes.CreateListParams{File: reader})))
	var connErr *verifyinboxes.ConnectionError
	if !errors.As(err, &connErr) || len(sentFiles(api)) != 1 || len(clock.sleeps()) != 0 {
		t.Errorf("%v: %d sent, slept %v", err, len(sentFiles(api)), clock.sleeps())
	}
}

func TestCreateTakesExactlyOneSource(t *testing.T) {
	api := newFakeAPI(t, nil, fakeOptions{})
	client, _ := clientOf(t, api, nil)
	ctx := context.Background()
	for _, p := range []*verifyinboxes.CreateListParams{
		nil, {}, {Emails: []string{"a@example.com"}, CSV: csvText}, {CSV: csvText, File: strings.NewReader(csvText)},
	} {
		if _, err := client.Lists.Create(ctx, p); err == nil {
			t.Errorf("%+v was taken", p)
		}
	}
	if _, err := client.Lists.CreateFromFile(ctx, filepath.Join(t.TempDir(), "missing.csv"), nil); err == nil {
		t.Error("a missing file was taken")
	}
	if api.count() != 0 {
		t.Errorf("%d requests", api.count())
	}
}

// ---- downloads -----------------------------------------------------------------------------------------------------

func TestDownloadFileAtomic(t *testing.T) {
	path := "/v1/jobs/" + jobID + "/download"
	body := "email,verdict\n" + strings.Repeat("ann@example.com,invalid\n", 50)
	cut := textAnswer(200, "text/csv; charset=utf-8", body)
	cut.CutAfter = ptr(100)
	whole := textAnswer(200, "text/csv; charset=utf-8", body)
	dir := t.TempDir()
	target := filepath.Join(dir, "results.csv")
	if err := os.WriteFile(target, []byte("the results from before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	listDir := func() []string {
		entries, _ := os.ReadDir(dir)
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		sort.Strings(names)
		return names
	}

	api := newFakeAPI(t, []exchange{on("GET", path, cut)}, fakeOptions{})
	client, _ := clientOf(t, api, newPaperClock(), verifyinboxes.WithMaxRetries(0))
	err := errorOf(t, second(client.Lists.DownloadFile(context.Background(), jobID, target, nil)))
	if !errors.Is(err, verifyinboxes.ErrConnection) {
		t.Errorf("%v", err)
	}
	if text, _ := os.ReadFile(target); string(text) != "the results from before\n" || fmt.Sprint(listDir()) != "[results.csv]" {
		t.Errorf("%q %v", text, listDir())
	}

	api = newFakeAPI(t, []exchange{on("GET", path, cut), on("GET", path, whole)}, fakeOptions{})
	client, _ = clientOf(t, api, newPaperClock())
	n, err := client.Lists.DownloadFile(context.Background(), jobID, target, nil)
	if err != nil || n != int64(len(body)) {
		t.Fatalf("%d %v", n, err)
	}
	if text, _ := os.ReadFile(target); string(text) != body || fmt.Sprint(listDir()) != "[results.csv]" {
		t.Errorf("%.40q %v", text, listDir())
	}
	if accept := api.recordedRequests()[1].Header.Get("Accept"); accept != "text/csv" {
		t.Errorf("Accept: %q", accept)
	}
}

// failAfter is a writer that takes n bytes, then fails.
type failAfter struct {
	buf bytes.Buffer
	n   int
}

func (w *failAfter) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.n {
		return 0, errors.New("disk full")
	}
	return w.buf.Write(p)
}

func TestDownloadToAWriterIsRetriedOnlyBeforeItsFirstByte(t *testing.T) {
	path := "/v1/jobs/" + jobID + "/download"
	body := "email,verdict\n" + strings.Repeat("ann@example.com,invalid\n", 50)
	whole := textAnswer(200, "text/csv; charset=utf-8", body)
	cut := textAnswer(200, "text/csv; charset=utf-8", body)
	cut.CutAfter = ptr(100)

	api := newFakeAPI(t, []exchange{on("GET", path, dropped), on("GET", path, whole)}, fakeOptions{})
	client, _ := clientOf(t, api, newPaperClock())
	var out bytes.Buffer
	n, err := client.Lists.Download(context.Background(), jobID, &out, &verifyinboxes.DownloadParams{OnlySafeToSend: true})
	if err != nil || n != int64(len(body)) || out.String() != body || api.count() != 2 {
		t.Fatalf("%d %v, %d requests", n, err, api.count())
	}
	if q := api.recordedRequests()[1].RawQuery; q != "only=safe_to_send" {
		t.Errorf("query %q", q)
	}

	api = newFakeAPI(t, []exchange{on("GET", path, cut), on("GET", path, whole)}, fakeOptions{})
	client, _ = clientOf(t, api, newPaperClock())
	out.Reset()
	err = errorOf(t, second(client.Lists.Download(context.Background(), jobID, &out, nil)))
	if !errors.Is(err, verifyinboxes.ErrConnection) || api.count() != 1 || out.Len() != 100 {
		t.Errorf("%v: %d requests, %d bytes", err, api.count(), out.Len())
	}

	api = newFakeAPI(t, []exchange{on("GET", path, whole), on("GET", path, whole)}, fakeOptions{})
	client, _ = clientOf(t, api, newPaperClock())
	err = errorOf(t, second(client.Lists.Download(context.Background(), jobID, &failAfter{n: 10}, nil)))
	if !strings.Contains(err.Error(), "disk full") || api.count() != 1 {
		t.Errorf("%v: %d requests", err, api.count())
	}
}

// ---- the transport -------------------------------------------------------------------------------------------------

// reuseRecorder is a RoundTripper that writes down whether each request went out on a connection used before.
type reuseRecorder struct {
	base   http.RoundTripper
	mu     sync.Mutex
	reused map[string][]bool
}

func (r *reuseRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.reused[req.Method+" "+req.URL.Path] = append(r.reused[req.Method+" "+req.URL.Path], info.Reused)
	}}
	return r.base.RoundTrip(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
}

// closingServer answers GET /warm with 204, and reads every other request whole, then closes its connection with no
// answer. It counts what it read.
func closingServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/warm" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		posts.Add(1)
		hijackAndClose(w, nil)
	}))
	t.Cleanup(server.Close)
	return server, &posts
}

// TestNoTransportResend: net/http sends a request again by itself when a connection it had used before is closed
// without an answer, if the request looks idempotent, and an Idempotency-Key header makes a POST look so. The client
// must decide every resend itself: a webhook made twice would be two webhooks.
func TestNoTransportResend(t *testing.T) {
	ctx := context.Background()
	calls := map[string]func(c *verifyinboxes.Client) error{
		"webhooks.create": func(c *verifyinboxes.Client) error {
			return second(c.Webhooks.Create(ctx, &verifyinboxes.WebhookParams{URL: "https://example.com/hook"}))
		},
		"integrations.create": func(c *verifyinboxes.Client) error {
			return second(c.Integrations.Create(ctx, &verifyinboxes.IntegrationParams{Provider: "instantly"}))
		},
		"verify": func(c *verifyinboxes.Client) error { return second(c.Verify(ctx, "ann@example.com", nil)) },
		"lists.resolve, no body": func(c *verifyinboxes.Client) error {
			return second(c.Lists.Resolve(ctx, jobID, nil))
		},
		"lists.create": func(c *verifyinboxes.Client) error {
			return second(c.Lists.Create(ctx, &verifyinboxes.CreateListParams{CSV: csvText}))
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			server, posts := closingServer(t)
			transport := &http.Transport{}
			defer transport.CloseIdleConnections()
			recorder := &reuseRecorder{base: transport, reused: map[string][]bool{}}
			hc := &http.Client{Transport: recorder}
			client, err := verifyinboxes.NewClient(verifyinboxes.WithAPIKey(testKey), verifyinboxes.WithBaseURL(server.URL),
				verifyinboxes.WithHTTPClient(hc), verifyinboxes.WithMaxRetries(0))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := hc.Get(server.URL + "/warm")
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			err = call(client)
			if !errors.Is(err, verifyinboxes.ErrConnection) {
				t.Fatalf("%v", err)
			}
			if posts.Load() != 1 {
				t.Errorf("the server read %d requests: the transport sent it again", posts.Load())
			}
			recorder.mu.Lock()
			defer recorder.mu.Unlock()
			reusedOnce := false
			for _, reused := range recorder.reused {
				if len(reused) > 0 && reused[0] {
					reusedOnce = true
				}
			}
			if !reusedOnce {
				t.Errorf("the request did not go out on the warm connection: %v", recorder.reused)
			}
		})
	}

	t.Run("the trap, without the client", func(t *testing.T) {
		// The same request made with net/http alone is sent twice; if a Go release stops doing that, there is no trap
		// left to show.
		server, posts := closingServer(t)
		transport := &http.Transport{}
		defer transport.CloseIdleConnections()
		hc := &http.Client{Transport: transport}
		resp, err := hc.Get(server.URL + "/warm")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		req, _ := http.NewRequest("POST", server.URL+"/v1/webhooks", strings.NewReader(`{"url":"https://example.com/hook"}`))
		req.Header.Set("Idempotency-Key", "019a7e00-0000-7000-8000-0000000000cc")
		if _, err := hc.Do(req); err == nil {
			t.Fatal("an answer")
		}
		if posts.Load() != 2 {
			t.Skipf("this Go sent it %d time(s): net/http no longer resends such a request", posts.Load())
		}
	})
}

// scriptedTransport answers each request with the next of its outcomes: an error, or a response.
type scriptedTransport struct {
	mu       sync.Mutex
	outcomes []any
	sent     []*http.Request
}

func (s *scriptedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, req)
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}
	if len(s.outcomes) == 0 {
		return nil, errors.New("more requests than scripted")
	}
	next := s.outcomes[0]
	s.outcomes = s.outcomes[1:]
	if err, ok := next.(error); ok {
		return nil, err
	}
	resp := next.(*http.Response)
	resp.Request = req
	return resp, nil
}

// headerFold is a header's value, whatever the case of its name in the map.
func headerFold(h http.Header, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func created() *http.Response {
	body := `{"id":"019a4f10-2b3c-7d4e-8f5a-6b7c8d9e0f12","url":"https://example.com/hook","events":[],"secret":"` + secret +
		`","created_at":"2026-11-18T10:00:00Z"}`
	return &http.Response{StatusCode: 201, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

func TestAWebhookIsSentAgainOnlyWhenItsConnectionWasNeverMade(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}
	for _, c := range []struct {
		name  string
		first error
		sent  int
	}{
		{"refused", refused, 2},
		{"closed with no answer", io.EOF, 1},
		{"reset", &net.OpError{Op: "read", Net: "tcp", Err: errors.New("connection reset by peer")}, 1},
	} {
		transport := &scriptedTransport{outcomes: []any{c.first, created()}}
		client, err := verifyinboxes.NewClient(verifyinboxes.WithAPIKey(testKey), verifyinboxes.WithHTTPClient(&http.Client{Transport: transport}))
		if err != nil {
			t.Fatal(err)
		}
		verifyinboxes.SetHooks(client, newPaperClock().sleep, nil, nil)
		hook, err := client.Webhooks.Create(context.Background(), &verifyinboxes.WebhookParams{URL: "https://example.com/hook"})
		if len(transport.sent) != c.sent {
			t.Errorf("%s: sent %d times (%v)", c.name, len(transport.sent), err)
		}
		if c.sent == 2 && (err != nil || hook.Secret != secret) {
			t.Errorf("%s: %v", c.name, err)
		}
		if c.sent == 1 && !errors.Is(err, verifyinboxes.ErrConnection) {
			t.Errorf("%s: %v", c.name, err)
		}
		if c.sent == 2 && (headerFold(transport.sent[0].Header, "Idempotency-Key") == "" ||
			headerFold(transport.sent[0].Header, "Idempotency-Key") != headerFold(transport.sent[1].Header, "Idempotency-Key")) {
			t.Errorf("%s: not one key", c.name)
		}
	}
}

func TestEachAttemptHasItsTimeout(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	t.Cleanup(server.Close)
	clock := newPaperClock()
	client, err := verifyinboxes.NewClient(verifyinboxes.WithAPIKey(testKey), verifyinboxes.WithBaseURL(server.URL),
		verifyinboxes.WithTimeout(50*time.Millisecond), verifyinboxes.WithHTTPClient(newHTTPClient(t)))
	if err != nil {
		t.Fatal(err)
	}
	verifyinboxes.SetHooks(client, clock.sleep, clock.clock, nil)
	err = errorOf(t, second(client.Account.Get(context.Background())))
	var connErr *verifyinboxes.ConnectionError
	if !errors.As(err, &connErr) || !connErr.Timeout || !errors.Is(err, verifyinboxes.ErrTimeout) {
		t.Fatalf("%v", err)
	}
	if calls.Load() != 3 || len(clock.sleeps()) != 2 {
		t.Errorf("%d attempts, slept %v", calls.Load(), clock.sleeps())
	}
}

func TestPathSegmentsAreEscapedAndIDsChecked(t *testing.T) {
	api := newFakeAPI(t, []exchange{on("GET", "/v1/domains/a%2Fb%3Fc", answerWith(404, apiError("not_found", "no")))}, fakeOptions{})
	client, _ := clientOf(t, api, nil)
	if _, err := client.Domains.Get(context.Background(), "a/b?c"); !errors.Is(err, verifyinboxes.ErrNotFound) {
		t.Errorf("%v", err)
	}
	if _, unexpected, _, _ := api.seen(); api.count() != 1 || len(unexpected) != 0 {
		t.Errorf("%d requests, %d unexpected", api.count(), len(unexpected))
	}
	for name, err := range map[string]error{
		"checks.get":   second(client.Checks.Get(context.Background(), "")),
		"lists.get":    second(client.Lists.Get(context.Background(), "")),
		"domains.get":  second(client.Domains.Get(context.Background(), "")),
		"webhooks.del": client.Webhooks.Delete(context.Background(), ""),
	} {
		if err == nil {
			t.Errorf("%s: an empty id was taken", name)
		}
	}
}
