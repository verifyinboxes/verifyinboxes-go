package verifyinboxes_test

// The conformance scenarios: what every official VerifyInboxes library must send and do, replayed here against a
// fake API.
//
// testdata/conformance/scenarios.json is shared, byte for byte, by the Python, JavaScript, Go and Java libraries. Each
// scenario names a call (call.op and its args, by the Python library's names, mapped below to this package's
// methods), the exchanges the server expects and answers (in order unless unordered), the seconds the client must
// sleep (sleeps; absent: not checked) and the outcome: returns (compared as a subset, all the way down: an object's
// keys must be there with those values, an array has exactly those elements) or raises (the error's kind, and its
// status, code, request id, retry_after and job_ids when given). A request is checked for its method, path (as
// escaped on the wire), query, body (json, compared so that true, 1 and 1.0 differ, or the ordered multipart parts),
// the headers named, its Idempotency-Key ("new": present and unseen, "same": the one of the exchange listed just
// before it, {"equals": ...}, absent: none) and, always, the bearer credential and the User-Agent. An answer can be
// dropped ("drop": true: the connection closes with no answer) or cut short ("cut_after"). Each scenario runs on a
// clock that moves only when the client sleeps, and on a connection already used once, as a long-lived client's
// requests are.
//
// Each signature vector says whether VerifySignature must accept a webhook signature.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	verifyinboxes "github.com/verifyinboxes/verifyinboxes-go"
)

func readTestdata(name string) ([]byte, error) { return os.ReadFile(filepath.Join("testdata", name)) }

var visibleASCII = regexp.MustCompile(`^[!-~]{1,255}$`)

// ---- running a call ------------------------------------------------------------------------------------------------

// args reads a scenario's arguments, by the Python library's names.
type args map[string]any

func (a args) str(name string) string {
	s, _ := a[name].(string)
	return s
}

func (a args) flag(name string) bool {
	b, _ := a[name].(bool)
	return b
}

func (a args) strings(name string) []string {
	list, ok := a[name].([]any)
	if !ok {
		return nil
	}
	out := make([]string, len(list))
	for i, v := range list {
		out[i], _ = v.(string)
	}
	return out
}

func (a args) int(name string) int {
	n, _ := a[name].(json.Number)
	i, _ := n.Int64()
	return int(i)
}

// seconds is a duration of the scenario file (seconds) as this package takes it; 0 when not given (the default).
func (a args) seconds(name string) time.Duration {
	n, ok := a[name].(json.Number)
	if !ok {
		return 0
	}
	f, _ := n.Float64()
	return time.Duration(f * float64(time.Second))
}

// run calls op with the scenario's arguments under this package's names, and answers what the wire would name.
func run(ctx context.Context, c *verifyinboxes.Client, op string, a args, dir string) (any, error) {
	switch op {
	case "account.get":
		return wire(c.Account.Get(ctx))
	case "verify":
		p := &verifyinboxes.VerifyParams{
			ForceRecheck: a.flag("force_recheck"), Timeout: a.seconds("timeout"), IdempotencyKey: a.str("idempotency_key"),
		}
		if wait, ok := a["wait"].(bool); ok && !wait {
			check, err := c.Checks.Start(ctx, a.str("email"), p)
			if err != nil {
				return nil, err
			}
			if check.Pending {
				return wire(map[string]any{"status": "pending", "job_id": check.JobID}, nil)
			}
			return wire(check.Result, nil)
		}
		return wire(c.Verify(ctx, a.str("email"), p))
	case "checks.get":
		return wire(c.Checks.Get(ctx, a.str("job_id")))
	case "checks.wait":
		return wire(c.Checks.Wait(ctx, a.str("job_id"), &verifyinboxes.WaitParams{Timeout: a.seconds("timeout")}))
	case "verify_many":
		return wire(c.VerifyMany(ctx, a.strings("emails"), &verifyinboxes.VerifyManyParams{Timeout: a.seconds("timeout")}))
	case "lists.create":
		return wire(c.Lists.Create(ctx, &verifyinboxes.CreateListParams{
			Emails: a.strings("emails"), CSV: a.str("csv"), EmailColumn: a.str("email_column"),
			Filename: a.str("filename"), IdempotencyKey: a.str("idempotency_key"),
		}))
	case "lists.get":
		return wire(c.Lists.Get(ctx, a.str("id")))
	case "lists.wait":
		return wire(c.Lists.Wait(ctx, a.str("id"), &verifyinboxes.WaitParams{Timeout: a.seconds("timeout")}))
	case "lists.results":
		rows := c.Lists.Results(ctx, a.str("id"), &verifyinboxes.ResultsParams{
			PageSize: a.int("page_size"), OnlySafeToSend: a.flag("only_safe_to_send"), Verdicts: a.strings("verdicts"),
			Partial: a.flag("partial"),
		})
		emails := []string{}
		for rows.Next() {
			emails = append(emails, rows.Current().Email)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return wire(map[string]any{"rows": emails}, nil)
	case "lists.download":
		path := filepath.Join(dir, "results.csv")
		if err := os.WriteFile(path, []byte(a.str("before")), 0o600); err != nil {
			return nil, err
		}
		if _, err := c.Lists.DownloadFile(ctx, a.str("id"), path, &verifyinboxes.DownloadParams{
			OnlySafeToSend: a.flag("only_safe_to_send"), Verdicts: a.strings("verdicts"), Partial: a.flag("partial"),
		}); err != nil {
			return nil, err
		}
		text, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return wire(map[string]any{"file": string(text)}, nil)
	case "lists.resolve":
		return wire(c.Lists.Resolve(ctx, a.str("id"), &verifyinboxes.ResolveParams{
			Emails: a.strings("emails"), IdempotencyKey: a.str("idempotency_key"),
		}))
	case "domains.get":
		return wire(c.Domains.Get(ctx, a.str("domain")))
	case "suppressions.list":
		return wire(c.Suppressions.List(ctx))
	case "suppressions.add":
		return wire(c.Suppressions.Add(ctx, &verifyinboxes.SuppressionParams{Emails: a.strings("emails"), Domains: a.strings("domains")}))
	case "suppressions.remove":
		return wire(c.Suppressions.Remove(ctx, &verifyinboxes.SuppressionParams{Emails: a.strings("emails"), Domains: a.strings("domains")}))
	case "webhooks.create":
		return wire(c.Webhooks.Create(ctx, &verifyinboxes.WebhookParams{URL: a.str("url"), Events: a.strings("events")}))
	case "webhooks.list":
		return wire(c.Webhooks.List(ctx))
	case "webhooks.delete":
		return nil, c.Webhooks.Delete(ctx, a.str("id"))
	case "notices.list":
		return wire(c.Notices.List(ctx, &verifyinboxes.NoticesParams{After: a.str("after"), Limit: a.int("limit")}))
	case "feedback.report":
		var events []verifyinboxes.FeedbackEvent
		data, _ := json.Marshal(a["events"])
		if err := json.Unmarshal(data, &events); err != nil {
			return nil, err
		}
		return wire(c.Feedback.Report(ctx, events, &verifyinboxes.FeedbackParams{IdempotencyKey: a.str("idempotency_key")}))
	case "integrations.create":
		return wire(c.Integrations.Create(ctx, &verifyinboxes.IntegrationParams{
			Provider: a.str("provider"), Label: a.str("label"), SigningSecret: a.str("signing_secret"),
		}))
	case "integrations.list":
		return wire(c.Integrations.List(ctx))
	case "integrations.delete":
		return nil, c.Integrations.Delete(ctx, a.str("id"))
	}
	return nil, fmt.Errorf("no such op in this runner: %s", op)
}

// ---- checking what happened ----------------------------------------------------------------------------------------

// subset reports where got (what the call returned) does not hold want, all the way down; "" when it does.
func subset(got, want any, where string) string {
	switch w := want.(type) {
	case json.Number:
		g, ok := got.(json.Number)
		if !ok || !sameNumber(g, w) {
			return fmt.Sprintf("%s: %v, not %v", where, got, w)
		}
		if whole(w) && !whole(g) {
			return fmt.Sprintf("%s: %v is not whole", where, g)
		}
	case []any:
		g, ok := got.([]any)
		if !ok {
			return fmt.Sprintf("%s: %v is not an array", where, got)
		}
		if len(g) != len(w) {
			return fmt.Sprintf("%s: %d elements, not %d", where, len(g), len(w))
		}
		for i := range w {
			if problem := subset(g[i], w[i], fmt.Sprintf("%s[%d]", where, i)); problem != "" {
				return problem
			}
		}
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Sprintf("%s: %v is not an object", where, got)
		}
		for k, v := range w {
			gv, ok := g[k]
			if !ok {
				return fmt.Sprintf("%s: no %s", where, k)
			}
			if problem := subset(gv, v, where+"."+k); problem != "" {
				return problem
			}
		}
	default:
		// nil is a call that returns nothing.
		if got != want {
			return fmt.Sprintf("%s: %#v, not %#v", where, got, want)
		}
	}
	return ""
}

func checkRequests(t *testing.T, sc *scenario, credential string, api *fakeAPI) {
	t.Helper()
	matched, unexpected, _, _ := api.seen()
	for _, r := range unexpected {
		t.Errorf("a request the scenario does not have: %s %s?%s %.200s", r.Method, r.Path, r.RawQuery, r.Body)
	}
	var keys []string
	for i := range sc.Exchanges {
		want := &sc.Exchanges[i].Request
		where := fmt.Sprintf("exchange %d (%s %s)", i, want.Method, want.Path)
		got := matched[i]
		if got == nil {
			t.Errorf("%s was never requested", where)
			keys = append(keys, "")
			continue
		}
		if got.Method != want.Method || got.Path != want.Path {
			t.Errorf("%s: got %s %s", where, got.Method, got.Path)
		}
		if want.Query != nil {
			query, err := parseQuery(got.RawQuery)
			if err != nil {
				t.Errorf("%s: query %q: %v", where, got.RawQuery, err)
			} else if fmt.Sprint(query) != fmt.Sprint(want.Query) {
				t.Errorf("%s: query %v, not %v", where, query, want.Query)
			}
		} else if got.RawQuery != "" {
			t.Errorf("%s: a query %q", where, got.RawQuery)
		}
		switch {
		case want.JSON != nil:
			w, err := decodeStrict(want.JSON)
			if err != nil {
				t.Fatal(err)
			}
			if got.JSON == nil || !strictEqual(got.JSON, w) {
				t.Errorf("%s: body %.500s, not %s", where, got.Body, want.JSON)
			}
		case want.Multipart != nil:
			gotParts, _ := json.Marshal(got.Multipart)
			wantParts, _ := json.Marshal(want.Multipart)
			if string(gotParts) != string(wantParts) {
				t.Errorf("%s: parts %s, not %s", where, gotParts, wantParts)
			}
		case len(got.Body) != 0:
			t.Errorf("%s: a body %.200q", where, got.Body)
		}
		for name, value := range want.Headers {
			if got.Header.Get(name) != value {
				t.Errorf("%s: %s %q, not %q", where, name, got.Header.Get(name), value)
			}
		}
		if auth := got.Header.Get("Authorization"); auth != "Bearer "+credential {
			t.Errorf("%s: the credential sent is not the client's", where)
		}
		if ua := got.Header.Get("User-Agent"); !strings.HasPrefix(ua, "verifyinboxes-go/"+verifyinboxes.Version) {
			t.Errorf("%s: User-Agent %q", where, ua)
		}
		key, sent := got.idempotencyKey()
		switch rule := strings.TrimSpace(string(want.IdempotencyKey)); {
		case rule == "":
			if sent {
				t.Errorf("%s: an Idempotency-Key %q", where, key)
			}
		case rule == `"new"`:
			if !sent || !visibleASCII.MatchString(key) {
				t.Errorf("%s: Idempotency-Key %q", where, key)
			}
			for _, earlier := range keys {
				if sent && key == earlier {
					t.Errorf("%s: an Idempotency-Key used earlier", where)
				}
			}
		case rule == `"same"`:
			if i == 0 || !sent || key != keys[i-1] {
				t.Errorf("%s: not the same Idempotency-Key as the exchange before", where)
			}
		default:
			var equals struct {
				Equals string `json:"equals"`
			}
			if err := json.Unmarshal(want.IdempotencyKey, &equals); err != nil {
				t.Fatal(err)
			}
			if key != equals.Equals {
				t.Errorf("%s: Idempotency-Key %q, not %q", where, key, equals.Equals)
			}
		}
		keys = append(keys, key)
	}
}

// parseQuery is a query as an exact map: each name once.
func parseQuery(raw string) (map[string]string, error) {
	out := map[string]string{}
	if raw == "" {
		return out, nil
	}
	for _, pair := range strings.Split(raw, "&") {
		name, value, _ := strings.Cut(pair, "=")
		n, err := url.QueryUnescape(name)
		if err != nil {
			return nil, err
		}
		v, err := url.QueryUnescape(value)
		if err != nil {
			return nil, err
		}
		if _, twice := out[n]; twice {
			return nil, fmt.Errorf("%s more than once", n)
		}
		out[n] = v
	}
	return out, nil
}

func checkSleeps(t *testing.T, sc *scenario, clock *paperClock) {
	t.Helper()
	if sc.Sleeps == nil {
		return
	}
	var want []json.RawMessage
	if err := json.Unmarshal(sc.Sleeps, &want); err != nil {
		t.Fatal(err)
	}
	slept := clock.sleeps()
	if len(slept) != len(want) {
		t.Fatalf("slept %v, not %s", slept, sc.Sleeps)
	}
	for i, w := range want {
		got := slept[i].Seconds()
		var exact float64
		if json.Unmarshal(w, &exact) == nil {
			if math.Abs(got-exact) > 1e-6 {
				t.Errorf("sleep %d: %vs, not %vs", i, got, exact)
			}
			continue
		}
		var span struct{ Min, Max float64 }
		if err := json.Unmarshal(w, &span); err != nil {
			t.Fatal(err)
		}
		if got < span.Min-1e-9 || got > span.Max+1e-9 {
			t.Errorf("sleep %d: %vs, not in [%v, %v]", i, got, span.Min, span.Max)
		}
	}
}

// apiKinds are the error kinds an answer of the API has, and the sentinel each matches.
var apiKinds = map[string]error{
	"invalid_request":      verifyinboxes.ErrInvalidRequest,
	"authentication":       verifyinboxes.ErrAuthentication,
	"insufficient_credits": verifyinboxes.ErrInsufficientCredits,
	"permission":           verifyinboxes.ErrPermissionDenied,
	"not_found":            verifyinboxes.ErrNotFound,
	"conflict":             verifyinboxes.ErrConflict,
	"rate_limit":           verifyinboxes.ErrRateLimited,
	"server":               verifyinboxes.ErrServer,
}

// checkKind fails unless err is of exactly the kind named: its sentinel, and no other kind's.
func checkKind(t *testing.T, kind string, err error) {
	t.Helper()
	var apiErr *verifyinboxes.APIError
	var connErr *verifyinboxes.ConnectionError
	var waitErr *verifyinboxes.WaitTimeoutError
	isAPI, isConn, isWait := errors.As(err, &apiErr), errors.As(err, &connErr), errors.As(err, &waitErr)
	matched := []string{}
	for name, sentinel := range apiKinds {
		if errors.Is(err, sentinel) {
			matched = append(matched, name)
		}
	}
	ok := false
	switch kind {
	case "api":
		ok = isAPI && len(matched) == 0
	case "connection":
		ok = isConn && !connErr.Timeout && errors.Is(err, verifyinboxes.ErrConnection) &&
			!errors.Is(err, verifyinboxes.ErrTimeout) && !isAPI
	case "timeout":
		ok = isConn && connErr.Timeout && errors.Is(err, verifyinboxes.ErrTimeout) && errors.Is(err, verifyinboxes.ErrConnection)
	case "wait_timeout":
		ok = isWait && errors.Is(err, verifyinboxes.ErrWaitTimeout) && !isAPI && !isConn
	case "missing_api_key":
		ok = errors.Is(err, verifyinboxes.ErrMissingAPIKey)
	case "sdk":
		ok = errors.Is(err, verifyinboxes.ErrUnexpectedAnswer) && !isAPI && !isConn && !isWait
	default:
		sentinel, known := apiKinds[kind]
		if !known {
			t.Fatalf("no such kind: %s", kind)
		}
		ok = isAPI && errors.Is(err, sentinel) && len(matched) == 1
	}
	if !ok {
		t.Fatalf("returned %T %q, not of the kind %s (matches %v)", err, err, kind, matched)
	}
}

func checkRaised(t *testing.T, want *raises, err error) {
	t.Helper()
	checkKind(t, want.Kind, err)
	var apiErr *verifyinboxes.APIError
	isAPI := errors.As(err, &apiErr)
	if want.Status != nil && (!isAPI || apiErr.StatusCode != *want.Status) {
		t.Errorf("status: %v, not %d", err, *want.Status)
	}
	if want.Code != nil {
		var code *string
		if err := json.Unmarshal(want.Code, &code); err != nil {
			t.Fatal(err)
		}
		wantCode := ""
		if code != nil {
			wantCode = *code
		}
		if !isAPI || apiErr.Code != wantCode {
			t.Errorf("code: %v, not %q", err, wantCode)
		}
	}
	if want.RequestID != nil && (!isAPI || apiErr.RequestID != *want.RequestID) {
		t.Errorf("request id: %v, not %s", err, *want.RequestID)
	}
	if want.RetryAfter != nil && (!isAPI || apiErr.RetryAfter != time.Duration(*want.RetryAfter*float64(time.Second))) {
		t.Errorf("retry after: %v, not %vs", err, *want.RetryAfter)
	}
	if want.JobIDs != nil {
		if got := verifyinboxes.JobIDs(err); fmt.Sprint(got) != fmt.Sprint(want.JobIDs) {
			t.Errorf("job ids: %v, not %v", got, want.JobIDs)
		}
		var waitErr *verifyinboxes.WaitTimeoutError
		if errors.As(err, &waitErr) && fmt.Sprint(waitErr.JobIDs) != fmt.Sprint(want.JobIDs) {
			t.Errorf("WaitTimeoutError.JobIDs: %v, not %v", waitErr.JobIDs, want.JobIDs)
		}
		if isAPI && fmt.Sprint(apiErr.JobIDs) != fmt.Sprint(want.JobIDs) {
			t.Errorf("APIError.JobIDs: %v, not %v", apiErr.JobIDs, want.JobIDs)
		}
	}
	if want.MessageHasRequestID && !strings.HasSuffix(err.Error(), fmt.Sprintf("(request id %s)", *want.RequestID)) {
		t.Errorf("the message does not end with its request id: %q", err.Error())
	}
}

func checkFile(t *testing.T, sc *scenario, dir string) {
	t.Helper()
	if sc.Outcome.File != "unchanged" {
		return
	}
	text, err := os.ReadFile(filepath.Join(dir, "results.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != args(sc.Call.Args).str("before") {
		t.Errorf("the file was changed: %q", text)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("a part file was left behind: %v", names)
	}
}

// ---- the tests -----------------------------------------------------------------------------------------------------

func TestConformance(t *testing.T) {
	file := readScenarios(t)
	if len(file.Scenarios) < 50 || len(file.Signatures) < 20 {
		t.Fatalf("only %d scenarios and %d vectors", len(file.Scenarios), len(file.Signatures))
	}
	seen := map[string]bool{}
	for i := range file.Scenarios {
		sc := &file.Scenarios[i]
		if seen[sc.Name] {
			t.Fatalf("two scenarios named %s", sc.Name)
		}
		seen[sc.Name] = true
		t.Run(sc.Name, func(t *testing.T) {
			api := newFakeAPI(t, sc.Exchanges, fakeOptions{unordered: sc.Unordered})
			clock := newPaperClock()
			credential := file.APIKey
			if sc.Client.APIKey != "" {
				credential = sc.Client.APIKey
			}
			opts := []verifyinboxes.Option{verifyinboxes.WithAPIKey(credential)}
			if sc.Client.MaxRetries != nil {
				opts = append(opts, verifyinboxes.WithMaxRetries(*sc.Client.MaxRetries))
			}
			client, hc := clientOf(t, api, clock, opts...)
			warm(t, hc, api)
			dir := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			got, err := run(ctx, client, sc.Call.Op, args(sc.Call.Args), dir)
			if sc.Outcome.Raises != nil {
				if err == nil {
					t.Fatalf("it returned %v, and no error", got)
				}
				checkRaised(t, sc.Outcome.Raises, err)
				checkFile(t, sc, dir)
			} else {
				if err != nil {
					t.Fatalf("it returned the error %v", err)
				}
				if sc.Outcome.Returns == nil {
					t.Fatal("the scenario has no outcome")
				}
				want, err := decodeStrict(sc.Outcome.Returns)
				if err != nil {
					t.Fatal(err)
				}
				if problem := subset(got, want, "returns"); problem != "" {
					t.Error(problem)
				}
			}
			checkRequests(t, sc, credential, api)
			checkSleeps(t, sc, clock)
		})
	}
}

func TestSignatureVectors(t *testing.T) {
	for _, v := range readScenarios(t).Signatures {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			err := verifyinboxes.VerifySignature([]byte(v.Body), v.Header, v.Secret,
				verifyinboxes.WithTolerance(time.Duration(v.Tolerance)*time.Second), verifyinboxes.WithNow(time.Unix(v.Now, 0)))
			if v.Valid && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !v.Valid && !errors.Is(err, verifyinboxes.ErrInvalidSignature) {
				t.Fatalf("returned %v, not ErrInvalidSignature", err)
			}
		})
	}
}

func TestStrictJSON(t *testing.T) {
	read := func(s string) any {
		v, err := decodeStrict([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if !strictEqual(read(`{"a":[1,{"b":"x"}],"c":null}`), read(`{"a": [1, {"b": "x"}], "c": null}`)) {
		t.Error("the same JSON, spaced differently, is not equal")
	}
	for _, pair := range [][2]string{
		{`1`, `true`}, {`true`, `1`}, {`1`, `1.0`}, {`0`, `false`}, {`{"a":[1]}`, `{"a":[true]}`}, {`[1.0]`, `[1]`},
		{`{"a":1}`, `{"a":1,"b":2}`}, {`"1"`, `1`},
	} {
		if strictEqual(read(pair[0]), read(pair[1])) {
			t.Errorf("%s equals %s", pair[0], pair[1])
		}
	}
	if !strictEqual(read(`1.0`), read(`1.00`)) {
		t.Error("1.0 is not 1.00")
	}
	if subset(read(`1.5`), read(`1`), "x") == "" || subset(read(`2`), read(`2`), "x") != "" {
		t.Error("subset compares numbers wrongly")
	}
}
