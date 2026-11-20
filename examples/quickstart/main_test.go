package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// TestQuickstart runs the example against a stand-in for the API: what it prints is what a reader copies.
func TestQuickstart(t *testing.T) {
	const requestID = "019a7e00-0000-7000-8000-0000000000aa"
	jobs := map[string]string{
		"ann@example.com": "019a3b6e-8f0c-7d2e-9a41-5c3e2f1b0b01",
		"bob@example.com": "019a3b6e-8f0c-7d2e-9a41-5c3e2f1b0b02",
	}
	var mu sync.Mutex
	var asked []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Email string `json:"email"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		asked = append(asked, body.Email)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", requestID)
		job, ok := jobs[body.Email]
		if r.Method != http.MethodPost || r.URL.Path != "/v1/verify" || !ok {
			w.WriteHeader(http.StatusPaymentRequired)
			fmt.Fprint(w, `{"error":{"code":"insufficient_credits","message":"the balance is 0"}}`)
			return
		}
		fmt.Fprintf(w, `{"email":%q,"verdict":"invalid","score":null,"safe_to_send":false,"flags":[],"provider":"google",`+
			`"catch_all_domain":false,"verified_at":"2026-11-18T10:12:00.123Z","source":"smtp",`+
			`"reason":"mailbox_not_found","job_id":%q}`, body.Email, job)
	}))
	defer api.Close()
	t.Setenv("VERIFYINBOXES_API_KEY", "bv_testtesttesttesttesttesttesttest")
	t.Setenv("VERIFYINBOXES_BASE_URL", api.URL)

	var code int
	stdout, stderr := captured(t, func() { code = run([]string{"ann@example.com", "bob@example.com", "cat@example.com"}) })

	if code != 1 {
		t.Errorf("exit %d", code)
	}
	// ann is checked once (by Verify), not again by VerifyMany.
	mu.Lock()
	n := strings.Count(strings.Join(asked, " "), "ann@example.com")
	mu.Unlock()
	if n != 1 || len(asked) != 3 {
		t.Errorf("the API was asked for %v", asked)
	}
	if !strings.HasPrefix(stdout, "ann@example.com: invalid") {
		t.Errorf("stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "402 insufficient_credits: the balance is 0 (request id "+requestID+")") {
		t.Errorf("stderr does not say what the API said: %q", stderr)
	}
	// bob's check carries on, its credit held: the error names it.
	if !strings.Contains(stderr, "jobs made: "+jobs["bob@example.com"]) {
		t.Errorf("stderr does not name the job made: %q", stderr)
	}
}

// captured runs f with the standard output and error going to pipes, and returns what was written to each.
func captured(t *testing.T, f func()) (stdout, stderr string) {
	t.Helper()
	read := func(target **os.File) (func() string, func()) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		saved := *target
		*target = w
		done := make(chan string)
		go func() {
			data, _ := io.ReadAll(r)
			done <- string(data)
		}()
		return func() string { _ = w.Close(); return <-done }, func() { *target = saved }
	}
	out, restoreOut := read(&os.Stdout)
	errs, restoreErr := read(&os.Stderr)
	defer restoreOut()
	defer restoreErr()
	f()
	return out(), errs()
}
