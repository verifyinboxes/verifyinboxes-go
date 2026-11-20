package verifyinboxes_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	verifyinboxes "github.com/verifyinboxes/verifyinboxes-go"
)

// originalBaseURL is VERIFYINBOXES_BASE_URL as the tests were started with (the smoke test's address).
var originalBaseURL string

// TestMain points VERIFYINBOXES_API_KEY and VERIFYINBOXES_BASE_URL at a small demo of the API on 127.0.0.1, so that
// the examples run as they are written, from the environment, and their output is checked.
func TestMain(m *testing.M) {
	originalBaseURL = os.Getenv(verifyinboxes.EnvBaseURL)
	demo := httptest.NewServer(demoAPI())
	_ = os.Setenv(verifyinboxes.EnvAPIKey, testKey)
	_ = os.Setenv(verifyinboxes.EnvBaseURL, demo.URL)
	code := m.Run()
	demo.Close()
	os.Exit(code)
}

// demoAPI answers the examples' requests.
func demoAPI() http.Handler {
	results := map[string]map[string]any{
		"ann@example.com":   withJob(resultJSON("ann@example.com", "invalid"), singleJobID(1)),
		"bob@example.com":   withJob(resultJSON("bob@example.com", "valid"), singleJobID(2)),
		"carol@example.com": withJob(resultJSON("carol@example.com", "catch_all"), singleJobID(3)),
	}
	results["bob@example.com"]["reason"], results["bob@example.com"]["safe_to_send"] = "mailbox_exists", true
	results["carol@example.com"]["reason"], results["carol@example.com"]["score"] = "accept_all", 0.91
	answer := func(w http.ResponseWriter, status int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "019a7e00-0000-7000-8000-0000000000dd")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/verify":
			var req struct{ Email string }
			_ = json.NewDecoder(r.Body).Decode(&req)
			if result, ok := results[req.Email]; ok {
				answer(w, 200, result)
			} else {
				answer(w, 402, apiError("insufficient_credits", "the balance does not cover this check"))
			}
		case r.Method == "GET" && r.URL.Path == "/v1/jobs/"+jobID+"/results":
			var rows []map[string]any
			next := any("c1")
			emails := []string{"ann@example.com", "bob@example.com"}
			if r.URL.Query().Get("cursor") == "c1" {
				emails, next = []string{"carol@example.com"}, nil
			}
			for _, email := range emails {
				row := map[string]any{}
				for k, v := range results[email] {
					if k != "job_id" {
						row[k] = v
					}
				}
				row["row"] = len(rows) + 1
				if next == nil {
					row["row"] = 3
				}
				rows = append(rows, row)
			}
			answer(w, 200, map[string]any{"data": rows, "next_cursor": next, "complete": true})
		default:
			answer(w, 404, apiError("not_found", "no such thing"))
		}
	})
}

// Check one address.
func ExampleClient_Verify() {
	client, err := verifyinboxes.NewClient() // reads VERIFYINBOXES_API_KEY
	if err != nil {
		log.Fatal(err)
	}
	result, err := client.Verify(context.Background(), "ann@example.com", nil)
	if err != nil {
		log.Fatal(err) // its message ends with the request id of the API's answer
	}
	fmt.Println(result.Email, result.Verdict, result.Reason, "safe to send:", result.SafeToSend)
	// Output:
	// ann@example.com invalid mailbox_not_found safe to send: false
}

// Check several addresses: up to 10 one by one, together; more as one list. Never a loop of Verify.
func ExampleClient_VerifyMany() {
	client, err := verifyinboxes.NewClient()
	if err != nil {
		log.Fatal(err)
	}
	addresses := []string{"ann@example.com", "bob@example.com", "carol@example.com"}
	results, err := client.VerifyMany(context.Background(), addresses, nil)
	var stillRunning *verifyinboxes.WaitTimeoutError
	if errors.As(err, &stillRunning) {
		// The checks carry on and their credits are held: wait for them again by their ids.
		log.Fatalf("still running: %v", stillRunning.JobIDs)
	} else if err != nil {
		log.Fatal(err)
	}
	for _, result := range results {
		fmt.Println(result.Email, result.Verdict, result.SafeToSend)
	}
	// Output:
	// ann@example.com invalid false
	// bob@example.com valid true
	// carol@example.com catch_all false
}

// Read every row of a finished list, a page at a time as you go.
func ExampleListService_Results() {
	client, err := verifyinboxes.NewClient()
	if err != nil {
		log.Fatal(err)
	}
	rows := client.Lists.Results(context.Background(), "019a3b71-3c4d-7e5f-8a6b-7c8d9e0f1a2b", nil)
	for rows.Next() {
		row := rows.Current()
		fmt.Println(row.Row, row.Email, row.Verdict)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	// Output:
	// 1 ann@example.com invalid
	// 2 bob@example.com valid
	// 3 carol@example.com catch_all
}

// Tell an answer of the API apart by its kind, and quote its request id to support.
func ExampleAPIError() {
	client, err := verifyinboxes.NewClient()
	if err != nil {
		log.Fatal(err)
	}
	_, err = client.Verify(context.Background(), "zoe@example.com", nil)
	var apiErr *verifyinboxes.APIError
	switch {
	case errors.Is(err, verifyinboxes.ErrInsufficientCredits) && errors.As(err, &apiErr):
		fmt.Println("top up first; request", apiErr.RequestID)
		fmt.Println(err)
	case err != nil:
		log.Fatal(err)
	}
	// Output:
	// top up first; request 019a7e00-0000-7000-8000-0000000000dd
	// 402 insufficient_credits: the balance does not cover this check (request id 019a7e00-0000-7000-8000-0000000000dd)
}

// Check a webhook delivery's signature before reading anything in it.
func ExampleVerifySignature() {
	secret := "6f1d0c9e8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e" // what Webhooks.Create returned
	body := []byte(`{"event":"job.completed","job_id":"019a3b71-3c4d-7e5f-8a6b-7c8d9e0f1a2b","status":"done"}`)
	header := "t=1762858800,v1=2ba51d9d7bfe4f09919b8ea9495e90101d81bbde57ab35f2f894704b2933edd7"
	at := verifyinboxes.WithNow(time.Unix(1762858800, 0)) // leave it out to compare with your clock

	fmt.Println(verifyinboxes.VerifySignature(body, header, secret, at))
	changed := []byte(strings.Replace(string(body), "done", "failed", 1))
	err := verifyinboxes.VerifySignature(changed, header, secret, at)
	fmt.Println(errors.Is(err, verifyinboxes.ErrInvalidSignature))
	// Output:
	// <nil>
	// true
}

// A receiver on the standard library's HTTP server.
func ExampleVerifySignature_handler() {
	secret := os.Getenv("VERIFYINBOXES_WEBHOOK_SECRET")
	http.HandleFunc("/webhooks/verifyinboxes", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, "unreadable", http.StatusBadRequest)
			return
		}
		if err := verifyinboxes.VerifySignature(body, r.Header.Get(verifyinboxes.SignatureHeader), secret); err != nil {
			http.Error(w, "bad signature", http.StatusBadRequest) // not from VerifyInboxes, changed, or too old
			return
		}
		var event struct {
			Event string `json:"event"`
			JobID string `json:"job_id"`
		}
		_ = json.Unmarshal(body, &event)
		log.Println(event.Event, event.JobID)
		w.WriteHeader(http.StatusNoContent)
	})
}

// Pick up a check that outlived its wait.
func ExampleCheckService_Wait() {
	client, err := verifyinboxes.NewClient()
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	result, err := client.Verify(ctx, "ann@example.com", &verifyinboxes.VerifyParams{Timeout: 10 * time.Second})
	var stillRunning *verifyinboxes.WaitTimeoutError
	if errors.As(err, &stillRunning) {
		// The check carries on: later, wait for it again by its job.
		result, err = client.Checks.Wait(ctx, stillRunning.JobIDs[0], &verifyinboxes.WaitParams{Timeout: 2 * time.Minute})
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result.Verdict)
}

// A list from a CSV: start it, wait for it, and download the CSV with the results appended.
func ExampleListService_CreateFromFile() {
	client, err := verifyinboxes.NewClient()
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	created, err := client.Lists.CreateFromFile(ctx, "prospects.csv", &verifyinboxes.CreateListParams{EmailColumn: "email"})
	if err != nil {
		log.Fatal(err)
	}
	// A few hundred addresses take minutes, Microsoft-hosted ones longer.
	job, err := client.Lists.Wait(ctx, created.ID, nil)
	if err != nil {
		log.Fatal(err) // the list carries on: verifyinboxes.JobIDs(err) names it
	}
	fmt.Println(job.Status, job.Total, "addresses")
	if _, err := client.Lists.DownloadFile(ctx, created.ID, "results.csv", nil); err != nil {
		log.Fatal(err)
	}
}
