package verifyinboxes_test

// A smoke test against the real API, run weekly by .github/workflows/smoke.yml.
//
// Skipped unless VERIFYINBOXES_SMOKE_API_KEY holds a key (it spends a few credits). VERIFYINBOXES_BASE_URL points it
// elsewhere than production.

import (
	"context"
	"os"
	"sort"
	"testing"
	"time"

	verifyinboxes "github.com/verifyinboxes/verifyinboxes-go"
)

func TestSmoke(t *testing.T) {
	key := os.Getenv("VERIFYINBOXES_SMOKE_API_KEY")
	if key == "" {
		t.Skip("VERIFYINBOXES_SMOKE_API_KEY is not set")
	}
	base := originalBaseURL
	if base == "" {
		base = verifyinboxes.DefaultBaseURL
	}
	client, err := verifyinboxes.NewClient(verifyinboxes.WithAPIKey(key), verifyinboxes.WithBaseURL(base))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	account, err := client.Account.Get(ctx)
	if err != nil || account.Name == "" {
		t.Fatalf("account: %+v %v", account, err)
	}

	result, err := client.Verify(ctx, "verify@verifyinboxes.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict == verifyinboxes.VerdictInvalid || result.JobID == "" {
		t.Errorf("verify@verifyinboxes.com: %+v", result)
	}

	addresses := []string{"verify@verifyinboxes.com", "support@verifyinboxes.com"}
	created, err := client.Lists.Create(ctx, &verifyinboxes.CreateListParams{Emails: addresses})
	if err != nil {
		t.Fatal(err)
	}
	job, err := client.Lists.Wait(ctx, created.ID, &verifyinboxes.WaitParams{Timeout: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != verifyinboxes.JobDone {
		t.Fatalf("the list ended %s", job.Status)
	}
	rows, err := client.Lists.Results(ctx, created.ID, nil).Collect()
	if err != nil {
		t.Fatal(err)
	}
	var emails []string
	for _, row := range rows {
		emails = append(emails, row.Email)
	}
	sort.Strings(emails)
	if len(emails) != 2 || emails[0] != addresses[1] || emails[1] != addresses[0] {
		t.Errorf("rows: %v", emails)
	}
}
