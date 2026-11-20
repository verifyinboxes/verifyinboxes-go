# VerifyInboxes Go library

[![Go Reference](https://pkg.go.dev/badge/github.com/verifyinboxes/verifyinboxes-go.svg)](https://pkg.go.dev/github.com/verifyinboxes/verifyinboxes-go)
[![CI](https://github.com/verifyinboxes/verifyinboxes-go/actions/workflows/ci.yml/badge.svg)](https://github.com/verifyinboxes/verifyinboxes-go/actions/workflows/ci.yml)

The official Go library for the [VerifyInboxes](https://verifyinboxes.com) API: check whether email addresses can
receive mail, one at a time or as lists of any size, and read the results.

- Retries that never charge twice, waiting for checks and lists, results read page by page
- Every call takes a `context.Context`; a cancelled `Verify` or `VerifyMany` names every job it made
- Errors you can match with `errors.Is` and `errors.As`, each naming the request it came from
- Webhook signature checks
- The standard library only: no dependencies. Go 1.22 or later

## Install

Not published yet: until the first release is tagged, `go get` cannot find it. Clone the repository and point your
module at your copy:

```bash
git clone https://github.com/verifyinboxes/verifyinboxes-go
cd your-module
go mod edit -require github.com/verifyinboxes/verifyinboxes-go@v0.1.0 \
  -replace github.com/verifyinboxes/verifyinboxes-go=/path/to/verifyinboxes-go
```

Once released:

```bash
go get github.com/verifyinboxes/verifyinboxes-go
```

The package is imported as `verifyinboxes`:

```go
import verifyinboxes "github.com/verifyinboxes/verifyinboxes-go"
```

## Quickstart

An organisation admin makes an API key in the VerifyInboxes app under **Developers** → **API keys**. Put it in the
environment:

```bash
export VERIFYINBOXES_API_KEY="bv_..."
```

```go
package main

import (
	"context"
	"fmt"
	"log"

	verifyinboxes "github.com/verifyinboxes/verifyinboxes-go"
)

func main() {
	client, err := verifyinboxes.NewClient() // reads VERIFYINBOXES_API_KEY
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	result, err := client.Verify(ctx, "ann@example.com", nil)
	if err != nil {
		log.Fatal(err) // its message ends with the request id of the API's answer
	}
	fmt.Println(result.Verdict)    // valid, invalid, catch_all, risky or unknown
	fmt.Println(result.SafeToSend) // true or false
	fmt.Println(result.Reason)     // why, e.g. mailbox_not_found
	fmt.Println(result.JobID)      // the check's job

	results, err := client.VerifyMany(ctx, []string{"bob@example.com", "cat@example.com"}, nil)
	if err != nil {
		log.Fatal(err)
	}
	for _, each := range results {
		fmt.Println(each.Email, each.Verdict)
	}
}
```

## The client

```go
client, err := verifyinboxes.NewClient(
	verifyinboxes.WithAPIKey("bv_..."),                         // default: the VERIFYINBOXES_API_KEY environment variable
	verifyinboxes.WithBaseURL("https://api.verifyinboxes.com"), // default: VERIFYINBOXES_BASE_URL, else this
	verifyinboxes.WithTimeout(60*time.Second),                  // one attempt of one request
	verifyinboxes.WithMaxRetries(2),                            // see "Retries"
	verifyinboxes.WithHTTPClient(&http.Client{}),               // its transport, proxy and TLS settings
	verifyinboxes.WithUserAgent("my-app/1.2"),                  // put in front of verifyinboxes-go/<version>
)
```

Without a key, `NewClient` returns `verifyinboxes.ErrMissingAPIKey`. A key with a space or a control character in
it, or one that is not ASCII (half of a copy and paste), is refused there too, and the error never repeats it. Keep
the key out of your code: the environment variable is the place for it. The client never logs it, and printing the
client with the `fmt` package shows only its first 6 characters. Make one client and share it: it is safe for use by
several goroutines at once, and keeps its connections open between calls.

Every method takes a `context.Context` first and, where it has options, a pointer to its params last: `nil` is the
defaults. Every duration is a `time.Duration`.

### Personal access tokens

Where an API key works, so does a personal access token (`vi_at_...`): what an app gets when a person signs in to it
with their VerifyInboxes account. It acts as that person, with their role in the organisation they chose, and lives
an hour; after that the API answers `401` (`ErrAuthentication`). Pass it as the key, or give a `TokenSource`, asked
before every request, for one that changes:

```go
type tokens struct{ /* your sign-in state */ }

func (t *tokens) Token(ctx context.Context) (string, error) { /* the current access token */ }
func (t *tokens) Refresh(ctx context.Context) error         { /* use the refresh token */ }

client, err := verifyinboxes.NewClient(verifyinboxes.WithTokenSource(&tokens{}))
```

A `TokenSource` that is also a `Refresher` is refreshed once when the API answers `401` with
`WWW-Authenticate: Bearer error="invalid_token"`, and the request is sent again with the new token and the same
`Idempotency-Key`; a second `401` is returned. `Token` is called from several goroutines at once, so make it safe for
that; `Refresh` is called from one at a time, and only while `Token` still gives the refused token: requests refused
together (the checks of a `VerifyMany`) renew it once. An upload from an `io.Reader` that cannot seek is not sent
again after a refresh (its file would go empty): its `401` is returned, and the next call has the new token.

## Checking addresses

### One address

```go
result, err := client.Verify(ctx, "ann@example.com", nil)
fresh, err := client.Verify(ctx, "ann@example.com", &verifyinboxes.VerifyParams{ForceRecheck: true}) // skip the cache
```

The API answers within about 5 seconds, or says the check is still running; then the client asks every 2 seconds
until it is done, for up to `Timeout` (default 60 seconds). Every result names its job (`result.JobID`): a
`catch_all` or `risky` one can later be sent to `client.Lists.Resolve`.

| `Result` field | |
| --- | --- |
| `Email` | The address, as checked. |
| `Verdict` | `valid`, `invalid`, `catch_all`, `risky` or `unknown` (the `Verdict...` constants). |
| `SafeToSend` | Whether to send to it: `valid`, or a `catch_all` whose score reaches your organisation's threshold. |
| `Score` | For a `catch_all` verdict, the probability that the mailbox exists (0 to 1), else `nil`. |
| `Reason` | Why: `mailbox_exists`, `mailbox_not_found`, `no_mail_server`, `accept_all`, `syntax`, `typo`, ... |
| `DidYouMean` | For a `typo`: the address it probably is. |
| `Flags` | `disposable`, `role`, `free_provider`, `gateway`. |
| `Provider`, `CatchAllDomain`, `Source`, `VerifiedAt` | The domain's mail provider, whether it accepts every address, where the answer came from, and when. |
| `JobID` | The job that holds the result. |

The API adds verdicts, reasons and flags over time: a value you do not know is kept as the string it is, never an
error. Show it, and act on `SafeToSend`.

### Waiting, and picking a check up again

A check that has not finished when `Timeout` runs out returns a `*verifyinboxes.WaitTimeoutError`. The check carries
on, and the error names its job, so nothing is lost:

```go
result, err := client.Verify(ctx, "ann@example.com", &verifyinboxes.VerifyParams{Timeout: 10 * time.Second})
var stillRunning *verifyinboxes.WaitTimeoutError
if errors.As(err, &stillRunning) {
	jobID := stillRunning.JobIDs[0]
	// ... later: picks it up where it was
	result, err = client.Checks.Wait(ctx, jobID, nil)
}
```

`client.Checks.Start` does not wait at all: you get the result, or a pending check with its job.

```go
check, err := client.Checks.Start(ctx, "ann@example.com", nil)
if check.Pending {
	result, err := client.Checks.Wait(ctx, check.JobID, &verifyinboxes.WaitParams{Timeout: 2 * time.Minute})
} else {
	fmt.Println(check.Result.Verdict)
}

job, err := client.Checks.Get(ctx, jobID) // the job as it is now; job.Result once it is done
```

A negative `Timeout` waits as long as the context allows.

### Many addresses

**Never check many addresses with a loop of `Verify`.** Checks go ahead of lists only up to 10 running at once:
past that, your checks wait behind other work, and a loop gains nothing over the ways below.

`VerifyMany` returns the results in the order of its input:

```go
results, err := client.VerifyMany(ctx, addresses, &verifyinboxes.VerifyManyParams{Timeout: 10 * time.Minute})
```

Up to 10 addresses are checked one by one, together. More go as one list (below), which the call waits for and
reads back; every result's `JobID` is then the list's. For a large or long-running batch, use a list yourself. An
empty list, or an empty address, is refused before any request.

### Lists

```go
created, err := client.Lists.CreateFromFile(ctx, "prospects.csv", &verifyinboxes.CreateListParams{EmailColumn: "email"})
created, err := client.Lists.Create(ctx, &verifyinboxes.CreateListParams{File: reader})            // an io.Reader
created, err := client.Lists.Create(ctx, &verifyinboxes.CreateListParams{CSV: "email\nann@example.com\n"}) // a CSV's text
created, err := client.Lists.Create(ctx, &verifyinboxes.CreateListParams{Emails: []string{"ann@example.com", "bob@example.com"}})

job, err := client.Lists.Wait(ctx, created.ID, nil) // asks at once, then after 2, 4, 8, 16 and every 30 seconds
fmt.Println(job.Status, job.Counts.Valid)           // done, and how many are valid
```

Give exactly one of `Emails`, `File` or `CSV`. The upload's name is the file's name, else `list.csv` (or
`Filename`).

**How long a list takes.** A few hundred addresses take minutes, and Microsoft-hosted ones longer. `Lists.Wait` waits
as long as the context allows unless you give it a `Timeout`; then it returns a `*WaitTimeoutError` (the list carries
on), and `Lists.Wait` picks it up again at any time. Instead of waiting, you can be told: see "Webhooks" below.

The results, every row once and in order, read a page at a time as you iterate (nothing is asked until then):

```go
rows := client.Lists.Results(ctx, created.ID, nil)
for rows.Next() {
	row := rows.Current()
	fmt.Println(row.Row, row.Email, row.Verdict, row.SafeToSend)
}
if err := rows.Err(); err != nil {
	log.Fatal(err)
}

all, err := client.Lists.Results(ctx, created.ID, nil).Collect()
client.Lists.Results(ctx, created.ID, &verifyinboxes.ResultsParams{OnlySafeToSend: true})
client.Lists.Results(ctx, created.ID, &verifyinboxes.ResultsParams{Verdicts: []string{"valid", "catch_all"}})
client.Lists.Results(ctx, created.ID, &verifyinboxes.ResultsParams{Partial: true})  // a list still running, as it stands
client.Lists.Results(ctx, created.ID, &verifyinboxes.ResultsParams{PageSize: 1000}) // rows per request, 1 to 1000 (default 500)
```

With Go 1.23 or later, range over it:

```go
for row, err := range client.Lists.Results(ctx, created.ID, nil).All() {
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(row.Email, row.Verdict)
}
```

To keep your own cursor (to resume elsewhere), read one page at a time:

```go
page, err := client.Lists.ResultsPage(ctx, created.ID, "", &verifyinboxes.ResultsParams{PageSize: 1000})
for err == nil {
	save(page.Data)
	if page.NextCursor == nil {
		break
	}
	page, err = client.Lists.ResultsPage(ctx, created.ID, *page.NextCursor, &verifyinboxes.ResultsParams{PageSize: 1000})
}
```

A page may hold fewer rows than asked, even none, before the last one: follow `NextCursor` until it is `nil`.

The CSV you sent, with the results appended:

```go
written, err := client.Lists.DownloadFile(ctx, created.ID, "results.csv", nil) // bytes written
written, err = client.Lists.DownloadFile(ctx, created.ID, "safe.csv", &verifyinboxes.DownloadParams{OnlySafeToSend: true})
written, err = client.Lists.Download(ctx, created.ID, w, nil) // to any io.Writer
```

`DownloadFile` writes beside the file and renames over it once the whole download is there: if it fails, the file
that was there is untouched, and a download cut short is made again from the start. `Download` is sent again until
the writer has its first byte; after that a failure is returned.

`client.Lists.Get(ctx, id)` is the list as it is now.

### Catch-all resolution

For an organisation allowed to send test emails, the `catch_all` and `risky` addresses of a finished list or check
can be settled by a test email. Most are settled within about 3 days of sending, some take up to 7 days. One request
takes at most 500 addresses (more is refused with `too_many_to_resolve`): for a list with more, name them in parts of
at most 500:

```go
resolution, err := client.Lists.Resolve(ctx, created.ID, nil) // all of them, if at most 500
some, err := client.Lists.Resolve(ctx, created.ID, &verifyinboxes.ResolveParams{Emails: []string{"bob@example.com"}})
job, err := client.Lists.Wait(ctx, resolution.ID, nil)
```

## Everything else

```go
account, err := client.Account.Get(ctx) // Name, Balance, Reviewed, TestEmails, SafeToSendThreshold

domain, err := client.Domains.Get(ctx, "example.com") // Provider, MXHosts, CatchAll, EmailPattern, ... (1 credit)

added, err := client.Suppressions.Add(ctx, &verifyinboxes.SuppressionParams{
	Emails: []string{"ann@example.com"}, Domains: []string{"competitor.example"},
})
removed, err := client.Suppressions.Remove(ctx, &verifyinboxes.SuppressionParams{Emails: []string{"ann@example.com"}})
list, err := client.Suppressions.List(ctx) // Domains, and AddressCount (addresses are kept only as a hash)

hook, err := client.Webhooks.Create(ctx, &verifyinboxes.WebhookParams{
	URL: "https://example.com/webhooks/verifyinboxes", Events: []string{verifyinboxes.EventJobCompleted},
})
secret := hook.Secret // shown only now: store it
hooks, err := client.Webhooks.List(ctx)
err = client.Webhooks.Delete(ctx, hook.ID)

page, err := client.Notices.List(ctx, &verifyinboxes.NoticesParams{After: lastSeen, Limit: 100}) // verdicts you bought, overturned since
// keep *page.NextAfter for next time

result, err := client.Feedback.Report(ctx, []verifyinboxes.FeedbackEvent{{
	Email: "ann@example.com", Type: "hard_bounce", ObservedAt: "2026-11-04T10:00:00Z", DSNCode: "5.1.1", EventID: "b-1",
}}, nil)

integration, err := client.Integrations.Create(ctx, &verifyinboxes.IntegrationParams{Provider: "instantly", Label: "main workspace"})
url := integration.URL // shown only now: paste it into the provider
integrations, err := client.Integrations.List(ctx)
err = client.Integrations.Delete(ctx, integration.ID)
```

`WebhookCreated.Secret` and `IntegrationCreated.URL` are left out of what the `fmt` package prints, and kept when you
read them or encode them as JSON.

## Errors

| Match it with | When |
| --- | --- |
| `errors.Is(err, verifyinboxes.ErrInvalidRequest)` | `400`, `413`, `414`, `415`, `422`: the request does not fit (`invalid_request`, `consumer_list`, ...) |
| `errors.Is(err, verifyinboxes.ErrAuthentication)` | `401`: the key or token is missing, mistyped, revoked, or past its hour |
| `errors.Is(err, verifyinboxes.ErrInsufficientCredits)` | `402`: the balance does not cover the request; nothing was charged |
| `errors.Is(err, verifyinboxes.ErrPermissionDenied)` | `403`: allowed for nobody with this credential |
| `errors.Is(err, verifyinboxes.ErrNotFound)` | `404 not_found`, or `410 gone` (a list whose data was deleted) |
| `errors.Is(err, verifyinboxes.ErrConflict)` | `409`: `not_ready` (the list has not finished), `idempotency_conflict` |
| `errors.Is(err, verifyinboxes.ErrRateLimited)` | `429`: retried on its own, unless `Retry-After` is over 60 seconds |
| `errors.Is(err, verifyinboxes.ErrServer)` | `5xx`: retried on its own; the error is the last answer's |
| `errors.As(err, &apiErr)` (`*verifyinboxes.APIError`) | every answer of the API with an error status, any other `4xx` included |
| `errors.Is(err, verifyinboxes.ErrConnection)` (`*verifyinboxes.ConnectionError`) | the request got no answer |
| `errors.Is(err, verifyinboxes.ErrTimeout)` | ... in time (`ConnectionError.Timeout`) |
| `errors.Is(err, verifyinboxes.ErrWaitTimeout)` (`*verifyinboxes.WaitTimeoutError`) | a check or a list was still running when the time to wait ran out |
| `errors.Is(err, verifyinboxes.ErrMissingAPIKey)` | no key given and `VERIFYINBOXES_API_KEY` not set |
| `errors.Is(err, verifyinboxes.ErrUnexpectedAnswer)` | the API answered something it should not have |
| `errors.Is(err, context.Canceled)`, `context.DeadlineExceeded` | the context ended the call: see "Cancellation" |

A wrong argument (an empty list of addresses, a page size of 0) is a plain error, returned before anything is sent.

An `*APIError` carries what the API said, and the request id support asks for:

```go
_, err := client.Lists.CreateFromFile(ctx, "prospects.csv", nil)
var apiErr *verifyinboxes.APIError
switch {
case errors.Is(err, verifyinboxes.ErrInsufficientCredits):
	fmt.Println("top up first")
case errors.As(err, &apiErr):
	fmt.Println(apiErr.StatusCode) // 422
	fmt.Println(apiErr.Code)       // consumer_list  <- match on this
	fmt.Println(apiErr.RequestID)  // the answer's X-Request-Id: quote it when you write to support
	fmt.Println(err)               // 422 consumer_list: ... (request id 019a...)
case err != nil:
	log.Fatal(err)
}
```

| Field | |
| --- | --- |
| `StatusCode` | The HTTP status. |
| `Code` | The API's error code, or `""` when the answer was not the API's (a proxy's error page). Match on it; treat one you do not know by its status. |
| `Message` | What the API said. The error's text is `<status> <code>: <message> (request id <id>)`: show it or log it; do not parse it. |
| `RequestID` | The answer's `X-Request-Id`. After retries, the last answer's. |
| `RetryAfter` | The answer's `Retry-After`, when it had one; else 0. |
| `Body` | The answer's body as it came. |
| `JobIDs` | The jobs the call had made when it failed. |

**Job ids.** Every error returned while waiting, and by `VerifyMany`, names every job the call made, in the order of
its input: `verifyinboxes.JobIDs(err)` returns them whatever the error (and `APIError`, `ConnectionError` and
`WaitTimeoutError` have them in their `JobIDs` field). Those jobs carry on, and the credits they hold are spent on
them: pick them up with `client.Checks.Wait` or `client.Lists.Wait` instead of starting again.

## Cancellation

When a call's context is cancelled or its deadline passes, the call stops, whatever it was doing (a request, a pause
before a retry, waiting for a check or a list), and its error matches `context.Canceled` (or
`context.DeadlineExceeded`) with `errors.Is`; nothing is sent again. One request is let finish, so that no job you
are charged for goes unnamed: the one that starts a check (`Verify`, `Checks.Start`, each check of `VerifyMany`) or
`VerifyMany`'s list, when it was already sent. It ends within the client's timeout, the job it made goes into the
error (`verifyinboxes.JobIDs(err)`), and nothing more is started or waited for.

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
results, err := client.VerifyMany(ctx, addresses, nil)
if errors.Is(err, context.DeadlineExceeded) {
	fmt.Println("still running:", verifyinboxes.JobIDs(err))
}
```

A check or a list that `Verify` or `VerifyMany` had started is not stopped by the context: it carries on and its
credits are held, and the error names it: wait for it again with `Checks.Wait` or `Lists.Wait`.

`Lists.Create`, `Lists.CreateFromFile` and `Lists.Resolve` stop at once, even when their request has already reached
the API (so that an upload can be cancelled). If it had, the list or the resolution exists and holds credits, but the
error does not name it. If you may cancel one, pass your own `IdempotencyKey`, and after the context's error make the
same call again with the same key, within 24 hours (the API keeps a key's answer that long):

- if the first request ran, the API answers with what it answered then (the list it made, or its error) and runs
  nothing again: nothing more is charged;
- if it is still running, the API answers `409 idempotency_in_progress`, which the library sends again after its
  `Retry-After` (up to `WithMaxRetries` times);
- if it never ran (for example it never arrived, or was answered `429` or `5xx`), it runs now, once.

An upload is known by its key alone, never by its file: send the same file again under the same key, and a new key
with a new file.

## Retries

A request that fails in a way worth retrying is sent again, up to `WithMaxRetries` times (default 2):

| Failure | Retried |
| --- | --- |
| No answer: the connection failed, was reset or closed, or timed out | Yes |
| `429` | Yes, after `Retry-After` |
| `409 idempotency_in_progress` | Yes, after `Retry-After` |
| `5xx` | Yes |
| Any other `4xx` | No: the same request would get the same answer |

The wait is the answer's `Retry-After` when it has one. A `Retry-After` over 60 seconds is not waited for: the error
is returned at once, with the wait in `RetryAfter`. Otherwise it backs off exponentially, with jitter: up to half a
second before the first retry, up to a second before the second, doubling to at most eight.

**Nothing is charged twice.** Every `POST` carries an `Idempotency-Key`, the same on every attempt of one call.
When an answer is lost after the API ran the request (a check, a list, an upload, a resolution, feedback, a
suppression), the retry gets the first answer again: one job, charged once. Over HTTP/1, `net/http` never sends a
`POST` of this library again by itself (a `POST` carries its key under the header map's key `idempotency-key`, so
that the transport does not take it for one it may repeat). Over HTTP/2 it may, when the server refused the request
or its connection failed before the request was taken (a `POST` with no body, such as `Lists.Resolve` without
`Emails`, is then sent again as it is): with the same `Idempotency-Key`, so the API runs it once, which is harmless.

A `409 idempotency_in_progress` (`ErrConflict`) left after the retries means the first request with that key is
still running on the API. Repeat the call later with your own `IdempotencyKey`, the same one: the API then answers
with what the first request answered, and runs nothing twice. (Without a key of your own, each call makes a new one,
which cannot be sent again: pass your own where a repeat matters.)

Your own key makes one request safe to send again after your program restarts. A key names **one** request, and the
API keeps its answer for 24 hours: in that time the same key gets that answer again, whatever you send with it. An
upload is known by its key alone, never by its file, so another file under a used key gets the first file's list;
and an error is kept like any answer, so a `402` stays a `402` under its key. So make the key from the request
itself, and give a new file, or a retry after you topped up, a new key:

```go
client.Verify(ctx, "ann@example.com", &verifyinboxes.VerifyParams{IdempotencyKey: "order-" + orderID}) // one key per order

data, _ := os.ReadFile("prospects.csv")
digest := sha256.Sum256(data)
client.Lists.CreateFromFile(ctx, "prospects.csv", &verifyinboxes.CreateListParams{
	IdempotencyKey: "import-" + hex.EncodeToString(digest[:]), // one key per file
})
```

A file is sent again whole: a path is read again, an `io.Reader` that can seek (an `*os.File`, a `*bytes.Reader`) is
rewound. Any other `io.Reader` is sent as it is read, so it is not sent again once its sending began.

Two requests are not sent again once they may have arrived: `Webhooks.Create` and `Integrations.Create`, whose
answers hold a secret shown once. They are retried only when the connection was never made, or after a `429`; after
a `*ConnectionError`, look at `Webhooks.List` or `Integrations.List` before making another. A `DELETE` whose answer
was lost is sent again; if the retry finds it gone, the first one did it.

```go
client, err := verifyinboxes.NewClient(verifyinboxes.WithMaxRetries(0)) // never retry
```

## Webhooks

A webhook gets a `POST` when a list finishes (`job.completed`) and when a verdict you bought is overturned
(`address.contradicted`). Check its signature before you read anything in it, against the raw body as it arrived,
never JSON decoded and encoded again:

```go
http.HandleFunc("/webhooks/verifyinboxes", func(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "unreadable", http.StatusBadRequest)
		return
	}
	if err := verifyinboxes.VerifySignature(body, r.Header.Get(verifyinboxes.SignatureHeader), secret); err != nil {
		http.Error(w, "bad signature", http.StatusBadRequest) // not from VerifyInboxes, changed on the way, or too old
		return
	}
	// ... json.Unmarshal(body, &event)
	w.WriteHeader(http.StatusNoContent)
})
```

`VerifySignature` returns `nil` for a valid signature, and otherwise an error matching
`verifyinboxes.ErrInvalidSignature` that says why; it never panics. `secret` is the 64 characters
`Webhooks.Create` returned. A signature more than 5 minutes from your clock is refused, so that an old delivery
cannot be sent again: `verifyinboxes.WithTolerance(d)` changes that, `verifyinboxes.WithNow(t)` sets the clock. It
needs no client and no key, and `client.Webhooks.VerifySignature` is the same function. Deliveries come at least
once: `X-Boxverifier-Delivery` (`verifyinboxes.DeliveryHeader`) is the same on every retry of one, to drop
duplicates.

## Types

Every answer is a struct named after the API's schemas (`Result`, `Job`, `JobCreated`, `ResultRow`, `ResultsPage`,
`Domain`, ...), with the API's field names in its JSON tags, so `json.Marshal` gives what the API sent. A value that
can be `null` is a pointer. Timestamps are ISO 8601 strings. A field this version does not know is ignored, and a
value it does not know is kept as the string it is, never an error.

## Examples

- [`examples/quickstart`](https://github.com/verifyinboxes/verifyinboxes-go/blob/main/examples/quickstart/main.go):
  one check, then several with `VerifyMany`.
- [`examples/list-from-csv`](https://github.com/verifyinboxes/verifyinboxes-go/blob/main/examples/list-from-csv/main.go):
  a list from a CSV: start it, wait, read the results, download them.
- [`examples/webhook-receiver`](https://github.com/verifyinboxes/verifyinboxes-go/blob/main/examples/webhook-receiver/main.go):
  a webhook receiver on the standard library's HTTP server, checking the signature before anything else.

Run one from a clone: `go run ./examples/quickstart ann@example.com`. The
[package documentation](https://pkg.go.dev/github.com/verifyinboxes/verifyinboxes-go) has more, each run by the
tests.

## Versioning

The library follows [semantic versioning](https://semver.org). It is `0.x` until the API's public launch, when it
becomes `1.0.0`; until then a minor version may change the library's surface, and the changes are listed in its
release notes. The API itself changes without breaking you: it adds fields, values and error codes, which this
library keeps as they are.

## Development

```bash
gofmt -l .                # nothing to show
go vet ./...
go test -race ./...       # against a fake API on 127.0.0.1 (no network)
go test -run '^$' -fuzz FuzzVerifySignature -fuzztime 60s .
```

`testdata/conformance/scenarios.json` is shared by every official VerifyInboxes library: what each must send and do
on the wire (retries with the same `Idempotency-Key`, job ids kept on a timeout, request ids on errors, results
through empty pages, the webhook signature cases). `conformance_test.go` replays it, each request on a connection
already used once. `smoke_test.go` runs against the live API when `VERIFYINBOXES_SMOKE_API_KEY` holds a key (it
spends a few credits).

## Licence

MIT. See [LICENSE](https://github.com/verifyinboxes/verifyinboxes-go/blob/main/LICENSE). To report a security
problem, see [SECURITY.md](https://github.com/verifyinboxes/verifyinboxes-go/blob/main/SECURITY.md).
