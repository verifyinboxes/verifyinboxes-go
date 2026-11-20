// Package verifyinboxes is the official Go library for the VerifyInboxes API: check whether email addresses can
// receive mail, one at a time or as lists of any size, and read the results.
//
// An organisation admin makes an API key in the VerifyInboxes app under Developers -> API keys. Put it in the
// environment as VERIFYINBOXES_API_KEY, then:
//
//	client, err := verifyinboxes.NewClient() // reads VERIFYINBOXES_API_KEY
//	if err != nil {
//		log.Fatal(err)
//	}
//	result, err := client.Verify(ctx, "ann@example.com", nil)
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Println(result.Verdict, result.SafeToSend)
//
// The services mirror the API: [Client.Account], [Client.Checks], [Client.Lists], [Client.Domains],
// [Client.Suppressions], [Client.Webhooks], [Client.Notices], [Client.Feedback] and [Client.Integrations]. Every
// method takes a [context.Context] first and, where it has options, a params pointer last (nil: the defaults). The
// library has no dependencies, and needs Go 1.22 or later.
//
// # Many addresses
//
// Never check many addresses with a loop of [Client.Verify]: past 10 running checks, an owner's checks wait behind
// other work. [Client.VerifyMany] checks up to 10 addresses together, and more as one list; for a large batch, make
// a list yourself with [ListService.Create] or [ListService.CreateFromFile]. A few hundred addresses take minutes,
// Microsoft-hosted ones longer.
//
// # Waiting, and picking a job up again
//
// [Client.Verify] waits up to 60 seconds for its check, [Client.VerifyMany] up to 10 minutes, [ListService.Wait] as
// long as the context allows; each takes a Timeout. A wait that runs out returns a [*WaitTimeoutError]: the job
// carries on, and its credits are held. Every error returned while waiting, and by VerifyMany, names every job the
// call made ([JobIDs]), so nothing is lost: wait for them again with [CheckService.Wait] or [ListService.Wait].
//
// # Errors
//
// An answer of the API with an error status is an [*APIError]: its Code is the API's (match on it), its RequestID
// the answer's X-Request-Id (quote it to support), and its message ends with "(request id <id>)". It matches the
// sentinel of its status with [errors.Is]: [ErrInvalidRequest] (400, 413, 414, 415, 422), [ErrAuthentication] (401),
// [ErrInsufficientCredits] (402), [ErrPermissionDenied] (403), [ErrNotFound] (404, 410), [ErrConflict] (409),
// [ErrRateLimited] (429), [ErrServer] (5xx). A request that got no answer is a [*ConnectionError] ([ErrConnection],
// and [ErrTimeout] when its time ran out). An answer that breaks the API's own rules matches [ErrUnexpectedAnswer].
//
// # Retries
//
// A request that fails in a way worth retrying is sent again, up to [WithMaxRetries] times (default 2): when it got
// no answer, after a 429 or a 409 idempotency_in_progress, and after a 5xx; never after another 4xx. The wait is the
// answer's Retry-After (one over 60 seconds is not waited for: the error is returned, with RetryAfter on it), else
// an exponential backoff with jitter: up to half a second before the first retry, doubling to at most eight.
//
// Nothing is charged twice. Every POST carries an Idempotency-Key, the same on every attempt of one call: when an
// answer is lost after the API ran the request (a check, a list, an upload, a resolution, feedback, a suppression),
// the retry gets the first answer again, one job charged once. Two requests are not sent again once they may have
// arrived, [WebhookService.Create] and [IntegrationService.Create], whose answers hold a secret shown once: they are
// retried only when the connection was never made, or after a 429. A DELETE whose answer was lost is sent again; if
// the retry finds it gone, the first one did it. net/http itself may send a POST again over HTTP/2, when the server
// refused the request or its connection failed before the request was taken; a POST with no body, such as
// [ListService.Resolve] without Emails, is then sent again as it is. It carries the same Idempotency-Key, so the API
// runs it once: that is harmless.
//
// Your own key (VerifyParams.IdempotencyKey, CreateListParams.IdempotencyKey, ...) makes one request safe to send
// again after your program restarts. A key names one request, and the API keeps its answer for 24 hours: in that
// time the same key gets that answer again, whatever you send with it. An upload is known by its key alone, never
// by its file, and an error is kept like any answer (a 402 stays a 402 under its key): make the key from the request
// itself, and give a new file, or a retry after you topped up, a new key.
//
// # Cancellation
//
// When a call's context is cancelled or its deadline passes, the call stops, whatever it was doing (a request, a
// pause before a retry, waiting for a check or a list), and its error matches context.Canceled or
// context.DeadlineExceeded with [errors.Is]; nothing is sent again. One request is let finish, so that no job you are
// charged for goes unnamed: the one that starts a check ([Client.Verify], [CheckService.Start], each check of
// [Client.VerifyMany]) or VerifyMany's list, when it was already sent. It ends within the client's timeout, the job
// it made is named by the error ([JobIDs]), and nothing more is started or waited for. That job carries on and its
// credits are held: wait for it again.
//
// [ListService.Create] and [ListService.Resolve] stop at once, even when their request has already reached the API
// (so that an upload can be cancelled). If it had, the list or the resolution exists and holds credits, but the
// error does not name it. If you may cancel one, pass your own IdempotencyKey, and afterwards make the same call
// again with the same key, within 24 hours: if the first request ran, the API answers with what it answered then and
// runs nothing again; if it is still running, the API answers 409 idempotency_in_progress, which the client sends
// again after its Retry-After; if it never ran, it runs now, once.
//
// # Webhooks
//
// [VerifySignature] checks a delivery's X-Boxverifier-Signature against its raw body and your webhook's secret,
// before you read anything in it. It needs no client.
//
// # Personal access tokens
//
// Where an API key works, so does a personal access token (vi_at_...): what an app gets when a person signs in to it
// with their VerifyInboxes account. It acts as that person, and lives an hour. Pass it with [WithAPIKey], or give a
// [TokenSource] with [WithTokenSource]; a TokenSource that is also a [Refresher] is refreshed once when the API
// answers that the token is no longer valid.
package verifyinboxes

// Version is the version of this library. It is sent in every request's User-Agent: "verifyinboxes-go/<version>".
const Version = "0.1.0"
