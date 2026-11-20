package verifyinboxes

import "fmt"

// What the API returns, named after the schemas of its description, with the API's own names in the JSON tags.
//
// Timestamps are ISO 8601 strings, as the API sends them. A value that can be null is a pointer (nil for null). The
// API adds fields and values without a new version: a field this version does not know is ignored, and a value it
// does not know (a new verdict, reason or flag) is kept as the plain string it is, never an error.

// Verdict says whether an address can receive mail. The API may add verdicts: show one you do not know, and act on
// SafeToSend.
type Verdict string

// The verdicts.
const (
	// VerdictValid: the mailbox exists.
	VerdictValid Verdict = "valid"
	// VerdictInvalid: it does not, or the address or domain cannot receive mail.
	VerdictInvalid Verdict = "invalid"
	// VerdictCatchAll: the domain accepts mail for any address, so whether this mailbox exists cannot be confirmed
	// (see Score).
	VerdictCatchAll Verdict = "catch_all"
	// VerdictRisky: it may receive mail, but that could not be confirmed.
	VerdictRisky Verdict = "risky"
	// VerdictUnknown: it could not be checked (free).
	VerdictUnknown Verdict = "unknown"
)

// JobStatus is where a job is: running until every address has a result, then done.
type JobStatus string

// The job statuses.
const (
	// JobRunning: some addresses have no result yet.
	JobRunning JobStatus = "running"
	// JobDone: every address has its result.
	JobDone JobStatus = "done"
	// JobQueued is reserved: no job has it today. It is waited out like JobRunning.
	JobQueued JobStatus = "queued"
	// JobFailed is reserved: no job has it today.
	JobFailed JobStatus = "failed"
)

// active reports whether a job is still being worked on.
func (s JobStatus) active() bool { return s == JobQueued || s == JobRunning }

// The events a webhook can be sent ([WebhookParams.Events]).
const (
	// EventJobCompleted: a list or a resolution finished.
	EventJobCompleted = "job.completed"
	// EventAddressContradicted: a verdict you bought was overturned by what became of mail sent to the address.
	EventAddressContradicted = "address.contradicted"
)

// Account is the organisation the credential belongs to (GET /v1/account).
type Account struct {
	// Name is the organisation's name.
	Name string `json:"name"`
	// Balance is the credits left; below zero after a refund of credits already spent.
	Balance int `json:"balance"`
	// Reviewed says whether what the account reports as feedback counts toward everyone's results.
	Reviewed bool `json:"reviewed"`
	// TestEmails says whether the account may resolve catch-all addresses ([ListService.Resolve]).
	TestEmails bool `json:"test_emails"`
	// SafeToSendThreshold is the score from which a catch_all address is safe to send to.
	SafeToSendThreshold float64 `json:"safe_to_send_threshold"`
}

// Result is one address's result. JobID names the job that holds it: the single check of [Client.Verify], or the
// list of [Client.VerifyMany] (11 addresses or more).
type Result struct {
	// Email is the address, as checked.
	Email string `json:"email"`
	// Verdict is valid, invalid, catch_all, risky or unknown.
	Verdict Verdict `json:"verdict"`
	// Score is, for a catch_all verdict, the probability that the mailbox exists (0 to 1); nil otherwise.
	Score *float64 `json:"score"`
	// SafeToSend says whether to send to it: valid, or a catch_all whose score reaches your organisation's
	// threshold.
	SafeToSend bool `json:"safe_to_send"`
	// Flags are disposable, role (info@, sales@), free_provider (a consumer provider), gateway (a security gateway).
	Flags []string `json:"flags"`
	// Provider is the domain's mail provider, from its MX hosts: google, microsoft, proofpoint, mimecast, other.
	Provider *string `json:"provider"`
	// CatchAllDomain says whether the domain accepts every address; nil when not known.
	CatchAllDomain *bool `json:"catch_all_domain"`
	// VerifiedAt is when the address was checked.
	VerifiedAt string `json:"verified_at"`
	// Source is where the answer came from: smtp (our live check), burner (a catch-all resolution's test email),
	// cache (an earlier result).
	Source string `json:"source"`
	// Reason is why the verdict is what it is: mailbox_exists, mailbox_not_found, no_mail_server, accept_all,
	// syntax, typo, greylisted, blocked, suppressed, ...
	Reason string `json:"reason"`
	// DidYouMean is, for a typo, the address it probably is.
	DidYouMean string `json:"did_you_mean,omitempty"`
	// JobID is the job that holds the result.
	JobID string `json:"job_id,omitempty"`
}

// Check is a check just started by [CheckService.Start]: its result, or, when the API is still running it, only its
// job.
type Check struct {
	// JobID is the check's job: wait for it with [CheckService.Wait].
	JobID string
	// Pending says the check is still running: Result is nil.
	Pending bool
	// Result is the check's result, when it is done.
	Result *Result
}

// ResultRow is one row of a list's results: the result of its address (its JobID is empty: the list's id is the one
// you asked with), and Row, its number in the CSV.
type ResultRow struct {
	// Row is the address's row in the CSV: 1 is the first under the header (or the first of the addresses sent).
	Row int `json:"row"`
	Result
}

// ResultsPage is one page of a list's results.
type ResultsPage struct {
	// Data are the page's rows, in order.
	Data []ResultRow `json:"data"`
	// NextCursor is the next page's cursor; nil on the last page. A page may hold fewer rows than asked, even none,
	// before it.
	NextCursor *string `json:"next_cursor"`
	// Complete is true when the job is done, so no row will be added.
	Complete bool `json:"complete"`
}

// VerdictCounts is how many rows have each verdict.
type VerdictCounts struct {
	// Valid is the number of valid rows.
	Valid int `json:"valid"`
	// Invalid is the number of invalid rows.
	Invalid int `json:"invalid"`
	// CatchAll is the number of catch_all rows.
	CatchAll int `json:"catch_all"`
	// Risky is the number of risky rows.
	Risky int `json:"risky"`
	// Unknown is the number of unknown rows.
	Unknown int `json:"unknown"`
}

// Job is a check, a list or a catch-all resolution, as it is now.
type Job struct {
	// ID is the job's id.
	ID string `json:"id"`
	// Kind is single (a check), bulk (a list) or resolve (a catch-all resolution).
	Kind string `json:"kind"`
	// Status is where the job is.
	Status JobStatus `json:"status"`
	// Total is the number of addresses in the job.
	Total int `json:"total"`
	// Done is the number with a result so far (for a resolution, settled).
	Done int `json:"done"`
	// CreatedAt is when the job was made.
	CreatedAt string `json:"created_at"`
	// FinishedAt is when it finished; nil until then.
	FinishedAt *string `json:"finished_at"`
	// Counts is by verdict once the job is done; a resolution's settled rows so far while it runs; else nil.
	Counts *VerdictCounts `json:"counts"`
	// Purged says the job's results have been deleted (30 days after it finished).
	Purged bool `json:"purged"`
	// Result is a single check's result, once it is done and while it is kept.
	Result *Result `json:"result,omitempty"`
	// ParentJobID is, for a resolution only, the job it resolves.
	ParentJobID *string `json:"parent_job_id,omitempty"`
	// ResolveJobIDs are, for a list or a check, its resolutions, oldest first.
	ResolveJobIDs []string `json:"resolve_job_ids,omitempty"`
	// DownloadURL is, for a finished list or resolution whose data is kept, where its CSV is
	// ([ListService.Download] reads it for you).
	DownloadURL string `json:"download_url,omitempty"`
}

// JobCreated is a list, just made.
type JobCreated struct {
	// ID is the list's id: wait for it with [ListService.Wait].
	ID string `json:"id"`
	// Status is where it is ([JobRunning]).
	Status JobStatus `json:"status"`
	// Total is the number of addresses in it.
	Total int `json:"total"`
}

// ResolveSkipped is the rows a resolution did not send, and why.
type ResolveSkipped struct {
	// Ineligible is the rows of a verdict other than catch_all or risky, or listed addresses not in the job.
	Ineligible int `json:"ineligible"`
	// Excluded is the rows of a top-level domain the service never sends to, or of a suppressed address.
	Excluded int `json:"excluded"`
	// AlreadyRequested is the rows an earlier resolution of this job took.
	AlreadyRequested int `json:"already_requested"`
	// Duplicate is the rows of an address this resolution already sends.
	Duplicate int `json:"duplicate"`
}

// ResolveCreated is a catch-all resolution, just made: a job of its own.
type ResolveCreated struct {
	// ID is the resolution's job: wait for it with [ListService.Wait].
	ID string `json:"id"`
	// Status is [JobDone] when every address was answered at once, else [JobRunning].
	Status JobStatus `json:"status"`
	// Total is the number of addresses sent, each once.
	Total int `json:"total"`
	// Skipped is what it left out.
	Skipped ResolveSkipped `json:"skipped"`
}

// MxHost is one of a domain's mail servers.
type MxHost struct {
	// Host is the server's name.
	Host string `json:"host"`
	// Preference is its MX preference: the lowest first.
	Preference int `json:"preference"`
}

// Domain is what is known about a domain.
type Domain struct {
	// Domain is the domain, as asked.
	Domain string `json:"domain"`
	// Provider is its mail provider, from its MX hosts; nil when the domain receives no mail.
	Provider *string `json:"provider"`
	// Gateway says its mail goes through a security gateway.
	Gateway bool `json:"gateway"`
	// AcceptsMail is false for a domain that does not exist, has a null MX or no records, or whose MX hosts all do
	// not exist (MXHosts still lists them).
	AcceptsMail bool `json:"accepts_mail"`
	// MXHosts are its MX hosts, by ascending preference.
	MXHosts []MxHost `json:"mx_hosts"`
	// CatchAll says whether it accepts every address; nil unless tested in the last 7 days.
	CatchAll *bool `json:"catch_all"`
	// CatchAllCheckedAt is when the catch-all test was last done, however long ago.
	CatchAllCheckedAt *string `json:"catch_all_checked_at"`
	// EmailPattern is the usual shape of the domain's addresses (first.last), when known.
	EmailPattern *string `json:"email_pattern"`
	// PatternConfidence is the share of the domain's known addresses that fit EmailPattern.
	PatternConfidence *float64 `json:"pattern_confidence"`
	// RegisteredAt is when the domain was registered, when known.
	RegisteredAt *string `json:"registered_at"`
}

// SuppressionList is the account's suppression list. Addresses are kept only as a hash, so only their number is
// told.
type SuppressionList struct {
	// Domains are the domains on it.
	Domains []string `json:"domains"`
	// AddressCount is the number of addresses on it.
	AddressCount int `json:"address_count"`
}

// Webhook is where the API sends events.
type Webhook struct {
	// ID is the webhook's id.
	ID string `json:"id"`
	// URL is where the events are sent.
	URL string `json:"url"`
	// Events are the events sent ([EventJobCompleted], [EventAddressContradicted]).
	Events []string `json:"events"`
	// CreatedAt is when it was made.
	CreatedAt string `json:"created_at"`
}

// WebhookCreated is a webhook, just made. Secret signs its deliveries and is shown only here: store it. It is left
// out of what the fmt package prints, and kept in JSON.
type WebhookCreated struct {
	// ID is the webhook's id.
	ID string `json:"id"`
	// URL is where the events are sent.
	URL string `json:"url"`
	// Events are the events sent.
	Events []string `json:"events"`
	// Secret signs the deliveries: give it to [VerifySignature]. It is shown only here.
	Secret string `json:"secret"`
	// CreatedAt is when it was made.
	CreatedAt string `json:"created_at"`
}

// Format prints the webhook with its secret hidden, whatever the verb.
func (w WebhookCreated) Format(f fmt.State, verb rune) {
	type shown WebhookCreated
	s := shown(w)
	if s.Secret != "" {
		s.Secret = "[hidden]"
	}
	fmt.Fprintf(f, fmt.FormatString(f, verb), s)
}

// NoticePrevious is the verdict you bought.
type NoticePrevious struct {
	// Verdict is the verdict you bought.
	Verdict Verdict `json:"verdict"`
	// Reason is why it was given.
	Reason string `json:"reason"`
	// Score is its catch_all score; nil for another verdict.
	Score *float64 `json:"score"`
	// SafeToSend is what it said.
	SafeToSend bool `json:"safe_to_send"`
	// VerifiedAt is when it was given.
	VerifiedAt string `json:"verified_at"`
}

// NoticeCurrent is the verdict the address was verified again to.
type NoticeCurrent struct {
	// Verdict is valid or invalid.
	Verdict Verdict `json:"verdict"`
	// Reason is why.
	Reason string `json:"reason"`
	// VerifiedAt is when that finished.
	VerifiedAt string `json:"verified_at"`
}

// NoticeEvidence is what contradicted it. Never whose outreach it was, unless your own (ReportedByYou).
type NoticeEvidence struct {
	// Kind is hard_bounce, bounce (a bounce that came with no status code), reply or delivered.
	Kind string `json:"kind"`
	// DSNCode is the bounce's status code, such as 5.1.1.
	DSNCode *string `json:"dsn_code"`
	// ObservedAt is the UTC day it happened (YYYY-MM-DD), never the time.
	ObservedAt string `json:"observed_at"`
	// ReportedByYou is true when it is an outcome your account reported.
	ReportedByYou bool `json:"reported_by_you"`
}

// Notice is a verdict you bought, overturned by what became of mail sent to the address.
type Notice struct {
	// NoticeID is the notice's id: send the last one as [NoticesParams.After].
	NoticeID string `json:"notice_id"`
	// Email is the address.
	Email string `json:"email"`
	// JobIDs are your jobs that returned the verdict.
	JobIDs []string `json:"job_ids"`
	// Previous is the verdict you bought.
	Previous NoticePrevious `json:"previous"`
	// Current is the verdict now.
	Current NoticeCurrent `json:"current"`
	// Evidence is what contradicted it.
	Evidence NoticeEvidence `json:"evidence"`
	// Message says it in a sentence.
	Message string `json:"message"`
	// CreatedAt is when the notice was made.
	CreatedAt string `json:"created_at"`
}

// NoticePage is a page of notices, oldest first.
type NoticePage struct {
	// Notices are the page's notices.
	Notices []Notice `json:"notices"`
	// NextAfter is what to send as [NoticesParams.After] next time; nil when there were none.
	NextAfter *string `json:"next_after"`
}

// FeedbackEvent is what became of mail you sent to an address.
type FeedbackEvent struct {
	// Email is the address the mail was sent to.
	Email string `json:"email"`
	// Type is sent, delivered, reply, auto_reply, hard_bounce, soft_bounce or bounce.
	Type string `json:"type"`
	// ObservedAt is when it happened, ISO 8601.
	ObservedAt string `json:"observed_at"`
	// EventID is your own id of the event: the same id sent again counts once.
	EventID string `json:"event_id,omitempty"`
	// DSNCode is a bounce's status code, such as 5.1.1.
	DSNCode string `json:"dsn_code,omitempty"`
	// Diagnostic is a bounce's diagnostic text.
	Diagnostic string `json:"diagnostic,omitempty"`
}

// FeedbackRejection is an event that was refused.
type FeedbackRejection struct {
	// Index is the event's position in what you sent, from 0.
	Index int `json:"index"`
	// Error says why it was refused.
	Error string `json:"error"`
}

// FeedbackResult is what became of the events reported.
type FeedbackResult struct {
	// Accepted is the number of events recorded.
	Accepted int `json:"accepted"`
	// Duplicates is the number of events already recorded.
	Duplicates int `json:"duplicates"`
	// Ignored is the number of events of an address on the suppression list; nothing about it is stored.
	Ignored int `json:"ignored"`
	// Rejected are the events refused, and why.
	Rejected []FeedbackRejection `json:"rejected"`
}

// Integration is an address that lets Instantly or Smartlead report what became of your mail.
type Integration struct {
	// ID is the integration's id.
	ID string `json:"id"`
	// Provider is instantly or smartlead.
	Provider string `json:"provider"`
	// Label is your name for it; nil when none.
	Label *string `json:"label"`
	// TokenPrefix is the first 12 characters of its URL's token, to tell integrations apart.
	TokenPrefix string `json:"token_prefix"`
	// CreatedAt is when it was made.
	CreatedAt string `json:"created_at"`
	// LastEventAt is the last delivery it accepted, recorded or ignored; nil when none.
	LastEventAt *string `json:"last_event_at"`
	// LastBounceAt is the last new bounce it reported; nil when none.
	LastBounceAt *string `json:"last_bounce_at"`
	// LastError is the last real problem with a delivery: malformed, no_lead_email, invalid_email,
	// ambiguous_lead, bad_event_id, missing_signature or bad_signature; nil when there has been none.
	LastError *string `json:"last_error"`
	// LastErrorAt is when that was.
	LastErrorAt *string `json:"last_error_at"`
	// Signed says whether it has a signing secret.
	Signed bool `json:"signed"`
}

// IntegrationCreated is an integration, just made. URL holds its token and is shown only here: paste it into the
// provider. It is left out of what the fmt package prints, and kept in JSON.
type IntegrationCreated struct {
	// ID is the integration's id.
	ID string `json:"id"`
	// Provider is instantly or smartlead.
	Provider string `json:"provider"`
	// Label is your name for it; nil when none.
	Label *string `json:"label"`
	// URL is the address to paste into the provider. It holds the integration's token, and is shown only here.
	URL string `json:"url"`
	// CreatedAt is when it was made.
	CreatedAt string `json:"created_at"`
}

// Format prints the integration with its URL hidden, whatever the verb.
func (i IntegrationCreated) Format(f fmt.State, verb rune) {
	type shown IntegrationCreated
	s := shown(i)
	if s.URL != "" {
		s.URL = "[hidden]"
	}
	fmt.Fprintf(f, fmt.FormatString(f, verb), s)
}
