package verifyinboxes

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

// AccountService is the organisation the credential belongs to.
type AccountService struct{ client *Client }

// Get returns the organisation's name, balance and switches (GET /v1/account).
func (s *AccountService) Get(ctx context.Context) (*Account, error) {
	var account Account
	if _, err := s.client.doJSON(ctx, &request{method: http.MethodGet, path: "/v1/account"}, &account); err != nil {
		return nil, err
	}
	return &account, nil
}

// DomainService is what is known about a domain.
type DomainService struct{ client *Client }

// Get returns what is known about a domain (GET /v1/domains/{domain}): its mail provider, MX hosts, whether it
// accepts every address, its likely address pattern. It costs a credit.
func (s *DomainService) Get(ctx context.Context, domain string) (*Domain, error) {
	escaped, err := segment("domain", domain)
	if err != nil {
		return nil, err
	}
	var out Domain
	if _, err := s.client.doJSON(ctx, &request{method: http.MethodGet, path: "/v1/domains/" + escaped}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SuppressionService is the addresses and domains never to check: a check of one is answered invalid
// (suppressed), free.
type SuppressionService struct{ client *Client }

// SuppressionParams are the addresses and domains to add or remove; at least one of them.
type SuppressionParams struct {
	// Emails are addresses.
	Emails []string
	// Domains are domains: every address on them.
	Domains []string
}

// List returns the domains on the list, and how many addresses (kept only as a hash) (GET /v1/suppressions).
func (s *SuppressionService) List(ctx context.Context) (*SuppressionList, error) {
	var out SuppressionList
	if _, err := s.client.doJSON(ctx, &request{method: http.MethodGet, path: "/v1/suppressions"}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Add puts addresses and domains on the list, never to be checked again (POST /v1/suppressions), and returns how
// many were added.
func (s *SuppressionService) Add(ctx context.Context, p *SuppressionParams) (int, error) {
	body, err := suppressionBody(p)
	if err != nil {
		return 0, err
	}
	var out struct {
		Added *int `json:"added"`
	}
	got, err := s.client.doJSON(ctx, &request{method: http.MethodPost, path: "/v1/suppressions", body: body, key: newKey()}, &out)
	if err != nil {
		return 0, err
	}
	if out.Added == nil {
		return 0, unexpected(got.requestID, nil, "the API answered without added")
	}
	return *out.Added, nil
}

// Remove takes addresses and domains off the list (DELETE /v1/suppressions), and returns how many were removed.
func (s *SuppressionService) Remove(ctx context.Context, p *SuppressionParams) (int, error) {
	body, err := suppressionBody(p)
	if err != nil {
		return 0, err
	}
	var out struct {
		Removed *int `json:"removed"`
	}
	got, err := s.client.doJSON(ctx, &request{method: http.MethodDelete, path: "/v1/suppressions", body: body}, &out)
	if err != nil {
		return 0, err
	}
	if out.Removed == nil {
		return 0, unexpected(got.requestID, nil, "the API answered without removed")
	}
	return *out.Removed, nil
}

func suppressionBody(p *SuppressionParams) (any, error) {
	if p == nil || (len(p.Emails) == 0 && len(p.Domains) == 0) {
		return nil, errors.New("verifyinboxes: give Emails, Domains or both")
	}
	return struct {
		Emails  []string `json:"emails,omitempty"`
		Domains []string `json:"domains,omitempty"`
	}{p.Emails, p.Domains}, nil
}

// WebhookService is where the API sends events: a list finished, a verdict you bought was overturned.
type WebhookService struct{ client *Client }

// WebhookParams are a webhook to make.
type WebhookParams struct {
	// URL gets the events: an https:// address.
	URL string
	// Events are the events to send ([EventJobCompleted], [EventAddressContradicted]); default both.
	Events []string
}

// Create makes a webhook (POST /v1/webhooks). The answer's Secret is shown only once: store it.
//
// It is not sent again once it may have arrived (a second webhook would be made): it is retried only when the
// connection was never made, or after a 429. After a [*ConnectionError], look at [WebhookService.List] before making
// another.
func (s *WebhookService) Create(ctx context.Context, p *WebhookParams) (*WebhookCreated, error) {
	if p == nil || p.URL == "" {
		return nil, errors.New("verifyinboxes: a webhook needs its URL")
	}
	body := struct {
		URL    string   `json:"url"`
		Events []string `json:"events,omitempty"`
	}{p.URL, p.Events}
	var out WebhookCreated
	if _, err := s.client.doJSON(ctx, &request{
		method: http.MethodPost, path: "/v1/webhooks", body: body, key: newKey(), retry: retryUnsent,
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// List returns the webhooks, never their secrets (GET /v1/webhooks).
func (s *WebhookService) List(ctx context.Context) ([]Webhook, error) {
	out := []Webhook{}
	if _, err := s.client.doJSON(ctx, &request{method: http.MethodGet, path: "/v1/webhooks"}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Delete removes a webhook (DELETE /v1/webhooks/{id}). A retry that finds it gone counts as done.
func (s *WebhookService) Delete(ctx context.Context, id string) error {
	escaped, err := segment("webhook id", id)
	if err != nil {
		return err
	}
	_, err = s.client.do(ctx, &request{method: http.MethodDelete, path: "/v1/webhooks/" + escaped, goneIsDone: true})
	return err
}

// VerifySignature is [VerifySignature], here too.
func (s *WebhookService) VerifySignature(payload []byte, header, secret string, opts ...SignatureOption) error {
	return VerifySignature(payload, header, secret, opts...)
}

// NoticeService is the contradiction notices: verdicts you bought, overturned by what became of mail sent to the
// address.
type NoticeService struct{ client *Client }

// NoticesParams are the options of [NoticeService.List]. A nil *NoticesParams is all defaults.
type NoticesParams struct {
	// After is the NextAfter of the page before: only notices after it.
	After string
	// Limit is at most this many, 1 to 500. Default (0) 100.
	Limit int
}

// List returns contradiction notices, oldest first (GET /v1/notices). Keep the page's NextAfter and send it as
// After next time; a page shorter than Limit means you have caught up.
func (s *NoticeService) List(ctx context.Context, p *NoticesParams) (*NoticePage, error) {
	query := url.Values{}
	if p != nil && p.After != "" {
		query.Set("after", p.After)
	}
	if p != nil && p.Limit != 0 {
		query.Set("limit", strconv.Itoa(p.Limit))
	}
	var out NoticePage
	if _, err := s.client.doJSON(ctx, &request{method: http.MethodGet, path: "/v1/notices", query: query}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// FeedbackService is what became of the mail you sent: bounces, deliveries, replies.
type FeedbackService struct{ client *Client }

// FeedbackParams are the options of [FeedbackService.Report]. A nil *FeedbackParams is all defaults.
type FeedbackParams struct {
	// IdempotencyKey is your own Idempotency-Key; default: a new one for the call.
	IdempotencyKey string
}

// Report tells what became of mail you sent (POST /v1/feedback).
//
//	client.Feedback.Report(ctx, []verifyinboxes.FeedbackEvent{{
//		Email: "ann@example.com", Type: "hard_bounce", ObservedAt: "2026-11-04T10:00:00Z",
//		DSNCode: "5.1.1", EventID: "b-1",
//	}}, nil)
func (s *FeedbackService) Report(ctx context.Context, events []FeedbackEvent, p *FeedbackParams) (*FeedbackResult, error) {
	if p == nil {
		p = &FeedbackParams{}
	}
	key, err := idempotencyKey(p.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	if events == nil {
		events = []FeedbackEvent{}
	}
	body := struct {
		Events []FeedbackEvent `json:"events"`
	}{events}
	var out FeedbackResult
	if _, err := s.client.doJSON(ctx, &request{method: http.MethodPost, path: "/v1/feedback", body: body, key: key}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// IntegrationService is the addresses to paste into Instantly or Smartlead, which then report what became of your
// mail.
type IntegrationService struct{ client *Client }

// IntegrationParams are an integration to make.
type IntegrationParams struct {
	// Provider is instantly or smartlead.
	Provider string
	// Label is your name for it.
	Label string
	// SigningSecret is the provider's webhook signing secret, when it signs what it sends.
	SigningSecret string
}

// Create makes an integration (POST /v1/integrations): an address (URL, shown only once) to paste into the
// provider. It is not sent again once it may have arrived: after a [*ConnectionError], look at
// [IntegrationService.List] before making another.
func (s *IntegrationService) Create(ctx context.Context, p *IntegrationParams) (*IntegrationCreated, error) {
	if p == nil || p.Provider == "" {
		return nil, errors.New("verifyinboxes: an integration needs its provider: instantly or smartlead")
	}
	body := struct {
		Provider      string `json:"provider"`
		Label         string `json:"label,omitempty"`
		SigningSecret string `json:"signing_secret,omitempty"`
	}{p.Provider, p.Label, p.SigningSecret}
	var out IntegrationCreated
	if _, err := s.client.doJSON(ctx, &request{
		method: http.MethodPost, path: "/v1/integrations", body: body, key: newKey(), retry: retryUnsent,
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// List returns the integrations (GET /v1/integrations).
func (s *IntegrationService) List(ctx context.Context) ([]Integration, error) {
	out := []Integration{}
	if _, err := s.client.doJSON(ctx, &request{method: http.MethodGet, path: "/v1/integrations"}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Delete removes an integration (DELETE /v1/integrations/{id}). A retry that finds it gone counts as done.
func (s *IntegrationService) Delete(ctx context.Context, id string) error {
	escaped, err := segment("integration id", id)
	if err != nil {
		return err
	}
	_, err = s.client.do(ctx, &request{method: http.MethodDelete, path: "/v1/integrations/" + escaped, goneIsDone: true})
	return err
}
