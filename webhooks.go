package verifyinboxes

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	// SignatureHeader is the header that carries a webhook delivery's signature: "t=<unix seconds>,v1=<hex>".
	SignatureHeader = "X-Boxverifier-Signature"
	// DeliveryHeader is the same on every retry of one delivery: deliveries come at least once, so drop the ones
	// you have seen.
	DeliveryHeader = "X-Boxverifier-Delivery"
	// DefaultTolerance is how far a signature's time may be from yours (5 minutes).
	DefaultTolerance = 300 * time.Second
)

// ErrInvalidSignature matches every error of [VerifySignature]: the delivery did not come from VerifyInboxes, was
// changed on the way, is older (or newer) than the tolerance, or its header cannot be read.
var ErrInvalidSignature = errors.New("verifyinboxes: the webhook signature is not valid")

// SignatureOption is an option of [VerifySignature].
type SignatureOption func(*signatureConfig)

type signatureConfig struct {
	tolerance time.Duration
	now       time.Time
}

// WithTolerance sets how far the signature's time may be from now (default [DefaultTolerance]); a negative one
// accepts nothing.
func WithTolerance(d time.Duration) SignatureOption {
	return func(c *signatureConfig) { c.tolerance = d }
}

// WithNow sets the time to compare the signature's with. Default: your clock.
func WithNow(t time.Time) SignatureOption { return func(c *signatureConfig) { c.now = t } }

// VerifySignature checks that header (the delivery's X-Boxverifier-Signature) signs payload with your webhook's
// secret. It returns nil for a valid signature, and otherwise an error matching [ErrInvalidSignature] that says
// why; it never panics. It needs no client and no key.
//
// Pass the body exactly as it arrived, before any JSON parsing: its bytes. secret is the 64 characters
// [WebhookService.Create] returned. A signature more than the tolerance (default 5 minutes) from now is refused, so
// that an old delivery cannot be sent again. Several v1 signatures may be given (while a secret is being replaced):
// one that matches is enough. They are compared in constant time.
func VerifySignature(payload []byte, header, secret string, opts ...SignatureOption) error {
	cfg := signatureConfig{tolerance: DefaultTolerance}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.now.IsZero() {
		cfg.now = time.Now()
	}
	invalid := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidSignature, fmt.Sprintf(format, a...))
	}
	if secret == "" {
		return invalid("the secret is empty")
	}
	if strings.TrimSpace(header) == "" {
		return invalid("no signature header")
	}
	var stamps, signatures []string
	for _, item := range strings.Split(header, ",") {
		name, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		switch {
		case name == "t":
			stamps = append(stamps, value)
		case name == "v1" && lowerHex64(value):
			signatures = append(signatures, value)
		}
	}
	if len(stamps) != 1 {
		return invalid("the header must have exactly one t, not %d", len(stamps))
	}
	stamp := stamps[0]
	if stamp == "" || strings.Trim(stamp, "0123456789") != "" {
		return invalid("t is not a number of seconds")
	}
	if len(signatures) == 0 {
		return invalid("no v1 of 64 lowercase hex characters")
	}
	seconds, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		return invalid("t is not a number of seconds")
	}
	age := cfg.now.Sub(time.Unix(seconds, 0))
	if age == math.MinInt64 {
		age = math.MaxInt64
	} else if age < 0 {
		age = -age
	}
	if cfg.tolerance < 0 || age > cfg.tolerance {
		return invalid("signed %v from now, past the tolerance of %v", age.Round(time.Second), cfg.tolerance)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stamp + "."))
	mac.Write(payload)
	expected := []byte(hex.EncodeToString(mac.Sum(nil)))
	matched := 0
	for _, signature := range signatures {
		// Every one is compared, in constant time: which of them matched is not told by the time it took.
		matched |= subtleEqual(expected, []byte(signature))
	}
	if matched != 1 {
		return invalid("no v1 matches the body and the secret")
	}
	return nil
}

// subtleEqual is 1 when a and b are equal, in constant time for their length.
func subtleEqual(a, b []byte) int {
	if hmac.Equal(a, b) {
		return 1
	}
	return 0
}

// lowerHex64 reports whether s is 64 lowercase hex characters.
func lowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
