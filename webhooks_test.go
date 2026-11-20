package verifyinboxes_test

// VerifySignature beyond the shared vectors: it needs no client, gives a reason, and never panics, whatever it is
// given.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	verifyinboxes "github.com/verifyinboxes/verifyinboxes-go"
)

const webhookBody = `{"event":"job.completed","job_id":"019a3b71-3c4d-7e5f-8a6b-7c8d9e0f1a2b","status":"done"}`

func sign(body string, t int64, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	fmt.Fprintf(mac, "%d.%s", t, body)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignatureNeedsNoClient(t *testing.T) {
	now := time.Now().Unix()
	header := fmt.Sprintf("t=%d,v1=%s", now, sign(webhookBody, now, secret))
	if err := verifyinboxes.VerifySignature([]byte(webhookBody), header, secret); err != nil {
		t.Errorf("refused: %v", err)
	}
	if err := verifyinboxes.VerifySignature([]byte(webhookBody+" "), header, secret); !errors.Is(err, verifyinboxes.ErrInvalidSignature) {
		t.Errorf("a changed body: %v", err)
	}
	old := now - 301
	stale := fmt.Sprintf("t=%d,v1=%s", old, sign(webhookBody, old, secret))
	if err := verifyinboxes.VerifySignature([]byte(webhookBody), stale, secret); !errors.Is(err, verifyinboxes.ErrInvalidSignature) {
		t.Errorf("301 seconds old: %v", err)
	}
	if err := verifyinboxes.VerifySignature([]byte(webhookBody), stale, secret, verifyinboxes.WithTolerance(10*time.Minute)); err != nil {
		t.Errorf("301 seconds old, 10 minutes allowed: %v", err)
	}
	if verifyinboxes.SignatureHeader != "X-Boxverifier-Signature" {
		t.Errorf("the header is %s", verifyinboxes.SignatureHeader)
	}
}

func TestVerifySignatureSaysWhy(t *testing.T) {
	const at = 1762858800
	good := sign(webhookBody, at, secret)
	for header, why := range map[string]string{
		"":                         "no signature",
		fmt.Sprintf("v1=%s", good): "one t",
		fmt.Sprintf("t=%d,t=%d,v1=%s", at, at, good):                         "one t",
		fmt.Sprintf("t=%d", at):                                              "no v1",
		fmt.Sprintf("t=%d,v1=%s", at-400, sign(webhookBody, at-400, secret)): "tolerance",
		fmt.Sprintf("t=%d,v1=%s", at, sign(webhookBody, at, "another")):      "matches",
		fmt.Sprintf("t=1a,v1=%s", good):                                      "seconds",
	} {
		err := verifyinboxes.VerifySignature([]byte(webhookBody), header, secret, verifyinboxes.WithNow(time.Unix(at, 0)))
		if !errors.Is(err, verifyinboxes.ErrInvalidSignature) || !strings.Contains(err.Error(), why) {
			t.Errorf("%q: %v, which does not say %q", header, err, why)
		}
		if strings.Contains(fmt.Sprint(err), secret) {
			t.Errorf("the error shows the secret: %v", err)
		}
	}
	err := verifyinboxes.VerifySignature([]byte(webhookBody), fmt.Sprintf("t=%d,v1=%s", at, good), "", verifyinboxes.WithNow(time.Unix(at, 0)))
	if !errors.Is(err, verifyinboxes.ErrInvalidSignature) {
		t.Errorf("an empty secret: %v", err)
	}
}

func TestVerifySignatureIsOnTheClientToo(t *testing.T) {
	client, err := verifyinboxes.NewClient(verifyinboxes.WithAPIKey(testKey))
	if err != nil {
		t.Fatal(err)
	}
	const at = 1762858800
	header := fmt.Sprintf("t=%d,v1=%s", at, sign(webhookBody, at, secret))
	if err := client.Webhooks.VerifySignature([]byte(webhookBody), header, secret, verifyinboxes.WithNow(time.Unix(at, 0))); err != nil {
		t.Error(err)
	}
}

// referenceValid is the signature scheme as the API's documentation states it, written plainly.
func referenceValid(body []byte, header, key string, now, tolerance int64) bool {
	if key == "" {
		return false
	}
	var stamps, sigs []string
	for _, item := range strings.Split(header, ",") {
		name, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		switch {
		case name == "t":
			stamps = append(stamps, value)
		case name == "v1" && len(value) == 64 && strings.Trim(value, "0123456789abcdef") == "":
			sigs = append(sigs, value)
		}
	}
	if len(stamps) != 1 || len(sigs) == 0 || stamps[0] == "" || strings.Trim(stamps[0], "0123456789") != "" {
		return false
	}
	t, err := strconv.ParseInt(stamps[0], 10, 64)
	if err != nil {
		return false
	}
	if d := now - t; d > tolerance || -d > tolerance {
		return false
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(stamps[0] + "."))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	for _, s := range sigs {
		if s == want {
			return true
		}
	}
	return false
}

func FuzzVerifySignature(f *testing.F) {
	for _, v := range readScenarios(f).Signatures {
		f.Add([]byte(v.Body), v.Header, v.Secret, v.Now, v.Tolerance)
	}
	f.Add([]byte(""), "t=,v1=", "", int64(0), int64(0))
	f.Add([]byte("x"), "t=99999999999999999999999999,v1="+strings.Repeat("0", 64), "s", int64(-1<<63), int64(1<<62))
	f.Add([]byte("x"), "=,=,=,,,t=1"+strings.Repeat(",v1=", 50), "s", int64(1<<62), int64(-5))
	f.Fuzz(func(t *testing.T, body []byte, header, key string, now, tolerance int64) {
		tol := time.Duration(tolerance%(1<<33)) * time.Second
		err := verifyinboxes.VerifySignature(body, header, key, verifyinboxes.WithNow(time.Unix(now, 0)), verifyinboxes.WithTolerance(tol))
		if err != nil && !errors.Is(err, verifyinboxes.ErrInvalidSignature) {
			t.Fatalf("an error that is not ErrInvalidSignature: %v", err)
		}
		// Where the plain reading of the scheme is sure (a stamp it can read, a tolerance it can hold), they agree.
		if want := referenceValid(body, header, key, now, int64(tol/time.Second)); want != (err == nil) {
			if now > -(1<<40) && now < 1<<40 {
				t.Fatalf("valid %v, the scheme says %v (%v)", err == nil, want, err)
			}
		}
	})
}
