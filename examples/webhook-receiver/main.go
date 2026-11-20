// Webhook-receiver receives VerifyInboxes webhooks: it checks the signature before anything else, then reads the
// event.
//
//	export VERIFYINBOXES_WEBHOOK_SECRET="..."      # the secret Webhooks.Create returned
//	go run ./examples/webhook-receiver :8000
//
// Put it behind HTTPS (the API calls only https:// addresses), and register its address with
// client.Webhooks.Create(ctx, &verifyinboxes.WebhookParams{URL: "https://example.com/webhooks/verifyinboxes"}).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	verifyinboxes "github.com/verifyinboxes/verifyinboxes-go"
)

func main() {
	secret := os.Getenv("VERIFYINBOXES_WEBHOOK_SECRET")
	if secret == "" {
		fmt.Fprintln(os.Stderr, "set VERIFYINBOXES_WEBHOOK_SECRET to the webhook's secret")
		os.Exit(2)
	}
	address := ":8000"
	if len(os.Args) > 1 {
		address = os.Args[1]
	}
	server := &http.Server{Addr: address, Handler: handler(secret), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(server.ListenAndServe())
}

func handler(secret string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// The body exactly as it came: the signature is over these bytes, not over JSON parsed and written again.
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := verifyinboxes.VerifySignature(body, r.Header.Get(verifyinboxes.SignatureHeader), secret); err != nil {
			log.Println(err) // not from VerifyInboxes, changed on the way, or older than 5 minutes
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var event map[string]any
		if err := json.Unmarshal(body, &event); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Deliveries come at least once: the delivery header is the same on every retry of one, to drop duplicates.
		delivery := r.Header.Get(verifyinboxes.DeliveryHeader)
		switch event["event"] {
		case verifyinboxes.EventJobCompleted:
			log.Printf("%s: list %v is %v: %v", delivery, event["job_id"], event["status"], event["counts"])
		case verifyinboxes.EventAddressContradicted:
			log.Printf("%s: %v: %v", delivery, event["email"], event["message"])
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
