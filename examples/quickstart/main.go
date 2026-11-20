// Quickstart checks one address, then several at once.
//
//	export VERIFYINBOXES_API_KEY="bv_..."
//	go run ./examples/quickstart ann@example.com bob@example.com
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"

	verifyinboxes "github.com/verifyinboxes/verifyinboxes-go"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(addresses []string) int {
	if len(addresses) == 0 {
		fmt.Fprintln(os.Stderr, "usage: quickstart ADDRESS [ADDRESS ...]")
		return 2
	}
	client, err := verifyinboxes.NewClient() // reads VERIFYINBOXES_API_KEY
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// Ctrl-C cancels the context: a check already started is let finish, and the error names it.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	result, err := client.Verify(ctx, addresses[0], nil)
	if err != nil {
		return report(err)
	}
	fmt.Printf("%s: %s (%s), safe to send: %v\n", result.Email, result.Verdict, result.Reason, result.SafeToSend)

	// Several addresses: VerifyMany, never a loop of Verify. Up to 10 are checked together; more go as one list.
	if rest := addresses[1:]; len(rest) > 0 {
		results, err := client.VerifyMany(ctx, rest, nil)
		if err != nil {
			return report(err)
		}
		for _, each := range results {
			fmt.Printf("%s: %s\n", each.Email, each.Verdict)
		}
	}
	return 0
}

// report prints the error (an API error's ends with its request id) and the jobs it names, whatever the error.
func report(err error) int {
	fmt.Fprintln(os.Stderr, err)
	if ids := verifyinboxes.JobIDs(err); len(ids) > 0 {
		// Each job carries on and its credits are held: wait for it again with client.Checks.Wait
		// (a list's with client.Lists.Wait).
		fmt.Fprintln(os.Stderr, "jobs made:", strings.Join(ids, ", "))
	}
	return 1
}
