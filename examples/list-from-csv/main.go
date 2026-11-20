// List-from-csv verifies a CSV of addresses as a list: it starts the list, waits for it, reads the results and
// downloads the CSV with them.
//
//	export VERIFYINBOXES_API_KEY="bv_..."
//	go run ./examples/list-from-csv prospects.csv email
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	verifyinboxes "github.com/verifyinboxes/verifyinboxes-go"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: list-from-csv FILE.csv [EMAIL_COLUMN]")
		os.Exit(2)
	}
	column := "email"
	if len(os.Args) > 2 {
		column = os.Args[2]
	}
	if err := run(os.Args[1], column); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path, column string) error {
	client, err := verifyinboxes.NewClient()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	created, err := client.Lists.CreateFromFile(ctx, path, &verifyinboxes.CreateListParams{EmailColumn: column})
	if err != nil {
		return err
	}
	fmt.Printf("list %s: %d addresses\n", created.ID, created.Total)

	// A few hundred addresses take minutes, Microsoft-hosted ones longer. If this stops, the list carries on: wait
	// for it again with client.Lists.Wait(ctx, created.ID, nil).
	job, err := client.Lists.Wait(ctx, created.ID, nil)
	if err != nil {
		return err
	}
	fmt.Printf("%s: %d of %d done\n", job.Status, job.Done, job.Total)

	byVerdict := map[verifyinboxes.Verdict]int{}
	safe := 0
	rows := client.Lists.Results(ctx, created.ID, nil)
	for rows.Next() {
		row := rows.Current()
		byVerdict[row.Verdict]++
		if row.SafeToSend {
			safe++
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	fmt.Printf("%d safe to send; by verdict: %v\n", safe, byVerdict)

	written, err := client.Lists.DownloadFile(ctx, created.ID, "results.csv", nil)
	if err != nil {
		return err
	}
	fmt.Printf("saved results.csv (%d bytes)\n", written)
	return nil
}
