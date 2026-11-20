package verifyinboxes

import (
	"context"
	"time"
)

// SetHooks replaces the client's sleep, clock and jitter (each when not nil), so that a test can see every pause
// and move time itself. It exists for this package's tests only.
func SetHooks(c *Client, sleep func(context.Context, time.Duration) error, now func() time.Time, jitter func() float64) {
	if sleep != nil {
		c.sleep = sleep
	}
	if now != nil {
		c.now = now
	}
	if jitter != nil {
		c.jitter = jitter
	}
}
