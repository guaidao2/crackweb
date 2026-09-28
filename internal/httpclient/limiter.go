package httpclient

import (
	"context"
	"math"
	"sync"
	"time"
)

// limiter is a token-bucket rate limiter. A scanner that hammers a target is
// both rude and counter-productive — it trips rate limits and produces timing
// noise that ruins time-based checks — so request pacing is built into the
// client rather than bolted on by callers.
type limiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second; 0 disables limiting
	burst  float64
	tokens float64
	last   time.Time
}

// newLimiter builds a limiter. A non-positive rate disables limiting entirely.
func newLimiter(rate, burst float64) *limiter {
	if rate <= 0 {
		return &limiter{}
	}
	if burst < 1 {
		burst = 1
	}
	return &limiter{
		rate:   rate,
		burst:  burst,
		tokens: burst,
		last:   time.Now(),
	}
}

// Wait blocks until a request may proceed, or until the context is cancelled.
func (l *limiter) Wait(ctx context.Context) error {
	if l == nil || l.rate <= 0 {
		return nil
	}

	l.mu.Lock()
	now := time.Now()
	l.tokens = math.Min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)

	var delay time.Duration
	if l.tokens >= 1 {
		l.tokens--
		l.last = now
	} else {
		// Reserve the token this caller is about to wait for by advancing the
		// clock past the wait. Without this, the time spent waiting would be
		// credited back as fresh tokens on the next call, and the limiter would
		// run at roughly double the requested rate.
		delay = time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		l.tokens = 0
		l.last = now.Add(delay)
	}
	l.mu.Unlock()

	if delay <= 0 {
		return nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
