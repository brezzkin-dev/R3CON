package core

import (
	"context"
	"sync"
	"time"
)

type RateLimiter struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64
	last     time.Time
}

func NewRateLimiter(capacity, perSecond float64) *RateLimiter {
	return &RateLimiter{
		tokens:   capacity,
		capacity: capacity,
		rate:     perSecond,
		last:     time.Now(),
	}
}

func (r *RateLimiter) Wait(ctx context.Context) error {
	for {
		r.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(r.last).Seconds()
		r.tokens = minf(r.capacity, r.tokens+elapsed*r.rate)
		r.last = now
		if r.tokens >= 1 {
			r.tokens -= 1
			r.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - r.tokens) / r.rate * float64(time.Second))
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}