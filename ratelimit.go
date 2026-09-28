package main

import (
	"sync"
	"time"
)

// rateLimiter is a per-client-IP token bucket used to limit abuse of
// unauthenticated (keyless) instances.
type rateLimiter struct {
	mu       sync.Mutex
	rate     float64 // tokens per second
	burst    float64
	visitors map[string]*visitor
	maxIdle  time.Duration
}

type visitor struct {
	tokens float64
	last   time.Time
}

// newRateLimiter creates a limiter allowing perMinute requests per minute
// per client IP with a burst of the same size.
func newRateLimiter(perMinute uint) *rateLimiter {
	return &rateLimiter{
		rate:     float64(perMinute) / 60.0,
		burst:    float64(perMinute),
		visitors: make(map[string]*visitor),
		maxIdle:  10 * time.Minute,
	}
}

// allow reports whether a request from ip may proceed.
func (l *rateLimiter) allow(ip string) bool {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	// opportunistic cleanup of stale entries to bound memory
	if len(l.visitors) > 4096 {
		for k, v := range l.visitors {
			if now.Sub(v.last) > l.maxIdle {
				delete(l.visitors, k)
			}
		}
	}

	v := l.visitors[ip]
	if v == nil {
		v = &visitor{tokens: l.burst}
		l.visitors[ip] = v
	}
	v.tokens += l.rate * now.Sub(v.last).Seconds()
	if v.tokens > l.burst {
		v.tokens = l.burst
	}
	v.last = now

	if v.tokens < 1 {
		return false
	}
	v.tokens--
	return true
}
