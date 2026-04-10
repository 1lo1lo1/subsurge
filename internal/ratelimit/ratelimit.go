package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a simple token-bucket rate limiter.
type Limiter struct {
	mu       sync.Mutex
	rate     time.Duration // minimum time between requests
	lastTick time.Time
}

// New creates a Limiter that allows rps requests per second.
// rps <= 0 means unlimited.
func New(rps float64) *Limiter {
	if rps <= 0 {
		return &Limiter{}
	}
	return &Limiter{rate: time.Duration(float64(time.Second) / rps)}
}

// Wait blocks until a new request is allowed.
func (l *Limiter) Wait() {
	if l.rate == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.lastTick.IsZero() {
		l.lastTick = now
		return
	}
	next := l.lastTick.Add(l.rate)
	if now.Before(next) {
		time.Sleep(next.Sub(now))
	}
	l.lastTick = time.Now()
}
