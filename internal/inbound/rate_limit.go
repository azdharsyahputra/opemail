package inbound

import (
	"sync"
	"time"
)

type RateLimitPolicy struct {
	MaxConnectionsPerIP int
	MaxMessagesPerIP    int
	MaxRecipientsPerIP  int
	Window              time.Duration
}

type MemoryRateLimiter struct {
	mu           sync.Mutex
	policy       RateLimitPolicy
	connections  map[string][]time.Time
	messages     map[string][]time.Time
	recipients   map[string]int
	authFailures map[string]int
}

func NewMemoryRateLimiter(policy RateLimitPolicy) *MemoryRateLimiter {
	if policy.Window == 0 {
		policy.Window = time.Minute
	}
	if policy.MaxConnectionsPerIP == 0 {
		policy.MaxConnectionsPerIP = 50
	}
	if policy.MaxMessagesPerIP == 0 {
		policy.MaxMessagesPerIP = 60
	}
	if policy.MaxRecipientsPerIP == 0 {
		policy.MaxRecipientsPerIP = 100
	}

	return &MemoryRateLimiter{
		policy:       policy,
		connections:  make(map[string][]time.Time),
		messages:     make(map[string][]time.Time),
		recipients:   make(map[string]int),
		authFailures: make(map[string]int),
	}
}

func (r *MemoryRateLimiter) AllowConnection(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.policy.Window)

	// Clean older timestamps
	var valid []time.Time
	for _, t := range r.connections[ip] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= r.policy.MaxConnectionsPerIP {
		r.connections[ip] = valid
		return false
	}

	valid = append(valid, now)
	r.connections[ip] = valid
	return true
}

func (r *MemoryRateLimiter) AllowMessage(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.policy.Window)

	var valid []time.Time
	for _, t := range r.messages[ip] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= r.policy.MaxMessagesPerIP {
		r.messages[ip] = valid
		return false
	}

	valid = append(valid, now)
	r.messages[ip] = valid
	return true
}

func (r *MemoryRateLimiter) RecordAuthFailure(ip string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.authFailures[ip]++
	return r.authFailures[ip]
}
