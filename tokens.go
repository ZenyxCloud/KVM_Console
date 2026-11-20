package main

import (
	"crypto/rand"
	"errors"
	"net/netip"
	"sync"
	"time"
)

const tokenAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var errTooManyTokens = errors.New("too many pending console tokens")

type Target struct {
	URL            string
	AuthToken      string
	Node           string
	Kind           string
	VMID           string
	ClientIP       netip.Addr
	TLSFingerprint string
}

type tokenEntry struct {
	target  Target
	expires time.Time
}

type TokenStore struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	nextID  uint64
	entries map[string]tokenEntry
	now     func() time.Time
}

func NewTokenStore(ttl time.Duration, max int) *TokenStore {
	return &TokenStore{ttl: ttl, max: max, entries: map[string]tokenEntry{}, now: time.Now}
}

func (s *TokenStore) Issue(t Target) (string, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	if len(s.entries) >= s.max {
		return "", 0, errTooManyTokens
	}
	for {
		tok, err := randomToken(32)
		if err != nil {
			return "", 0, err
		}
		if _, exists := s.entries[tok]; exists {
			continue
		}
		s.nextID++
		s.entries[tok] = tokenEntry{target: t, expires: s.now().Add(s.ttl)}
		return tok, s.nextID, nil
	}
}

func (s *TokenStore) Redeem(tok string) (Target, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[tok]
	if !ok {
		return Target{}, false
	}
	delete(s.entries, tok)
	if !s.now().Before(e.expires) {
		return Target{}, false
	}
	return e.target, true
}

func (s *TokenStore) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *TokenStore) Purge() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
}

func (s *TokenStore) purgeLocked() {
	now := s.now()
	for k, e := range s.entries {
		if !now.Before(e.expires) {
			delete(s.entries, k)
		}
	}
}

func randomToken(n int) (string, error) {
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	limit := byte(256 - 256%len(tokenAlphabet))
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b >= limit {
				continue
			}
			out = append(out, tokenAlphabet[int(b)%len(tokenAlphabet)])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
}

func validToken(tok string) bool {
	if len(tok) != 32 {
		return false
	}
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
