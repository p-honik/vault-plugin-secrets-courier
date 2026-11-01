package backend

import (
	"sync"
	"time"
)

// rateState is the in-memory rate-limit and in-flight state. It lives only in the
// backend, never
// in storage, behind its own mutex, which is never held together with the
// configuration lock. It is lost on restart and failover by design.
//
// Only a fully accepted request touches the state. All checks and the commit
// happen in one critical section, and every drop leaves the state exactly as it
// was.
type rateState struct {
	mu           sync.Mutex
	lastAccepted map[roleURL]time.Time    // for min_request_interval
	inflight     map[inflightKey]struct{} // its size is the max_inflight count
}

type roleURL struct{ role, receiptURL string }

type inflightKey struct{ role, receiptURL, nonce string }

func newRateState() *rateState {
	return &rateState{
		lastAccepted: make(map[roleURL]time.Time),
		inflight:     make(map[inflightKey]struct{}),
	}
}

// reservation is a committed request. Exactly one of abort or finish must be
// called.
type reservation struct {
	s       *rateState
	ru      roleURL
	ik      inflightKey
	prev    time.Time
	hadPrev bool
}

// reserve applies the checks in this order: the interval for
// (role, receipt URL), a duplicate of a delivery already in flight (same role,
// URL and nonce), then max_inflight. If all pass it commits the timer and the
// in-flight entry together and returns the reservation. Callers have already
// validated the format, found the role and matched the allowlist, so a request
// dropped earlier never allocates anything here.
func (s *rateState) reserve(role, receiptURL, nonce string, now time.Time, interval time.Duration, maxInflight int) (*reservation, bool) {
	ru := roleURL{role, receiptURL}
	ik := inflightKey{role, receiptURL, nonce}

	s.mu.Lock()
	defer s.mu.Unlock()

	prev, hadPrev := s.lastAccepted[ru]
	if hadPrev && interval > 0 && now.Sub(prev) < interval {
		return nil, false
	}
	if _, dup := s.inflight[ik]; dup {
		return nil, false
	}
	if len(s.inflight) >= maxInflight {
		return nil, false
	}
	s.lastAccepted[ru] = now
	s.inflight[ik] = struct{}{}
	return &reservation{s: s, ru: ru, ik: ik, prev: prev, hadPrev: hadPrev}, true
}

// abort releases a reservation whose request failed before the delivery
// started (for example signing failed): the previous timestamp is restored, so
// an internal fault never locks a requester out.
func (r *reservation) abort() {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	delete(r.s.inflight, r.ik)
	if r.hadPrev {
		r.s.lastAccepted[r.ru] = r.prev
	} else {
		delete(r.s.lastAccepted, r.ru)
	}
}

// finish ends the in-flight entry when the delivery goroutine ends. The timer
// stays: a failed delivery was still accepted and attempted.
func (r *reservation) finish() {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	delete(r.s.inflight, r.ik)
}

// empty reports whether there is nothing to evict.
func (s *rateState) empty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.lastAccepted) == 0
}

// inflightCount is the number of deliveries in progress.
func (s *rateState) inflightCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.inflight)
}

// evict removes last_accepted entries whose interval has elapsed or whose role
// or URL no longer exists. interval returns the role's current
// min_request_interval and false when the role or URL is gone. Called by the
// one-minute tick; harmless on nodes that are not active.
func (s *rateState) evict(now time.Time, interval func(role, receiptURL string) (time.Duration, bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ru, at := range s.lastAccepted {
		d, ok := interval(ru.role, ru.receiptURL)
		if !ok || now.Sub(at) >= d {
			delete(s.lastAccepted, ru)
		}
	}
}

// reset clears all state; called from Clean on step-down.
func (s *rateState) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastAccepted = make(map[roleURL]time.Time)
	s.inflight = make(map[inflightKey]struct{})
}
