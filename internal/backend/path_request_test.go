package backend

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// panicOnKeySetStorage panics when the key set is read while armed. The request
// handler reads the key set after it has reserved its in-flight slot, so this is
// a panic in the window between reserve and the start of the delivery goroutine.
type panicOnKeySetStorage struct {
	*logical.InmemStorage
	armed atomic.Bool
}

func (p *panicOnKeySetStorage) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	if p.armed.Load() && key == storageKeySet {
		panic("boom after reserve")
	}
	return p.InmemStorage.Get(ctx, key)
}

// A panic after the reservation was taken (the guard recovers it) must release
// the in-flight slot and restore the rate-limit timer, exactly as an error
// return does. Otherwise each such panic leaks a max_inflight slot for good and
// locks the requester out for min_request_interval.
func TestPanicAfterReserveReleasesTheReservation(t *testing.T) {
	e := newEnv(t)
	ps := &panicOnKeySetStorage{InmemStorage: &logical.InmemStorage{}}
	e.s = ps
	rc := newReceiver(t)
	e.configureJWT(nil)
	e.createRole("r", map[string]interface{}{
		"allowed_receipt_urls": []string{rc.url("/x")},
		"receipt_ca_pem":       rc.caPEM,
		"min_request_interval": 3600,
	})
	req := map[string]interface{}{"receipt_url": rc.url("/x"), "nonce": "k3Jx9wQ2mZpL7vTa"}

	e.b.invalidate()
	ps.armed.Store(true)
	resp, err := e.do(logical.UpdateOperation, "request/r", req)
	e.b.wg.Wait()
	if err != nil || resp != nil {
		t.Fatalf("the caller must get the empty 204 even when the handler panics: %v, %v", resp, err)
	}
	if n := e.b.state.inflightCount(); n != 0 {
		t.Fatalf("a panic after reserve leaked %d in-flight slot(s)", n)
	}
	if _, locked := e.b.state.lastAccepted[roleURL{"r", rc.url("/x")}]; locked {
		t.Fatal("a panic after reserve left the rate-limit timer behind")
	}
	if len(rc.received()) != 0 {
		t.Fatal("a request whose handler panicked was delivered")
	}

	// The requester is not locked out: the same request works once the fault is gone.
	ps.armed.Store(false)
	e.b.invalidate()
	e.request("r", req)
	if len(rc.received()) != 1 {
		t.Fatal("the request did not work after the panic: the slot or the timer stayed reserved")
	}
}
