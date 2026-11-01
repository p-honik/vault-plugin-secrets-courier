package backend

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	hclog "github.com/hashicorp/go-hclog"

	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
)

// These tests model Vault Enterprise replication from the plugin's side: they
// give the backend the replication state and mount locality that Vault would
// report and check what the plugin does. They do NOT test Vault's own
// forwarding, which lives in Enterprise code: a handler or the framework
// returning logical.ErrReadOnly is the signal Vault uses to forward a request to
// the active node, and that part has not been run against a real replicated
// cluster.

// sysView is a system view whose replication state and locality can be set.
type sysView struct {
	logical.StaticSystemView
	state consts.ReplicationState
	local bool
}

func (s *sysView) ReplicationState() consts.ReplicationState { return s.state }
func (s *sysView) LocalMount() bool                          { return s.local }

// nodeAt builds a backend over shared storage, as a node of the given kind.
func nodeAt(t *testing.T, s logical.Storage, state consts.ReplicationState, local bool, now time.Time) *backend {
	t.Helper()
	conf := logical.TestBackendConfig()
	conf.StorageView = s
	conf.System = &sysView{StaticSystemView: logical.StaticSystemView{}, state: state, local: local}
	lb, err := Factory(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}
	b := lb.(*backend)
	b.now = func() time.Time { return now }
	return b
}

func (b *backend) call(s logical.Storage, op logical.Operation, path string, data map[string]interface{}) (*logical.Response, error) {
	return b.HandleRequest(context.Background(), &logical.Request{Operation: op, Path: path, Data: data, Storage: s})
}

func TestReplicationNodeKinds(t *testing.T) {
	const (
		perfStandby   = consts.ReplicationPerformanceStandby
		perfSecondary = consts.ReplicationPerformanceSecondary
		drSecondary   = consts.ReplicationDRSecondary
	)
	cases := []struct {
		name  string
		state consts.ReplicationState
		local bool
		// forwards: the request endpoint returns ErrReadOnly so Vault forwards it
		// to the active node. writable: this node may write storage (admin writes
		// run, the tick rotates, and a request is handled here).
		forwards, writable bool
	}{
		{"primary active node", 0, false, false, true},
		{"performance standby", perfStandby, false, true, false},
		{"performance secondary, replicated mount", perfSecondary, false, true, false},
		{"performance secondary, local mount", perfSecondary, true, false, true},
		{"performance standby of a secondary, local mount", perfSecondary | perfStandby, true, true, false},
		{"DR secondary", drSecondary, false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Prepare shared storage as the primary would have.
			e := newEnv(t)
			rc := newReceiver(t)
			e.configureJWT(nil)
			e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM, "min_request_interval": 0})

			now := e.clock.Add(25 * time.Hour) // a rotation is due
			n := nodeAt(t, e.s, c.state, c.local, now)
			req := map[string]interface{}{"receipt_url": rc.url("/x")}

			// Reads are served on every node, from the replicated storage.
			if resp, err := n.call(e.s, logical.ReadOperation, ".well-known/jwks.json", nil); err != nil || resp.Data[logical.HTTPStatusCode] != 200 {
				t.Fatalf("JWKS read: %v %v", resp, err)
			}
			if resp, err := n.call(e.s, logical.ReadOperation, "roles/r", nil); err != nil || resp == nil {
				t.Fatalf("role read: %v %v", resp, err)
			}

			// The request endpoint: forwarded, handled, or (DR secondary) dropped.
			resp, err := n.call(e.s, logical.UpdateOperation, "request/r", req)
			n.wg.Wait()
			switch {
			case c.forwards:
				if !errors.Is(err, logical.ErrReadOnly) {
					t.Fatalf("request: err = %v, want ErrReadOnly so Vault forwards it", err)
				}
			case err != nil || resp != nil:
				t.Fatalf("request: %v %v, want the empty 204", resp, err)
			}
			delivered := len(rc.received())
			if c.writable && delivered != 1 {
				t.Fatalf("a write-safe node delivered %d times, want 1", delivered)
			}
			if !c.writable && delivered != 0 {
				t.Fatalf("a node that cannot write delivered %d times, want 0", delivered)
			}

			// Administrative writes: ErrReadOnly where storage is read-only.
			for _, w := range []struct {
				op   logical.Operation
				path string
				data map[string]interface{}
			}{
				{logical.UpdateOperation, "config", map[string]interface{}{"max_inflight": 7}},
				{logical.UpdateOperation, "config", map[string]interface{}{"max_ttl": 600}},
				{logical.UpdateOperation, "roles/r", map[string]interface{}{"ttl": 150}},
				{logical.DeleteOperation, "roles/r", nil},
				{logical.UpdateOperation, "keys/rotate", nil},
			} {
				_, err := n.call(e.s, w.op, w.path, w.data)
				if c.writable && err != nil {
					t.Errorf("%s %s on a write-safe node: %v", w.op, w.path, err)
				}
				if !c.writable && !errors.Is(err, logical.ErrReadOnly) {
					t.Errorf("%s %s: err = %v, want ErrReadOnly", w.op, w.path, err)
				}
			}

			// The tick rotates only where it may write.
			e2 := newEnv(t)
			e2.configureJWT(nil)
			first := e2.keySet().Current.KID
			tn := nodeAt(t, e2.s, c.state, c.local, e2.clock.Add(25*time.Hour))
			if err := tn.periodic(context.Background(), &logical.Request{Storage: e2.s}); err != nil {
				t.Fatal(err)
			}
			rotated := e2.keySet().Current.KID != first
			if rotated != c.writable {
				t.Fatalf("tick rotated = %v, want %v", rotated, c.writable)
			}
		})
	}
}

// A standby serves reads from its own cache and learns about a replicated write
// through the Invalidate hook, so it never serves stale keys indefinitely.
func TestStandbyCacheFollowsReplicatedWrites(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	standby := nodeAt(t, e.s, consts.ReplicationPerformanceStandby, false, e.clock)
	kids := func() []string {
		resp, err := standby.call(e.s, logical.ReadOperation, ".well-known/jwks.json", nil)
		if err != nil {
			t.Fatal(err)
		}
		var set struct{ Keys []map[string]interface{} }
		rawBody(t, resp, &set)
		var out []string
		for _, k := range set.Keys {
			out = append(out, k["kid"].(string))
		}
		return out
	}
	before := kids() // primes the standby's cache

	// The primary rotates; replication delivers the new key set to the standby's
	// storage and calls InvalidateKey for it.
	e.ok(logical.UpdateOperation, "keys/rotate", nil)
	if got := kids(); len(got) != len(before) || got[0] != before[0] {
		t.Fatalf("the standby should still serve its cache before the hook fires: %v vs %v", got, before)
	}
	standby.InvalidateKey(context.Background(), storageKeySet)
	after := kids()
	if after[0] == before[0] || len(after) != 3 {
		t.Fatalf("after the Invalidate hook the standby must serve the rotated keys: %v -> %v", before, after)
	}
}

// Step-down and a new active node: the new node starts with a cold cache, reads
// the keys the old one wrote, and its tokens verify with the shared JWKS.
func TestFailoverToANewActiveNode(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t)
	e.configureJWT(nil)
	e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM, "min_request_interval": 0})
	e.request("r", map[string]interface{}{"receipt_url": rc.url("/x")})
	oldKid := e.keySet().Current.KID

	e.b.clean(context.Background()) // the old active node steps down
	next := nodeAt(t, e.s, 0, false, e.clock)
	if _, err := next.call(e.s, logical.UpdateOperation, "request/r", map[string]interface{}{"receipt_url": rc.url("/x")}); err != nil {
		t.Fatal(err)
	}
	next.wg.Wait()
	posts := rc.received()
	if len(posts) != 2 {
		t.Fatalf("got %d deliveries, want 2 (one from each node)", len(posts))
	}
	if e.keySet().Current.KID != oldKid {
		t.Fatal("failover must not replace the keys")
	}
	// The new node's rate-limit state is fresh: memory only, lost on failover.
	if next.state.inflightCount() != 0 {
		t.Fatal("deliveries still in flight on the new node")
	}
}

// A request that reaches a node that cannot write is dropped with the usual 204
// and one warning a minute, so a flood cannot fill the log.
func TestNotWriteSafeWarningIsRateLimited(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t)
	e.configureJWT(nil)
	e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM, "min_request_interval": 0})

	var logs bytes.Buffer
	now := e.clock
	conf := logical.TestBackendConfig()
	conf.StorageView = e.s
	conf.Logger = hclog.New(&hclog.LoggerOptions{Output: &logs, Level: hclog.Warn})
	conf.System = &sysView{state: consts.ReplicationDRSecondary} // reached despite forwarding
	lb, err := Factory(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}
	n := lb.(*backend)
	n.now = func() time.Time { return now }

	req := map[string]interface{}{"receipt_url": rc.url("/x")}
	for i := 0; i < 50; i++ {
		if resp, err := n.call(e.s, logical.UpdateOperation, "request/r", req); resp != nil || err != nil {
			t.Fatalf("drop: %v %v, want the empty 204", resp, err)
		}
	}
	if got := strings.Count(logs.String(), "not write-safe"); got != 1 {
		t.Fatalf("%d warnings for 50 dropped requests, want 1", got)
	}
	now = now.Add(61 * time.Second)
	n.call(e.s, logical.UpdateOperation, "request/r", req)
	if got := strings.Count(logs.String(), "not write-safe"); got != 2 {
		t.Fatalf("%d warnings after a minute, want 2", got)
	}
	if len(rc.received()) != 0 {
		t.Fatal("a node that cannot write delivered")
	}
}
