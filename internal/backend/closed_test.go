package backend

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// A request that reaches a backend after Clean is dropped with the usual 204, no
// delivery, and one warning: otherwise a host that keeps serving a cleaned-up
// backend would drop every request without a trace.
func TestRequestAfterCleanWarnsOnce(t *testing.T) {
	l := newLeakEnv(t, 0)
	l.n.clean(context.Background())

	const msg = "this backend has been cleaned up"
	for i := 0; i < 3; i++ {
		resp, err := l.n.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation, Path: "request/r",
			Data:    map[string]interface{}{"receipt_url": l.rc.url("/x"), "nonce": "LeakNonce123456789"},
			Storage: l.fs,
		})
		if err != nil || resp != nil {
			t.Fatalf("request %d: want the empty 204, got %v, %v", i, resp, err)
		}
	}
	l.n.wg.Wait()

	if len(l.rc.received()) != 0 {
		t.Fatal("a cleaned-up backend delivered")
	}
	if n := l.n.state.inflightCount(); n != 0 {
		t.Fatalf("%d in-flight slot(s) left after dropped requests", n)
	}
	logged := l.logs.String()
	if n := strings.Count(logged, msg); n != 1 {
		t.Fatalf("the warning appeared %d times, want 1:\n%s", n, logged)
	}
	if jwtShape.MatchString(logged) || strings.Contains(logged, "LeakNonce123456789") {
		t.Fatalf("the warning leaked the token or the nonce:\n%s", logged)
	}
}
