package backend

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func testBackend(t testing.TB) *backend {
	t.Helper()
	conf := logical.TestBackendConfig()
	conf.StorageView = &logical.InmemStorage{}
	lb, err := Factory(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}
	return lb.(*backend)
}

// Only these two patterns are unauthenticated.
func TestUnauthenticatedPathsAreExact(t *testing.T) {
	got := testBackend(t).PathsSpecial.Unauthenticated
	want := []string{"request/*", ".well-known/*"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Unauthenticated = %v, want %v", got, want)
	}
}

// request/* must forward to the active node, and must be
// defined under Operations so the flags are honored.
func TestRequestPathForwardingFlags(t *testing.T) {
	b := testBackend(t)
	for _, p := range b.Paths {
		if p.Pattern != "request/"+`(?P<role>[^/]+)` {
			continue
		}
		op, ok := p.Operations[logical.UpdateOperation].(*framework.PathOperation)
		if !ok {
			t.Fatal("request path has no UpdateOperation under Operations")
		}
		if !op.ForwardPerformanceStandby || !op.ForwardPerformanceSecondary {
			t.Fatal("request path must set both ForwardPerformance flags")
		}
		return
	}
	t.Fatal("request path not found")
}

// Format errors are a 400, everything else a nil response
// (204). The skeleton implements only the format step.
func TestRequestFormatErrors(t *testing.T) {
	b := testBackend(t)
	do := func(data map[string]interface{}) *logical.Response {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "request/billing-svc",
			Data:      data,
			Storage:   &logical.InmemStorage{},
		})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if r := do(map[string]interface{}{}); r == nil || !r.IsError() {
		t.Error("missing receipt_url must be a 400")
	}
	if r := do(map[string]interface{}{"receipt_url": "https://a.example/x", "nonce": ""}); r == nil || !r.IsError() {
		t.Error("empty nonce must be a 400")
	}
	if r := do(map[string]interface{}{"receipt_url": "https://a.example/x", "nonce": "short"}); r == nil || !r.IsError() {
		t.Error("invalid nonce must be a 400")
	}
	// A well-formed request for an unknown role is a silent drop: nil response.
	if r := do(map[string]interface{}{"receipt_url": "https://a.example/x"}); r != nil {
		t.Errorf("well-formed request returned %v, want nil (204)", r)
	}
}
