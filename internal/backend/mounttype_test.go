package backend

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func factoryWith(t *testing.T, options map[string]string) (*backend, error) {
	t.Helper()
	conf := logical.TestBackendConfig()
	conf.StorageView = &logical.InmemStorage{}
	conf.Config = options
	lb, err := Factory(context.Background(), conf)
	if err != nil {
		return nil, err
	}
	return lb.(*backend), nil
}

// The mount option `type` selects the credential type; jwt is the default.
func TestMountOptionSelectsTheType(t *testing.T) {
	for name, opts := range map[string]map[string]string{"unset": nil, "empty": {"type": ""}, "jwt": {"type": "jwt"}} {
		b, err := factoryWith(t, opts)
		if err != nil || b.ctype.name() != "jwt" {
			t.Errorf("%s: %v %v, want the jwt type", name, b, err)
		}
	}
	_, err := factoryWith(t, map[string]string{"type": "tls"})
	if err == nil || !strings.Contains(err.Error(), `"tls"`) || !strings.Contains(err.Error(), "jwt") {
		t.Fatalf("unknown type: %v, want an error naming the type and the supported ones", err)
	}
}

// A mount has one fixed schema: no `type` on roles, and the paths are flat.
func TestFlatPathsAndRolesWithoutAType(t *testing.T) {
	b, _ := factoryWith(t, nil)
	have := map[string]bool{}
	for _, p := range b.Paths {
		have[p.Pattern] = true
		if strings.HasPrefix(p.Pattern, "roles/") {
			if _, has := p.Fields["type"]; has {
				t.Error("a role must not have a type field")
			}
		}
	}
	for _, want := range []string{"config", "keys", "keys/rotate", `\.well-known/openid-configuration`, `\.well-known/jwks\.json`,
		`roles/(?P<name>[^/]+)`, "roles/?$", `request/(?P<role>[^/]+)`} {
		if !have[want] {
			t.Errorf("path %q is missing", want)
		}
	}
	for p := range have {
		if strings.HasPrefix(p, "jwt/") || strings.HasPrefix(p, "role/") {
			t.Errorf("the old layout's path %q is still registered", p)
		}
	}
}

func TestFirstConfigWriteRecordsTheType(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	cfg, exists, err := loadConfig(context.Background(), e.s)
	if err != nil || !exists || cfg.Type != "jwt" {
		t.Fatalf("stored config: %+v %v %v, want type jwt", cfg, exists, err)
	}
	if got := e.ok(logical.ReadOperation, "config", nil).Data["type"]; got != "jwt" {
		t.Fatalf("config read type = %v", got)
	}
}

// If the mount option no longer matches the type recorded with the config, the
// backend refuses to serve: a fixed message on authenticated paths,
// the usual 204 on the request endpoint, the 503 on the public endpoints.
func TestTypeMismatchRefusesToServe(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t)
	e.configureJWT(nil)
	e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM, "min_request_interval": 0})

	// The data was written for another type.
	cfg, _, _ := loadConfig(context.Background(), e.s)
	cfg.Type = "tls"
	if err := putJSON(context.Background(), e.s, storageConfig, cfg); err != nil {
		t.Fatal(err)
	}
	e.b.invalidate()

	for _, p := range []struct {
		op   logical.Operation
		path string
		data map[string]interface{}
	}{
		{logical.ReadOperation, "config", nil},
		{logical.UpdateOperation, "config", map[string]interface{}{"max_inflight": 5}},
		{logical.ReadOperation, "keys", nil},
		{logical.UpdateOperation, "keys/rotate", nil},
		{logical.ReadOperation, "roles/r", nil},
		{logical.UpdateOperation, "roles/r", map[string]interface{}{"ttl": 150}},
		{logical.ListOperation, "roles/", nil},
	} {
		resp, err := e.do(p.op, p.path, p.data)
		if err == nil || !strings.Contains(err.Error(), typeMismatchMessage) || resp != nil {
			t.Errorf("%s %s: %v %v, want the fixed mismatch message", p.op, p.path, resp, err)
		}
	}
	// The request endpoint stays the empty 204 and delivers nothing.
	if resp := e.request("r", map[string]interface{}{"receipt_url": rc.url("/x")}); resp != nil {
		t.Errorf("request: %v, want the empty 204", resp)
	}
	if len(rc.received()) != 0 {
		t.Error("a mount of the wrong type delivered")
	}
	// The public endpoints answer the fixed 503.
	for _, p := range []string{".well-known/jwks.json", ".well-known/openid-configuration"} {
		resp, err := e.do(logical.ReadOperation, p, nil)
		if err != nil || resp.Data[logical.HTTPStatusCode] != 503 {
			t.Errorf("%s: %v %v, want the 503", p, resp, err)
		}
	}
}

// A mount that already holds data and whose type option now names a type this
// build does not support still loads, and refuses to serve; a fresh mount with
// that option is refused outright.
func TestUnsupportedOptionOnAMountWithData(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t)
	e.configureJWT(nil)
	e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM, "min_request_interval": 0})

	conf := logical.TestBackendConfig()
	conf.StorageView = e.s
	conf.Config = map[string]string{"type": "tls"}
	lb, err := Factory(context.Background(), conf)
	if err != nil {
		t.Fatalf("a mount with data must load and refuse to serve, got %v", err)
	}
	n := lb.(*backend)
	n.now = func() time.Time { return e.clock }

	resp, err := n.call(e.s, logical.ReadOperation, "config", nil)
	if err == nil || !strings.Contains(err.Error(), typeMismatchMessage) || resp != nil {
		t.Fatalf("config read: %v %v, want the fixed mismatch message", resp, err)
	}
	if resp, err := n.call(e.s, logical.UpdateOperation, "request/r", map[string]interface{}{"receipt_url": rc.url("/x")}); resp != nil || err != nil {
		t.Fatalf("request: %v %v, want the empty 204", resp, err)
	}
	n.wg.Wait()
	if len(rc.received()) != 0 {
		t.Fatal("a refusing mount delivered")
	}
	resp, err = n.call(e.s, logical.ReadOperation, ".well-known/jwks.json", nil)
	if err != nil || resp.Data[logical.HTTPStatusCode] != 503 {
		t.Fatalf("jwks: %v %v, want the 503", resp, err)
	}

	// An empty mount with the same option is refused when it is enabled.
	conf.StorageView = &logical.InmemStorage{}
	if _, err := Factory(context.Background(), conf); err == nil {
		t.Fatal("a fresh mount with an unsupported type was accepted")
	}
}
