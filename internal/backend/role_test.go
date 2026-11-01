package backend

import (
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestRoleRequiresJWTConfig(t *testing.T) {
	e := newEnv(t)
	msg := e.fails(logical.CreateOperation, "roles/billing-svc", map[string]interface{}{
		"allowed_receipt_urls": []string{"https://billing.internal/x"}, "aud": "a",
	})
	if !strings.Contains(msg, "config") {
		t.Fatalf("message = %q", msg)
	}
}

func TestRoleCreateReadListDelete(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	e.createRole("billing-svc", map[string]interface{}{"require_nonce": true, "nonce_in_token": true})
	e.createRole("a", nil)

	r := e.ok(logical.ReadOperation, "roles/billing-svc", nil)
	if r.Data["aud"] != "payments-api" || r.Data["ttl"] != 600 ||
		r.Data["min_request_interval"] != 5 || r.Data["require_nonce"] != true || r.Data["nonce_in_token"] != true {
		t.Fatalf("role = %v", r.Data)
	}
	// URLs are stored exactly as submitted.
	if urls := r.Data["allowed_receipt_urls"].([]string); len(urls) != 1 || urls[0] != "https://billing.internal/courier/receive" {
		t.Fatalf("urls = %v", urls)
	}

	l := e.ok(logical.ListOperation, "roles/", nil)
	keys := l.Data["keys"].([]string)
	sort.Strings(keys)
	if len(keys) != 2 || keys[0] != "a" || keys[1] != "billing-svc" {
		t.Fatalf("list = %v", keys)
	}

	e.ok(logical.DeleteOperation, "roles/billing-svc", nil)
	if resp, _ := e.do(logical.ReadOperation, "roles/billing-svc", nil); resp != nil {
		t.Fatal("deleted role must read as not found")
	}
}

func TestRolePartialUpdateAndNoTypeField(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	e.createRole("billing-svc", nil)
	e.ok(logical.UpdateOperation, "roles/billing-svc", map[string]interface{}{"ttl": 120})
	r := e.ok(logical.ReadOperation, "roles/billing-svc", nil)
	if r.Data["ttl"] != 120 || r.Data["aud"] != "payments-api" || len(r.Data["allowed_receipt_urls"].([]string)) != 1 {
		t.Fatalf("partial update lost values: %v", r.Data)
	}
	// A role carries no type: the mount has one, and a role holds exactly the
	// fields of that type.
	if _, has := r.Data["type"]; has {
		t.Fatalf("a role must not report a type: %v", r.Data)
	}
}

func TestRoleNameRule(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	for _, bad := range []string{"Billing", "a.b", "-a", "a-", strings.Repeat("a", 65)} {
		e.fails(logical.CreateOperation, "roles/"+bad, map[string]interface{}{
			"allowed_receipt_urls": []string{"https://billing.internal/x"}, "aud": "a",
		})
		// Read and delete of a non-conforming name are simply not found.
		if resp, _ := e.do(logical.ReadOperation, "roles/"+bad, nil); resp != nil {
			t.Errorf("read %q should be not found", bad)
		}
		e.ok(logical.DeleteOperation, "roles/"+bad, nil)
	}
}

func TestRoleValidation(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil) // max_ttl 30m
	base := func(extra map[string]interface{}) map[string]interface{} {
		d := map[string]interface{}{"allowed_receipt_urls": []string{"https://billing.internal/x"}, "aud": "a"}
		for k, v := range extra {
			d[k] = v
		}
		return d
	}
	urls := make([]string, maxReceiptURLs+1)
	for i := range urls {
		urls[i] = "https://billing.internal/x"
	}
	cases := map[string]map[string]interface{}{
		"missing urls":      {"allowed_receipt_urls": []string{}},
		"too many urls":     {"allowed_receipt_urls": urls},
		"http url":          {"allowed_receipt_urls": []string{"http://billing.internal/x"}},
		"query in url":      {"allowed_receipt_urls": []string{"https://billing.internal/x?a=b"}},
		"missing aud":       {"aud": ""},
		"ttl above max":     {"ttl": 1801},
		"ttl zero":          {"ttl": 0},
		"ttl below window":  {"ttl": 5}, // delivery_timeout defaults to 5s: ttl must exceed it
		"negative interval": {"min_request_interval": -1},
		"bad ca":            {"receipt_ca_pem": "not pem"},
	}
	for name, extra := range cases {
		if msg := e.fails(logical.CreateOperation, "roles/billing-svc", base(extra)); msg == "" {
			t.Errorf("%s: empty message", name)
		}
	}
	if resp, _ := e.do(logical.ReadOperation, "roles/billing-svc", nil); resp != nil {
		t.Fatal("a rejected write must not store a role")
	}
}

func TestCrossValidationBetweenConfigsAndRoles(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	e.createRole("billing-svc", map[string]interface{}{"ttl": 600})
	e.createRole("short", map[string]interface{}{"ttl": 150})

	// Lowering max_ttl below an existing role's ttl is rejected.
	e.fails(logical.UpdateOperation, "config", map[string]interface{}{"max_ttl": 300, "verification_ttl": 3600})
	// A delivery window of 180s ("once", 60s + 2 x 60s) is not below the ttl of "short" (150s).
	e.fails(logical.UpdateOperation, "config", map[string]interface{}{"delivery_retry": "once", "delivery_timeout": 60, "retry_delay": 60})
	// A window of 122s ("once", 2s + 2 x 60s) is fine for "short", and then a new
	// role with ttl 120 does not exceed it, while 123 does.
	e.ok(logical.UpdateOperation, "config", map[string]interface{}{"delivery_retry": "once", "delivery_timeout": 60})
	e.fails(logical.CreateOperation, "roles/tight", map[string]interface{}{
		"allowed_receipt_urls": []string{"https://billing.internal/x"}, "aud": "a", "ttl": 120,
	})
	e.createRole("ok", map[string]interface{}{"ttl": 123})
}

func TestRoleParameterBounds(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	pem := (newReceiver(t)).caPEM
	base := func(extra map[string]interface{}) map[string]interface{} {
		d := map[string]interface{}{"allowed_receipt_urls": []string{"https://billing.internal/x"}, "aud": "a"}
		for k, v := range extra {
			d[k] = v
		}
		return d
	}
	e.ok(logical.CreateOperation, "roles/edge", base(map[string]interface{}{
		"ttl": 120, "min_request_interval": 3600, "aud": strings.Repeat("a", 256), "receipt_ca_pem": pem,
	}))
	for name, extra := range map[string]map[string]interface{}{
		"ttl below 2m":       {"ttl": 119},
		"interval above 1h":  {"min_request_interval": 3601},
		"aud too long":       {"aud": strings.Repeat("a", 257)},
		"aud control char":   {"aud": "a\nb"},
		"duplicate url":      {"allowed_receipt_urls": []string{"https://billing.internal/x", "https://billing.internal/x"}},
		"ca not certificate": {"receipt_ca_pem": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"},
		"ca trailing data":   {"receipt_ca_pem": pem + "junk"},
		"ca with a key":      {"receipt_ca_pem": pem + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"},
		"ca too large":       {"receipt_ca_pem": pem + strings.Repeat("\n", maxCAPEMBytes)},
	} {
		if msg := e.fails(logical.CreateOperation, "roles/bad", base(extra)); msg == "" {
			t.Errorf("%s: empty message", name)
		}
	}
}

func TestDefaultTTLResolvesToMinOfTenMinutesAndMaxTTL(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(map[string]interface{}{"max_ttl": 300, "verification_ttl": 3600}) // 5m < 10m
	e.createRole("r", nil)
	if got := e.ok(logical.ReadOperation, "roles/r", nil).Data["ttl"]; got != 300 {
		t.Fatalf("ttl = %v, want the resolved default min(10m, max_ttl) = 300", got)
	}
	// Raising max_ttl later does not change the stored value.
	e.ok(logical.UpdateOperation, "config", map[string]interface{}{"max_ttl": 1800})
	if got := e.ok(logical.ReadOperation, "roles/r", nil).Data["ttl"]; got != 300 {
		t.Fatalf("ttl = %v, the resolved value must be stored", got)
	}

	// A default that is below 2 minutes is rejected with a message to set ttl.
	e2 := newEnv(t)
	e2.configureJWT(map[string]interface{}{"max_ttl": 60, "verification_ttl": 3600})
	msg := e2.fails(logical.CreateOperation, "roles/r", map[string]interface{}{
		"allowed_receipt_urls": []string{"https://billing.internal/x"}, "aud": "a",
	})
	if !strings.Contains(msg, "set ttl") {
		t.Fatalf("message = %q", msg)
	}
}

func TestMountAndIssuerBounds(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	for name, data := range map[string]map[string]interface{}{
		"retry_delay 0":       {"retry_delay": 0},
		"retry_delay 61":      {"retry_delay": 61},
		"delivery_timeout 61": {"delivery_timeout": 61},
		"max_inflight 10001":  {"max_inflight": 10001},
	} {
		if msg := e.fails(logical.UpdateOperation, "config", data); msg == "" {
			t.Errorf("%s: empty message", name)
		}
	}
	e.ok(logical.UpdateOperation, "config", map[string]interface{}{"retry_delay": 60, "delivery_timeout": 1, "max_inflight": 10000})

	for name, issuer := range map[string]string{
		"userinfo":       "https://user@vault.example.com/jwt",
		"trailing slash": "https://vault.example.com/jwt/",
		"too long":       "https://vault.example.com/" + strings.Repeat("a", 2048),
	} {
		if msg := e.fails(logical.UpdateOperation, "config", map[string]interface{}{"issuer": issuer}); msg == "" {
			t.Errorf("%s: empty message", name)
		}
	}
}

func TestDurationsAreTruncatedAndErrorsNameTheEffectiveValue(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	base := map[string]interface{}{"allowed_receipt_urls": []string{"https://billing.internal/x"}, "aud": "a"}
	with := func(ttl interface{}) map[string]interface{} {
		d := map[string]interface{}{}
		for k, v := range base {
			d[k] = v
		}
		d["ttl"] = ttl
		return d
	}
	// 119500ms truncates to 1m59s, which is below the 2m minimum.
	if msg := e.fails(logical.CreateOperation, "roles/r", with("119500ms")); !strings.Contains(msg, "1m59s") {
		t.Fatalf("message = %q, want the effective value 1m59s", msg)
	}
	// 1.9s style input is truncated, not rejected, when the result is in bounds.
	e.ok(logical.CreateOperation, "roles/r", with("120500ms"))
	if got := e.ok(logical.ReadOperation, "roles/r", nil).Data["ttl"]; got != 120 {
		t.Fatalf("stored ttl = %v, want 120 (truncated)", got)
	}
	e.ok(logical.UpdateOperation, "config", map[string]interface{}{"retry_delay": "1.9s"})
	if got := e.ok(logical.ReadOperation, "config", nil).Data["retry_delay"]; got != 1 {
		t.Fatalf("retry_delay = %v, want 1", got)
	}
	// 500ms truncates to 0 and is rejected by the lower bound.
	e.fails(logical.UpdateOperation, "config", map[string]interface{}{"retry_delay": "500ms"})
}
