package backend

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestMountConfigDefaultsAndPartialUpdate(t *testing.T) {
	e := newEnv(t)
	r := e.ok(logical.ReadOperation, "config", nil)
	if r.Data["delivery_retry"] != "never" || r.Data["retry_delay"] != 2 || r.Data["delivery_timeout"] != 5 || r.Data["max_inflight"] != 100 {
		t.Fatalf("defaults wrong: %v", r.Data)
	}
	e.configureJWT(map[string]interface{}{"delivery_retry": "once", "allowed_networks": []string{"10.0.0.0/8"}})
	// A later write that sends only one parameter keeps the others.
	e.ok(logical.UpdateOperation, "config", map[string]interface{}{"max_inflight": 7})
	r = e.ok(logical.ReadOperation, "config", nil)
	if r.Data["delivery_retry"] != "once" || r.Data["max_inflight"] != 7 {
		t.Fatalf("partial update lost values: %v", r.Data)
	}
	if got := r.Data["allowed_networks"].([]string); len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Fatalf("allowed_networks = %v", got)
	}
	// Mutually exclusive lists are rejected, and the rejected write changes nothing.
	e.fails(logical.UpdateOperation, "config", map[string]interface{}{"denied_networks": []string{"192.168.0.0/16"}})
	// Switching modes in one write works; [] clears a list.
	e.ok(logical.UpdateOperation, "config", map[string]interface{}{"allowed_networks": []string{}, "denied_networks": []string{"169.254.0.0/16"}})
	r = e.ok(logical.ReadOperation, "config", nil)
	if len(r.Data["allowed_networks"].([]string)) != 0 || len(r.Data["denied_networks"].([]string)) != 1 {
		t.Fatalf("mode switch failed: %v", r.Data)
	}
}

func TestMountConfigValidation(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil) // the first write must include the issuer; these are updates
	for name, data := range map[string]map[string]interface{}{
		"bad retry":     {"delivery_retry": "twice"},
		"zero timeout":  {"delivery_timeout": 0},
		"zero inflight": {"max_inflight": 0},
		"host bits set": {"allowed_networks": []string{"10.0.0.5/8"}},
		"not a cidr":    {"denied_networks": []string{"nope"}},
	} {
		if msg := e.fails(logical.UpdateOperation, "config", data); msg == "" {
			t.Errorf("%s: empty message", name)
		}
	}
}

func TestJWTConfigFirstWriteCreatesKeys(t *testing.T) {
	e := newEnv(t)
	// Before the first write a read shows the delivery defaults and the type, and
	// nothing of the jwt parameters.
	r := e.ok(logical.ReadOperation, "config", nil)
	if r.Data["type"] != "jwt" {
		t.Fatalf("type = %v", r.Data["type"])
	}
	if _, has := r.Data["issuer"]; has {
		t.Fatal("a config that was never written must not report an issuer")
	}
	e.fails(logical.CreateOperation, "config", map[string]interface{}{})                         // issuer required
	e.fails(logical.CreateOperation, "config", map[string]interface{}{"delivery_retry": "once"}) // the first write must include the issuer
	e.fails(logical.CreateOperation, "config", map[string]interface{}{"issuer": "http://vault.example.com/jwt"})
	e.fails(logical.CreateOperation, "config", map[string]interface{}{"issuer": "https://vault.example.com/jwt?x=1"})
	if ks, _ := loadKeySet(context.Background(), e.s); ks != nil {
		t.Fatal("a rejected write must not create keys")
	}

	e.configureJWT(nil)
	ks := e.keySet()
	if ks.Current == nil || ks.Next == nil || ks.Current.KID == ks.Next.KID {
		t.Fatalf("first write must create distinct current and next: %+v", ks)
	}
	if want := e.clock.Add(24 * time.Hour); !ks.NextRotation.Equal(want) {
		t.Errorf("next_rotation = %v, want %v", ks.NextRotation, want)
	}
	if want := e.clock.Add(6 * time.Minute); !ks.Next.NotBefore.Equal(want) {
		t.Errorf("next.not_before = %v, want %v", ks.Next.NotBefore, want)
	}
	if ks.Current.LongestTTL != 30*time.Minute {
		t.Errorf("longest_ttl = %v", ks.Current.LongestTTL)
	}
	r = e.ok(logical.ReadOperation, "config", nil)
	if r.Data["alg"] != "ES256" || r.Data["max_ttl"] != 1800 || r.Data["rotation_period"] != 86400 {
		t.Fatalf("effective values wrong: %v", r.Data)
	}
}

func TestJWTConfigUpdateRules(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	before := e.keySet()

	// Partial update: no issuer needed on later writes.
	e.ok(logical.UpdateOperation, "config", map[string]interface{}{"max_ttl": 600})
	if got := e.ok(logical.ReadOperation, "config", nil).Data["issuer"]; got != "https://vault.example.com/v1/courier" {
		t.Fatalf("issuer lost: %v", got)
	}
	// alg is immutable.
	if msg := e.fails(logical.UpdateOperation, "config", map[string]interface{}{"alg": "RS256"}); !strings.Contains(msg, "alg") {
		t.Fatalf("message = %q", msg)
	}
	// Cross-validation: verification_ttl below max_ttl + 5m + 60s, above 10 x rotation_period, rotation floor.
	e.fails(logical.UpdateOperation, "config", map[string]interface{}{"verification_ttl": 600})
	e.fails(logical.UpdateOperation, "config", map[string]interface{}{"verification_ttl": 86400 * 11})
	e.fails(logical.UpdateOperation, "config", map[string]interface{}{"rotation_period": 300})
	// Keys were not touched by config writes that do not need it.
	after := e.keySet()
	if before.Current.KID != after.Current.KID || before.Next.KID != after.Next.KID {
		t.Fatal("config writes must not rotate keys")
	}
	// longest_ttl is a high-water mark: lowering max_ttl keeps the larger value.
	if after.Current.LongestTTL != 30*time.Minute {
		t.Fatalf("longest_ttl = %v, want 30m", after.Current.LongestTTL)
	}
}

func TestRotationPeriodChangeRecomputesFromLastRotation(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	rotatedAt := e.keySet().Current.RotatedAt
	e.advance(2 * time.Hour)
	e.ok(logical.UpdateOperation, "config", map[string]interface{}{"rotation_period": 3600 * 6, "verification_ttl": 3600})
	ks := e.keySet()
	if want := rotatedAt.Add(6 * time.Hour); !ks.NextRotation.Equal(want) {
		t.Fatalf("next_rotation = %v, want %v (from last rotation, not from now)", ks.NextRotation, want)
	}
	// Lower bound: next.not_before.
	e.ok(logical.UpdateOperation, "config", map[string]interface{}{"rotation_period": 360})
	ks = e.keySet()
	if ks.NextRotation.Before(ks.Next.NotBefore) {
		t.Fatalf("next_rotation %v is before next.not_before %v", ks.NextRotation, ks.Next.NotBefore)
	}
}
