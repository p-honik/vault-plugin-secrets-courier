package backend

import (
	"context"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestWellKnown404BeforeConfig(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{".well-known/openid-configuration", ".well-known/jwks.json"} {
		if got := rawBody(t, e.ok(logical.ReadOperation, p, nil), nil); got != 404 {
			t.Errorf("%s: status %d, want 404", p, got)
		}
	}
}

func TestWellKnown404WithOrphanedKeys(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	// Simulate a crash between storing the key set and the config.
	if err := e.s.Delete(context.Background(), storageConfig); err != nil {
		t.Fatal(err)
	}
	e.b.invalidate() // storage was changed behind the backend's back
	if got := rawBody(t, e.ok(logical.ReadOperation, ".well-known/jwks.json", nil), nil); got != 404 {
		t.Fatalf("orphaned keys must not be published, status %d", got)
	}
	// A retry finds the keys, skips creation and requires a matching alg.
	before := e.keySet().Current.KID
	e.fails(logical.CreateOperation, "config", map[string]interface{}{"issuer": "https://v.example/jwt", "alg": "RS256"})
	e.configureJWT(nil)
	if e.keySet().Current.KID != before {
		t.Fatal("retry must keep the existing keys")
	}
}

func TestDiscoveryAndJWKS(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)

	resp := e.ok(logical.ReadOperation, ".well-known/openid-configuration", nil)
	var disc map[string]interface{}
	if rawBody(t, resp, &disc) != 200 || resp.Data[logical.HTTPContentType] != "application/json" {
		t.Fatalf("discovery response wrong: %v", resp.Data)
	}
	if disc["issuer"] != "https://vault.example.com/v1/courier" ||
		disc["jwks_uri"] != "https://vault.example.com/v1/courier/.well-known/jwks.json" {
		t.Fatalf("discovery = %v", disc)
	}
	if algs := disc["id_token_signing_alg_values_supported"].([]interface{}); len(algs) != 1 || algs[0] != "ES256" {
		t.Fatalf("discovery lists %v, want only the configured alg", algs)
	}

	resp = e.ok(logical.ReadOperation, ".well-known/jwks.json", nil)
	var jwks struct{ Keys []map[string]interface{} }
	if rawBody(t, resp, &jwks) != 200 {
		t.Fatal("jwks status")
	}
	if resp.Data[logical.HTTPCacheControlHeader] != "max-age=300" {
		t.Fatalf("Cache-Control = %v", resp.Data[logical.HTTPCacheControlHeader])
	}
	if len(jwks.Keys) != 2 {
		t.Fatalf("want current and next, got %d keys", len(jwks.Keys))
	}
	for _, k := range jwks.Keys {
		got := keysOf(k)
		want := []string{"alg", "crv", "kid", "kty", "use", "x", "y"}
		if !equal(got, want) {
			t.Errorf("ES256 JWKS members = %v, want %v (no private members)", got, want)
		}
		if k["kty"] != "EC" || k["crv"] != "P-256" || k["use"] != "sig" || k["alg"] != "ES256" {
			t.Errorf("key = %v", k)
		}
	}
}

func TestJWKSMembersRS256(t *testing.T) {
	if testing.Short() {
		t.Skip("RSA key generation")
	}
	e := newEnv(t)
	e.configureJWT(map[string]interface{}{"alg": "RS256"})
	var jwks struct{ Keys []map[string]interface{} }
	rawBody(t, e.ok(logical.ReadOperation, ".well-known/jwks.json", nil), &jwks)
	for _, k := range jwks.Keys {
		if got, want := keysOf(k), []string{"alg", "e", "kid", "kty", "n", "use"}; !equal(got, want) {
			t.Errorf("RS256 JWKS members = %v, want %v", got, want)
		}
		if k["e"] != "AQAB" || k["alg"] != "RS256" {
			t.Errorf("key = %v", k)
		}
	}
	// The discovery document lists the configured alg.
	var disc map[string]interface{}
	rawBody(t, e.ok(logical.ReadOperation, ".well-known/openid-configuration", nil), &disc)
	if algs := disc["id_token_signing_alg_values_supported"].([]interface{}); algs[0] != "RS256" {
		t.Fatalf("discovery = %v", disc)
	}
}

func TestScheduledRotation(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	first := e.keySet()

	e.tick() // nothing is due
	if got := e.keySet(); got.Current.KID != first.Current.KID {
		t.Fatal("tick rotated early")
	}

	e.advance(24*time.Hour + time.Minute)
	e.tick()
	ks := e.keySet()
	if ks.Current.KID != first.Next.KID {
		t.Fatalf("next must become current with the same kid: current %s, old next %s", ks.Current.KID, first.Next.KID)
	}
	if ks.Next.KID == first.Next.KID || ks.Next.KID == first.Current.KID {
		t.Fatal("a new next must be generated")
	}
	if len(ks.Previous) != 1 || ks.Previous[0].KID != first.Current.KID {
		t.Fatalf("old current must move to previous: %+v", ks.Previous)
	}
	// retire_at = now + max(verification_ttl 1h, longest_ttl 30m + 5m + 60s).
	if want := e.clock.Add(time.Hour); !ks.Previous[0].RetireAt.Equal(want) {
		t.Errorf("retire_at = %v, want %v", ks.Previous[0].RetireAt, want)
	}
	if want := e.clock.Add(24 * time.Hour); !ks.NextRotation.Equal(want) {
		t.Errorf("next_rotation = %v, want %v", ks.NextRotation, want)
	}
	if want := e.clock.Add(6 * time.Minute); !ks.Next.NotBefore.Equal(want) {
		t.Errorf("next.not_before = %v, want %v", ks.Next.NotBefore, want)
	}
	if string(ks.Previous[0].Public) == "" || containsPrivate(ks.Previous[0].Public) {
		t.Error("a previous entry must hold the public key only")
	}
	if ids := jwksKIDs(t, e); len(ids) != 3 {
		t.Fatalf("JWKS should hold current, next and previous: %v", ids)
	}

	// The retired key leaves the JWKS after retire_at, even if no rotation is due.
	e.advance(61 * time.Minute)
	e.tick()
	if got := e.keySet(); len(got.Previous) != 0 {
		t.Fatalf("expired retired key not dropped: %+v", got.Previous)
	}
	if ids := jwksKIDs(t, e); len(ids) != 2 {
		t.Fatalf("JWKS should hold current and next: %v", ids)
	}
}

func TestMissedRotationCatchesUpOnce(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	first := e.keySet()
	e.advance(10 * 24 * time.Hour)
	e.tick()
	ks := e.keySet()
	if ks.Current.KID != first.Next.KID || len(ks.Previous) != 1 {
		t.Fatal("a long outage must catch up with exactly one rotation")
	}
	e.tick()
	if e.keySet().Current.KID != ks.Current.KID {
		t.Fatal("a second tick must be a no-op")
	}
}

func TestTickWaitsForNotBefore(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	e.advance(time.Hour)
	// Shorten the period so next_rotation is in the past, but next.not_before is
	// still pending after a manual rotation (fresh next gets now + 6 minutes).
	e.ok(logical.UpdateOperation, "config", map[string]interface{}{"rotation_period": 360, "verification_ttl": 3600})
	e.ok(logical.UpdateOperation, "keys/rotate", nil)
	kid := e.keySet().Current.KID
	e.advance(3 * time.Minute)
	e.tick()
	if e.keySet().Current.KID != kid {
		t.Fatal("tick must not rotate before next.not_before")
	}
	e.advance(5 * time.Minute)
	e.tick()
	if e.keySet().Current.KID == kid {
		t.Fatal("tick must rotate once both next_rotation and next.not_before have passed")
	}
}

func TestManualRotation(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	first := e.keySet()

	e.ok(logical.UpdateOperation, "keys/rotate", nil)
	ks := e.keySet()
	if ks.Current.KID == first.Current.KID || ks.Current.KID == first.Next.KID {
		t.Fatal("manual rotation must install a fresh key, never promote the stored next")
	}
	if ks.Next.KID == first.Next.KID {
		t.Fatal("the stored next must be discarded and replaced")
	}
	if len(ks.Previous) != 1 || ks.Previous[0].KID != first.Current.KID {
		t.Fatalf("previous = %+v", ks.Previous)
	}

	// revoke_previous drops every retired key, including the one just replaced.
	e.ok(logical.UpdateOperation, "keys/rotate", map[string]interface{}{"revoke_previous": true})
	ks = e.keySet()
	if len(ks.Previous) != 0 {
		t.Fatalf("revoke_previous left %+v", ks.Previous)
	}
	if ids := jwksKIDs(t, e); len(ids) != 2 {
		t.Fatalf("JWKS = %v", ids)
	}
}

func TestKeysReadNeverReturnsPrivateKeys(t *testing.T) {
	e := newEnv(t)
	if resp, _ := e.do(logical.ReadOperation, "keys", nil); resp != nil {
		t.Fatal("keys must read as not found before configuration")
	}
	e.configureJWT(nil)
	e.ok(logical.UpdateOperation, "keys/rotate", nil)
	r := e.ok(logical.ReadOperation, "keys", nil)
	b, _ := json.Marshal(r.Data)
	if containsPrivate(b) {
		t.Fatalf("response leaks private material: %s", b)
	}
	ks := e.keySet()
	if r.Data["current_kid"] != ks.Current.KID || r.Data["next_kid"] != ks.Next.KID {
		t.Fatalf("kids = %v", r.Data)
	}
	if len(r.Data["retired"].([]map[string]interface{})) != 1 {
		t.Fatalf("retired = %v", r.Data["retired"])
	}
}

func TestRotateRequiresConfiguration(t *testing.T) {
	e := newEnv(t)
	e.fails(logical.UpdateOperation, "keys/rotate", nil)
}

func TestSignAndVerifyWithPublishedKey(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	ks := e.keySet()
	snap := &keySnapshot{keySet: ks}
	key, err := snap.signingKey("ES256")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign([]byte(`{"hello":"world"}`))
	if err != nil {
		t.Fatal(err)
	}
	compact, _ := obj.CompactSerialize()
	parsed, err := jose.ParseSignedCompact(compact, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Signatures[0].Header.KeyID != ks.Current.KID {
		t.Fatalf("kid header = %q", parsed.Signatures[0].Header.KeyID)
	}
	var pub jose.JSONWebKey
	if err := pub.UnmarshalJSON(ks.Current.Public); err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Verify(pub); err != nil {
		t.Fatalf("token does not verify with the published key: %v", err)
	}
}

func jwksKIDs(t *testing.T, e *env) []string {
	t.Helper()
	var jwks struct{ Keys []map[string]interface{} }
	rawBody(t, e.ok(logical.ReadOperation, ".well-known/jwks.json", nil), &jwks)
	var ids []string
	for _, k := range jwks.Keys {
		ids = append(ids, k["kid"].(string))
	}
	return ids
}

func keysOf(m map[string]interface{}) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// containsPrivate reports whether JWK JSON includes a private member.
func containsPrivate(b []byte) bool {
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return true
	}
	for _, k := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}
