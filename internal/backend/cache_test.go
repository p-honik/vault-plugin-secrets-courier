package backend

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// countingStorage counts reads and can run a hook inside a read.
type countingStorage struct {
	*logical.InmemStorage
	gets atomic.Int64
	hook func(key string)
}

func (c *countingStorage) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	c.gets.Add(1)
	entry, err := c.InmemStorage.Get(ctx, key)
	if c.hook != nil {
		c.hook(key)
	}
	return entry, err
}

func countingEnv(t *testing.T) (*env, *countingStorage) {
	e := newEnv(t)
	cs := &countingStorage{InmemStorage: &logical.InmemStorage{}}
	e.s = cs
	return e, cs
}

func TestRequestPathUsesTheCache(t *testing.T) {
	e, cs := countingEnv(t)
	rc := newReceiver(t)
	e.configureJWT(nil)
	e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM, "min_request_interval": 0})
	req := map[string]interface{}{"receipt_url": rc.url("/x")}

	e.request("r", req) // warms the cache
	cs.gets.Store(0)
	for i := 0; i < 5; i++ {
		e.request("r", req)
	}
	if n := cs.gets.Load(); n != 0 {
		t.Fatalf("warm requests made %d storage reads, want 0", n)
	}
	if got := len(rc.received()); got != 6 {
		t.Fatalf("receiver got %d deliveries, want 6", got)
	}

	// The public endpoints use it too.
	e.ok(logical.ReadOperation, ".well-known/jwks.json", nil)
	cs.gets.Store(0)
	e.ok(logical.ReadOperation, ".well-known/jwks.json", nil)
	e.ok(logical.ReadOperation, ".well-known/openid-configuration", nil)
	if n := cs.gets.Load(); n != 0 {
		t.Fatalf("warm well-known reads made %d storage reads, want 0", n)
	}
}

func TestDroppedRequestDoesNotReadTheKeySet(t *testing.T) {
	e, cs := countingEnv(t)
	rc := newReceiver(t)
	e.configureJWT(nil)
	e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM, "min_request_interval": 3600})
	req := map[string]interface{}{"receipt_url": rc.url("/x")}
	e.request("r", req) // accepted
	// Drop the cache entries for the key set and jwt config only by rebuilding it
	// after the first request; then a request inside the interval must not load them.
	e.b.invalidate()
	cs.gets.Store(0)
	e.request("r", req) // inside the interval: dropped by reserve
	if n := cs.gets.Load(); n != 2 {
		t.Fatalf("a dropped request read storage %d times, want 2 (role and mount config only)", n)
	}
}

func TestWritersInvalidateTheCache(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t)
	e.configureJWT(nil)
	e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM, "min_request_interval": 0})
	e.request("r", map[string]interface{}{"receipt_url": rc.url("/x")})
	if len(rc.received()) != 1 {
		t.Fatal("setup: no delivery")
	}

	// Role update: the old URL is no longer allowed, at once.
	e.ok(logical.UpdateOperation, "roles/r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/y")}})
	e.request("r", map[string]interface{}{"receipt_url": rc.url("/x")})
	if len(rc.received()) != 1 {
		t.Fatal("a cached role let a removed URL through")
	}
	e.request("r", map[string]interface{}{"receipt_url": rc.url("/y")})
	if len(rc.received()) != 2 {
		t.Fatal("the updated role is not in effect")
	}

	// Role delete.
	e.ok(logical.DeleteOperation, "roles/r", nil)
	e.request("r", map[string]interface{}{"receipt_url": rc.url("/y")})
	if len(rc.received()) != 2 {
		t.Fatal("a cached role survived its deletion")
	}
}

func TestNetworkPolicyChangeAppliesToTheNextRequest(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t)
	e.configureJWT(nil)
	e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM, "min_request_interval": 0})
	req := map[string]interface{}{"receipt_url": rc.url("/x")}
	e.request("r", req)
	e.ok(logical.UpdateOperation, "config", map[string]interface{}{"denied_networks": []string{"127.0.0.0/8", "::1/128"}})
	e.request("r", req)
	if len(rc.received()) != 1 {
		t.Fatal("a tightened network policy was not applied")
	}
}

func TestInvalidateHookClearsTheCache(t *testing.T) {
	e, cs := countingEnv(t)
	e.configureJWT(nil)
	ctx := context.Background()
	if _, err := e.b.cachedJWTConfig(ctx, cs); err != nil {
		t.Fatal(err)
	}
	cs.gets.Store(0)
	e.b.cachedJWTConfig(ctx, cs)
	if cs.gets.Load() != 0 {
		t.Fatal("second read was not served from the cache")
	}
	// Change storage behind the backend's back, as a replicated write would.
	cfg, _, err := loadConfig(ctx, cs)
	if err != nil {
		t.Fatal(err)
	}
	cfg.JWT.Issuer = "https://other.example/jwt"
	if err := putJSON(ctx, cs, storageConfig, cfg); err != nil {
		t.Fatal(err)
	}
	e.b.InvalidateKey(ctx, storageConfig)
	got, _ := e.b.cachedJWTConfig(ctx, cs)
	if got.Issuer != "https://other.example/jwt" {
		t.Fatalf("issuer = %q: the Invalidate hook did not clear the cache", got.Issuer)
	}
}

// A reader that loaded before an invalidation must not store its stale result.
func TestStaleReadIsNotCached(t *testing.T) {
	e, cs := countingEnv(t)
	e.configureJWT(nil)
	ctx := context.Background()
	e.b.invalidate()
	fired := false
	cs.hook = func(key string) {
		if key == storageConfig && !fired {
			fired = true
			e.b.invalidate() // an invalidation lands while the read is in flight
		}
	}
	if _, err := e.b.cachedJWTConfig(ctx, cs); err != nil {
		t.Fatal(err)
	}
	cs.hook = nil
	cs.gets.Store(0)
	e.b.cachedJWTConfig(ctx, cs)
	if cs.gets.Load() == 0 {
		t.Fatal("a result read before an invalidation was cached")
	}
}

func TestUnknownRolesAreNotCached(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 50; i++ {
		e.b.cachedRole(context.Background(), e.s, "nope")
	}
	if len(e.b.cache.roles) != 0 {
		t.Fatal("an unknown role was cached: unauthenticated callers could grow the cache")
	}
}

func TestCleanDuringDeliveryIsSafe(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t)
	e.configureJWT(nil)
	e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM, "min_request_interval": 0})
	e.b.clean(context.Background())
	// After clean no delivery starts, the reservation is released, and nothing panics.
	e.request("r", map[string]interface{}{"receipt_url": rc.url("/x")})
	if rc.attempts() != 0 {
		t.Fatal("a delivery started after clean")
	}
	if e.b.state.inflightCount() != 0 {
		t.Fatal("the reservation of a refused delivery was not released")
	}
}
