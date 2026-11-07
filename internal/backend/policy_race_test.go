package backend

import (
	"context"
	"net/netip"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// A request that read the config just before a config write must not replace the
// tightened policy the write installed.
func TestStaleConfigReadCannotReopenTightenedPolicy(t *testing.T) {
	e := newEnv(t)
	e.configureJWT(nil)
	ctx := context.Background()
	// A request is served: policy built from the cached config Y.
	g := e.b.cacheGeneration()
	y, _ := e.b.cachedConfig(ctx, e.s)
	e.b.refreshPolicy(&y.mountConfig, g)
	// Something invalidates the cache (e.g. a role write or Vault's Invalidate hook).
	e.b.invalidate()
	// Request R loads a fresh config X, but has not reached refreshPolicy yet.
	g = e.b.cacheGeneration()
	x, _ := e.b.cachedConfig(ctx, e.s)
	// Admin tightens the policy: config write stores the new policy at once.
	e.ok(logical.UpdateOperation, "config", map[string]interface{}{"denied_networks": []string{"10.0.0.0/8"}})
	if e.b.currentPolicy().permits(netip.MustParseAddr("10.1.1.1")) {
		t.Fatal("setup: write did not tighten")
	}
	// R continues with its pre-write config.
	e.b.refreshPolicy(&x.mountConfig, g)
	if e.b.currentPolicy().permits(netip.MustParseAddr("10.1.1.1")) {
		t.Error("BUG: a request that read config before the write re-opened the denied network")
	}
}
