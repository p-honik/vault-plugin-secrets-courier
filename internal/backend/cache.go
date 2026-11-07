package backend

import (
	"context"
	"sync"

	"github.com/go-jose/go-jose/v4"
	"github.com/hashicorp/vault/sdk/logical"
)

// readCache holds the stored objects that the request handler and the public
// endpoints read on every call, so they do not cost a storage round trip each
// (for an external plugin every storage read is a gRPC call to Vault plus a
// barrier decryption). The cache is refreshed through the SDK's Invalidate hook and
// by the writers themselves.
//
// Rules that keep it correct:
//   - Only readers use it. Administrative writers always read storage directly:
//     validation under the configuration lock must see the stored state, not a
//     cache.
//   - Every cached object is immutable once published; callers must not modify it.
//   - Any storage change clears the whole cache: administrative writers call
//     invalidate after they write, and Vault calls Invalidate for changes made
//     elsewhere (a performance standby after a replicated write).
//   - A generation counter stops a reader that loaded before an invalidation
//     from storing its stale result afterwards.
//   - Absence is cached only for the singleton entries. An unknown role is not
//     cached, so an unauthenticated caller cannot grow the cache.
type readCache struct {
	mu  sync.Mutex
	gen uint64

	cfg     *storedConfig
	ksKnown bool
	ks      *keySnapshot
	roles   map[string]*role
}

// keySnapshot is an immutable view of the key set with the current signing key
// parsed once, instead of on every request.
type keySnapshot struct {
	*keySet
	once   sync.Once
	signer jose.SigningKey
	err    error
}

// signingKey parses the current private key on first use.
func (k *keySnapshot) signingKey(alg string) (jose.SigningKey, error) {
	k.once.Do(func() {
		var jwk jose.JSONWebKey
		if k.err = jwk.UnmarshalJSON(k.Current.Private); k.err != nil {
			return
		}
		k.signer = jose.SigningKey{Algorithm: jose.SignatureAlgorithm(alg), Key: jwk}
	})
	return k.signer, k.err
}

// invalidate clears the cache. Call it after every storage write that the
// readers depend on, and from the Invalidate hook.
func (b *backend) invalidate() {
	b.cache.mu.Lock()
	defer b.cache.mu.Unlock()
	b.cache.gen++
	b.cache.cfg, b.cache.ks, b.cache.roles = nil, nil, nil
	b.cache.ksKnown = false
}

// cacheGeneration is the number of invalidations so far.
func (b *backend) cacheGeneration() uint64 {
	b.cache.mu.Lock()
	defer b.cache.mu.Unlock()
	return b.cache.gen
}

// onInvalidate is the SDK Invalidate hook: some storage key changed elsewhere.
func (b *backend) onInvalidate(_ context.Context, _ string) { b.invalidate() }

// cachedConfig returns the stored config (defaults when none was written). The
// returned object is shared: do not modify it.
func (b *backend) cachedConfig(ctx context.Context, s logical.Storage) (*storedConfig, error) {
	c := &b.cache
	c.mu.Lock()
	if c.cfg != nil {
		cfg := c.cfg
		c.mu.Unlock()
		return cfg, nil
	}
	gen := c.gen
	c.mu.Unlock()

	cfg, _, err := loadConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.gen == gen {
		c.cfg = cfg
	}
	c.mu.Unlock()
	return cfg, nil
}

// cachedJWTConfig returns nil when the config has not been written.
func (b *backend) cachedJWTConfig(ctx context.Context, s logical.Storage) (*jwtConfig, error) {
	cfg, err := b.cachedConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	return cfg.JWT, nil
}

// cachedKeySet returns nil when no key set has been stored.
func (b *backend) cachedKeySet(ctx context.Context, s logical.Storage) (*keySnapshot, error) {
	c := &b.cache
	c.mu.Lock()
	if c.ksKnown {
		ks := c.ks
		c.mu.Unlock()
		return ks, nil
	}
	gen := c.gen
	c.mu.Unlock()

	ks, err := loadKeySet(ctx, s)
	if err != nil {
		return nil, err
	}
	var snap *keySnapshot
	if ks != nil {
		snap = &keySnapshot{keySet: ks}
	}
	c.mu.Lock()
	if c.gen == gen {
		c.ks, c.ksKnown = snap, true
	}
	c.mu.Unlock()
	return snap, nil
}

// cachedRole returns nil when the role does not exist (not cached).
func (b *backend) cachedRole(ctx context.Context, s logical.Storage, name string) (*role, error) {
	c := &b.cache
	c.mu.Lock()
	if r, ok := c.roles[name]; ok {
		c.mu.Unlock()
		return r, nil
	}
	gen := c.gen
	c.mu.Unlock()

	r, err := loadRole(ctx, s, name)
	if err != nil || r == nil {
		return nil, err
	}
	c.mu.Lock()
	if c.gen == gen {
		if c.roles == nil {
			c.roles = make(map[string]*role)
		}
		c.roles[name] = r
	}
	c.mu.Unlock()
	return r, nil
}
