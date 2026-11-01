// Package backend implements the Courier secrets engine: it delivers a secret to
// an allowlisted receipt URL without the requester ever seeing it. A mount serves
// one credential type, chosen by the mount option `type`.
package backend

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type backend struct {
	*framework.Backend

	// configLock is the ONE configuration lock: it covers
	// every administrative write (role create/update/delete, courier/config,
	// keys/rotate) and the PeriodicFunc tick. Reads and the
	// request handler never take it. It is never held together with state.mu.
	configLock sync.Mutex

	// unsupported is the mount option when it names a type this build does not
	// support although the mount holds data; the backend then refuses to serve.
	unsupported string

	// ctype is the mount's credential type, fixed when the backend is built from
	// the mount option `type`.
	ctype credentialType

	// state is the in-memory rate-limit and in-flight state.
	state *rateState

	// now is the wall clock; tests replace it.
	now func() time.Time

	// logMu guards lastLog, the time of the last log line per failing handler.
	logMu   sync.Mutex
	lastLog map[string]time.Time

	// warnMu guards lastWarn, the time of the last "not write-safe" warning.
	warnMu   sync.Mutex
	lastWarn time.Time

	// cache holds the objects readers need on every call (cache.go).
	cache readCache

	// policy is the current network policy, read by delivery goroutines at each
	// connection attempt. It is refreshed on every courier/config write and on
	// every request, so the goroutines never need storage access.
	policy    atomic.Pointer[networkPolicy]
	policySrc atomic.Pointer[mountConfig] // the config policy was built from

	// ctx is the parent context of delivery goroutines. It is created in
	// InitializeFunc and cancelled in Clean; request contexts end when the
	// handler returns and must not be used for deliveries.
	ctxMu  sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	closed bool           // set by clean; a closed backend starts no deliveries
	wg     sync.WaitGroup // running deliveries, waited on briefly in Clean
}

// Factory returns the configured backend. It is the plugin entry point.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	typeName := defaultCredentialType
	if v := conf.Config["type"]; v != "" {
		typeName = v
	}
	newType, ok := credentialTypes[typeName]
	var unsupported string
	if !ok {
		// A mount cannot be enabled with a type this build does not support. But
		// if the mount already holds data, the option was changed afterwards (or
		// the data came from a newer build): refuse to serve rather than fail to
		// load, so the mount answers with the fixed messages.
		if !hasStoredConfig(ctx, conf.StorageView) {
			return nil, fmt.Errorf("unsupported credential type %q: the supported types are %s", typeName, supportedTypes())
		}
		newType, unsupported = credentialTypes[defaultCredentialType], typeName
	}
	b := newBackend(newType())
	b.unsupported = unsupported
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// hasStoredConfig reports whether the mount already holds a config entry.
func hasStoredConfig(ctx context.Context, s logical.Storage) bool {
	if s == nil {
		return false
	}
	entry, err := s.Get(ctx, storageConfig)
	return err == nil && entry != nil
}

func supportedTypes() string {
	names := make([]string, 0, len(credentialTypes))
	for n := range credentialTypes {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func newBackend(ct credentialType) *backend {
	b := &backend{state: newRateState(), now: time.Now, ctype: ct}
	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			// Keep this list exact and short. Never add a
			// broad pattern such as "*". The type adds its own public patterns.
			Unauthenticated: append([]string{"request/*"}, ct.unauthenticated()...),
			// Harmless on community edition; may add protection on Enterprise.
			SealWrapStorage: ct.sealWrap(),
		},
		Paths: framework.PathAppend(
			pathConfig(b),
			pathRole(b),
			pathRequest(b),
			ct.paths(b),
		),
		InitializeFunc: b.initialize,
		PeriodicFunc:   b.periodic,
		Clean:          b.clean,
		Invalidate:     b.onInvalidate,
	}
	return b
}

func (b *backend) initialize(ctx context.Context, _ *logical.InitializationRequest) error {
	b.deliveryContext()
	return nil
}

// deliveryContext returns the long-lived parent context of delivery goroutines,
// creating it on first use. It is created per activation (each activation
// builds a fresh backend) and cancelled in Clean. Request contexts end when the
// handler returns and must not be used for deliveries.
func (b *backend) deliveryContext() context.Context {
	b.ctxMu.Lock()
	defer b.ctxMu.Unlock()
	if b.ctx == nil {
		b.ctx, b.cancel = context.WithCancel(context.Background())
	}
	return b.ctx
}

func (b *backend) currentPolicy() *networkPolicy {
	if p := b.policy.Load(); p != nil {
		return p
	}
	return &networkPolicy{} // no restriction until a config has been seen
}

// evictRateState drops rate-limit entries whose interval has elapsed or whose
// role or URL no longer exists. It reads roles from storage (a read, so it is
// harmless on any node) and touches only memory.
func (b *backend) evictRateState(ctx context.Context, s logical.Storage) {
	// Nothing to evict: skip the storage reads.
	if b.state.empty() {
		return
	}
	roles, err := loadAllRoles(ctx, s)
	if err != nil {
		return
	}
	b.state.evict(b.now(), func(role, receiptURL string) (time.Duration, bool) {
		r := roles[role]
		if r == nil {
			return 0, false
		}
		for _, u := range r.AllowedReceiptURLs {
			if u == receiptURL {
				return r.MinRequestInterval, true
			}
		}
		return 0, false
	})
}

// periodic runs on the RollbackManager tick (about once a minute). Under the
// configuration lock it rotates the key set if due and drops expired retired
// keys, then evicts rate-limit state. It never creates the first key set.
func (b *backend) periodic(ctx context.Context, req *logical.Request) error {
	// The rate-limit state is memory only, so eviction is harmless on any node.
	b.evictRateState(ctx, req.Storage)

	// Guard every storage write with the write-safe check.
	if !b.WriteSafeReplicationState() {
		return nil
	}
	b.configLock.Lock()
	defer b.configLock.Unlock()

	jc, err := loadJWTConfig(ctx, req.Storage)
	if err != nil || jc == nil {
		return err
	}
	ks, err := loadKeySet(ctx, req.Storage)
	if err != nil || ks == nil {
		return err
	}
	// Evaluated after taking the lock: a manual rotation that just reset
	// next_rotation turns a waiting tick into a no-op.
	now := b.now()
	changed := ks.dropExpired(now)
	if ks.rotationDue(now) {
		if err := ks.rotateScheduled(jc, now); err != nil {
			return err
		}
		changed = true
	}
	if !changed {
		return nil
	}
	err = putJSON(ctx, req.Storage, storageKeySet, ks)
	b.invalidate()
	return err
}

// cleanWait is how long clean waits for running deliveries after cancelling.
const cleanWait = 2 * time.Second

// clean runs on unload (step-down, unmount, shutdown): cancel the delivery
// context, wait briefly for running deliveries, then clear the memory-only
// rate-limit state.
func (b *backend) clean(_ context.Context) {
	b.ctxMu.Lock()
	b.closed = true
	if b.cancel != nil {
		b.cancel()
	}
	b.ctxMu.Unlock()

	done := make(chan struct{})
	go func() { b.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(cleanWait):
	}
	b.state.reset()
	b.invalidate()
}

const backendHelp = `
Courier delivers credentials to allowlisted receipt URLs. A role names a
credential type, an audience and the receipt URLs allowed to receive credentials
for it. An unauthenticated request asks the engine to sign a token and POST it
to one of those URLs; the caller never sees the token.
`
