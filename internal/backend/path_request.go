package backend

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathRequest is the UNAUTHENTICATED courier/request/:role.
//
// Defined under Operations (not Callbacks) so the forwarding flags are honored:
// the handler calls an external system, so both flags must be set.
// The :role segment accepts any single segment and the handler validates it, so
// the framework never answers 404 for a bad name and the naming rule is not
// revealed.
func pathRequest(b *backend) []*framework.Path {
	return []*framework.Path{{
		Pattern: "request/" + `(?P<role>[^/]+)`,
		Fields: map[string]*framework.FieldSchema{
			"role":        {Type: framework.TypeString, Description: "Role name."},
			"receipt_url": {Type: framework.TypeString, Description: "Must be byte-identical to an entry in the role's allowed_receipt_urls."},
			"nonce":       {Type: framework.TypeString, Description: "Optional: 16-128 base64url characters. Echoed in the delivery."},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.guard(kindRequest, "request", b.handleRequest),
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},
		HelpSynopsis: "Ask for a credential to be delivered to an allowlisted receipt URL.",
	}}
}

// handleRequest handles a delivery request. The plugin returns exactly two
// statuses: 204 (a nil response) and 400. Everything that is not a format error
// is a nil response, including every silent drop and every internal fault after
// the checks (which is logged). It never writes storage.
func (b *backend) handleRequest(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Step 1: format errors are a 400 whatever the allowlist says. The plugin's
	// messages are fixed strings that never echo the input.
	receiptURL, _ := d.Get("receipt_url").(string)
	if receiptURL == "" {
		return logical.ErrorResponse("receipt_url is required"), nil
	}
	nonce, hasNonce := "", false
	if v, ok := d.GetOk("nonce"); ok {
		nonce, hasNonce = v.(string), true
		if !validNonce(nonce) {
			return logical.ErrorResponse("nonce must be 16-128 characters from A-Za-z0-9_-"), nil
		}
	}

	// The role: a name that fails the rule is an unknown role (silent drop), so
	// the framework never answers 404 for a bad name.
	name, _ := d.Get("role").(string)
	if !validRoleName(name) {
		return nil, nil
	}
	// Readers use the cache (cache.go): a hit costs no storage round trip.
	r, err := b.cachedRole(ctx, req.Storage, name)
	if err != nil {
		return b.internalFault("loading role", name, err)
	}
	if r == nil {
		return nil, nil
	}
	// Reveals that the role exists and requires a nonce; accepted.
	if r.RequireNonce && !hasNonce {
		return logical.ErrorResponse("nonce is required"), nil
	}
	// Byte-exact match, no normalization.
	if !contains(r.AllowedReceiptURLs, receiptURL) {
		return nil, nil
	}
	// A node that cannot write never signs.
	if !b.WriteSafeReplicationState() {
		b.warnNotWriteSafe(name)
		return nil, nil
	}

	cfg, err := b.cachedConfig(ctx, req.Storage)
	if err != nil {
		return b.internalFault("loading config", name, err)
	}
	mc := &cfg.mountConfig
	b.refreshPolicy(mc)

	// Reserve, then sign: the cheap limit checks run first, and a request that is
	// dropped here never reads the key set. All checks and the commit are one
	// critical section.
	now := b.now()
	res, ok := b.state.reserve(name, receiptURL, nonce, now, r.MinRequestInterval, mc.MaxInflight)
	if !ok {
		return nil, nil
	}
	jc := cfg.JWT
	if jc == nil {
		res.abort()
		return b.internalFault("loading config", name, nil)
	}
	ks, err := b.cachedKeySet(ctx, req.Storage)
	if err != nil || ks == nil {
		res.abort()
		return b.internalFault("loading key set", name, err)
	}
	token, err := signToken(ks, jc, r, receiptURL, nonce, now)
	if err != nil {
		res.abort()
		return b.internalFault("signing", name, err)
	}

	dl := &delivery{
		roleName:        name,
		credential:      b.ctype.name(),
		token:           token,
		receiptURL:      receiptURL,
		nonce:           nonce,
		retry:           mc.DeliveryRetry == "once",
		retryDelay:      mc.RetryDelay,
		deliveryTimeout: mc.DeliveryTimeout,
		caPEM:           r.ReceiptCAPEM,
		policy:          b.currentPolicy,
		logger:          b.Logger(),
	}
	if !b.startDelivery(dl, res) {
		res.abort()
	}
	return nil, nil
}

// startDelivery runs the delivery in a goroutine under the backend's context. It
// reports false, starting nothing, once the backend is being cleaned up. The
// WaitGroup is only incremented while the context is live, under the same lock
// that clean takes to cancel it, so Wait in clean never races an Add.
func (b *backend) startDelivery(dl *delivery, res *reservation) bool {
	b.ctxMu.Lock()
	if b.closed {
		b.ctxMu.Unlock()
		return false
	}
	if b.ctx == nil {
		b.ctx, b.cancel = context.WithCancel(context.Background())
	}
	parent := b.ctx
	b.wg.Add(1)
	b.ctxMu.Unlock()

	go func() {
		defer b.wg.Done()
		defer res.finish()
		// A panic in a delivery must not take the plugin process down.
		defer func() {
			if p := recover(); p != nil {
				b.Logger().Error("delivery panicked", "role", dl.roleName, "panic", fmt.Sprint(p))
			}
		}()
		dl.run(parent)
	}()
	return true
}

// refreshPolicy rebuilds the network policy only when the mount config object
// changed (the cache hands out the same pointer until it is invalidated).
func (b *backend) refreshPolicy(mc *mountConfig) {
	if b.policySrc.Load() == mc {
		return
	}
	b.policy.Store(policyFor(mc))
	b.policySrc.Store(mc)
}

// internalFault logs a failure after the checks and still answers 204: the
// caller must not learn that the mount is unconfigured or failing.
func (b *backend) internalFault(what, role string, err error) (*logical.Response, error) {
	b.logCause("request."+what, "request failed", err, "role", role)
	return nil, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// notWriteSafeWarnEvery bounds the warning for a request that reached a node that
// cannot write: at most one a minute, so a flood cannot fill the log.
const notWriteSafeWarnEvery = time.Minute

// warnNotWriteSafe logs a warning that a request was dropped because this node is
// not write-safe, at most once per notWriteSafeWarnEvery. The caller still gets
// the usual 204.
func (b *backend) warnNotWriteSafe(role string) {
	now := b.now()
	b.warnMu.Lock()
	if !b.lastWarn.IsZero() && now.Sub(b.lastWarn) < notWriteSafeWarnEvery {
		b.warnMu.Unlock()
		return
	}
	b.lastWarn = now
	b.warnMu.Unlock()
	b.Logger().Warn("request dropped: this node is not write-safe and the request reached it despite forwarding",
		"role", role)
}
