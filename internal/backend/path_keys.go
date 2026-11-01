package backend

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathKeys is courier/keys and courier/keys/rotate.
func pathKeys(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "keys",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.guard(kindAuthenticated, "jwt.keys.read", b.handleKeysRead)},
			},
			HelpSynopsis: "Read key IDs and rotation times. Never returns private keys.",
		},
		{
			Pattern: "keys/rotate",
			Fields: map[string]*framework.FieldSchema{
				"revoke_previous": {Type: framework.TypeBool, Default: false, Description: "Drop all retired keys from the JWKS at once."},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.guard(kindAuthenticated, "jwt.keys.rotate", b.handleKeysRotate)},
			},
			HelpSynopsis: "Generate a fresh signing key and make it current immediately.",
		},
	}
}

// handleKeysRead returns key IDs and rotation times; never private keys.
func (b *backend) handleKeysRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	ks, err := loadKeySet(ctx, req.Storage)
	if err != nil || ks == nil {
		return nil, err
	}
	now := b.now()
	retired := make([]map[string]interface{}, 0, len(ks.Previous))
	for _, p := range ks.Previous {
		if now.Before(p.RetireAt) {
			retired = append(retired, map[string]interface{}{"kid": p.KID, "retire_at": p.RetireAt.UTC().Format(time.RFC3339)})
		}
	}
	return &logical.Response{Data: map[string]interface{}{
		"current_kid":   ks.Current.KID,
		"next_kid":      ks.Next.KID,
		"retired":       retired,
		"next_rotation": ks.NextRotation.UTC().Format(time.RFC3339),
	}}, nil
}

// handleKeysRotate always generates a fresh pair, never promotes the stored
// next, and honors revoke_previous. It runs under the
// configuration lock; with RS256 it generates two keys and can take a moment.
func (b *backend) handleKeysRotate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configLock.Lock()
	defer b.configLock.Unlock()
	if !b.WriteSafeReplicationState() {
		return nil, logical.ErrReadOnly
	}
	jc, err := loadJWTConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	ks, err := loadKeySet(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if jc == nil || ks == nil {
		return logical.ErrorResponse("the jwt type is not configured"), nil
	}
	revoke, _ := d.Get("revoke_previous").(bool)
	if err := ks.rotateManual(jc, b.now(), revoke); err != nil {
		return nil, err
	}
	err = putJSON(ctx, req.Storage, storageKeySet, ks)
	b.invalidate()
	return nil, err
}
