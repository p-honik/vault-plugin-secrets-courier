package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathWellKnown holds the two UNAUTHENTICATED public endpoints. Responses are raw
// HTTP bodies (logical.HTTPContentType,
// logical.HTTPRawBody), not Vault's JSON envelope.
func pathWellKnown(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: `\.well-known/openid-configuration`,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.guard(kindPublic, "jwt.discovery", b.handleDiscovery)},
			},
			HelpSynopsis: "OIDC discovery document (minimal subset for JWT verifiers).",
		},
		{
			Pattern: `\.well-known/jwks\.json`,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.guard(kindPublic, "jwt.jwks", b.handleJWKS)},
			},
			HelpSynopsis: "Public keys: next, current and unexpired retired keys.",
		},
	}
}

// rawResponse builds a raw (non-envelope) response. Every raw response, the 200s
// included, sets http_status_code, a content type and a []byte body:
// without the status code Vault wraps the response in its JSON envelope.
func rawResponse(status int, contentType string, body []byte, cacheControl string) *logical.Response {
	data := map[string]interface{}{
		logical.HTTPStatusCode:  status,
		logical.HTTPContentType: contentType,
		logical.HTTPRawBody:     body,
	}
	if cacheControl != "" {
		data[logical.HTTPCacheControlHeader] = cacheControl
	}
	return &logical.Response{Data: data}
}

func rawNotFound() *logical.Response {
	return rawResponse(http.StatusNotFound, "application/json", []byte(`{"error":"not found"}`), "")
}

// wellKnownState loads what both public endpoints need. ok is false when they
// must answer 404: the config entry is absent (even if orphaned keys exist)
// or there is no key set.
func (b *backend) wellKnownState(ctx context.Context, s logical.Storage) (jc *jwtConfig, ks *keySnapshot, ok bool, err error) {
	if jc, err = b.cachedJWTConfig(ctx, s); err != nil || jc == nil {
		return nil, nil, false, err
	}
	if ks, err = b.cachedKeySet(ctx, s); err != nil || ks == nil {
		return nil, nil, false, err
	}
	return jc, ks, true, nil
}

// handleDiscovery serves the minimal OIDC discovery document. It takes no write
// lock.
func (b *backend) handleDiscovery(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	jc, _, ok, err := b.wellKnownState(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if !ok {
		return rawNotFound(), nil
	}
	body, err := json.Marshal(map[string]interface{}{
		"issuer":                                jc.Issuer,
		"jwks_uri":                              strings.TrimSuffix(jc.Issuer, "/") + "/.well-known/jwks.json",
		"id_token_signing_alg_values_supported": []string{jc.Alg},
	})
	if err != nil {
		return nil, err
	}
	return rawResponse(http.StatusOK, "application/json", body, ""), nil
}

// handleJWKS serves the public keys: current, next and unexpired retired keys,
// with the fixed Cache-Control max-age. It takes no write lock.
func (b *backend) handleJWKS(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	_, ks, ok, err := b.wellKnownState(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if !ok {
		return rawNotFound(), nil
	}
	body, err := json.Marshal(map[string]interface{}{"keys": ks.publicJWKS(b.now())})
	if err != nil {
		return nil, err
	}
	return rawResponse(http.StatusOK, "application/json", body,
		fmt.Sprintf("max-age=%d", int(jwksMaxAge.Seconds()))), nil
}
