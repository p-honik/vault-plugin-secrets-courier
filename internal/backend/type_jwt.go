package backend

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// jwtType is the jwt credential type: Courier signs a JWT for an arbitrary
// service identity and delivers it, and publishes the discovery document and the
// JWKS.
type jwtType struct{}

func (jwtType) name() string { return "jwt" }

func (jwtType) configFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"issuer":           {Type: framework.TypeString, Description: "The iss claim and base URL verifiers use. Required on the first write."},
		"alg":              {Type: framework.TypeString, Default: defaultAlg, Description: "ES256 or RS256. Fixed once the first key set exists."},
		"rotation_period":  {Type: framework.TypeDurationSecond, Default: int(defaultRotationPeriod.Seconds()), Description: "How often the next signing key becomes current. At least 6 minutes."},
		"max_ttl":          {Type: framework.TypeDurationSecond, Default: int(defaultMaxTTL.Seconds()), Description: "Upper bound on any role's ttl."},
		"verification_ttl": {Type: framework.TypeDurationSecond, Default: int(defaultVerificationTTL.Seconds()), Description: "How long a retired key's public part stays in the JWKS."},
	}
}

func (jwtType) roleFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"aud":            {Type: framework.TypeString, Description: "The aud claim."},
		"ttl":            {Type: framework.TypeDurationSecond, Default: int(defaultRoleTTL.Seconds()), Description: "Token lifetime."},
		"nonce_in_token": {Type: framework.TypeBool, Default: false, Description: "Put the supplied nonce in the token."},
	}
}

func (jwtType) paths(b *backend) []*framework.Path {
	return framework.PathAppend(pathKeys(b), pathWellKnown(b))
}

// Keep this list exact and short. Never add a broad pattern
// such as "*".
func (jwtType) unauthenticated() []string { return []string{".well-known/*"} }

// Harmless on community edition; may add protection on Enterprise.
func (jwtType) sealWrap() []string { return []string{"keys/"} }

func (jwtType) mergeConfig(cfg *storedConfig, d *framework.FieldData, first bool) string {
	if first || cfg.JWT == nil {
		cfg.JWT = &jwtConfig{
			Alg:             defaultAlg,
			RotationPeriod:  defaultRotationPeriod,
			MaxTTL:          defaultMaxTTL,
			VerificationTTL: defaultVerificationTTL,
		}
	}
	jc := cfg.JWT
	if v, ok := d.GetOk("issuer"); ok {
		jc.Issuer = v.(string)
	}
	if v, ok := d.GetOk("alg"); ok {
		if !first && v.(string) != jc.Alg {
			return "alg cannot be changed after the first key set is created"
		}
		jc.Alg = v.(string)
	}
	if v, ok := d.GetOk("rotation_period"); ok {
		jc.RotationPeriod = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("max_ttl"); ok {
		jc.MaxTTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("verification_ttl"); ok {
		jc.VerificationTTL = time.Duration(v.(int)) * time.Second
	}
	return ""
}

func (jwtType) validateConfig(cfg *storedConfig, roles map[string]*role) error {
	if err := validateJWTConfig(cfg.JWT, roles); err != nil {
		return err
	}
	return validateRolesAgainstWindow(&cfg.mountConfig, roles)
}

// prepareWrite creates the initial key set on the first write, or updates the
// stored key state after a config change. Keys are generated before
// any storage write, so a failure here changes nothing.
func (jwtType) prepareWrite(ctx context.Context, s logical.Storage, old, merged *storedConfig, now time.Time) (func(context.Context, logical.Storage) error, string, error) {
	ks, err := loadKeySet(ctx, s)
	if err != nil {
		return nil, "", err
	}
	write := false
	switch {
	case ks == nil:
		// First creation (or a retry that finds no keys).
		if ks, err = newKeySet(merged.JWT, now); err != nil {
			return nil, "", fmt.Errorf("generating keys: %w", err)
		}
		write = true
	case old == nil || old.JWT == nil:
		// Orphaned keys from a partial first write: keep them and require the
		// submitted alg to match.
		alg, err := keySetAlg(ks)
		if err != nil {
			return nil, "", err
		}
		if alg != merged.JWT.Alg {
			return nil, fmt.Sprintf("alg does not match the existing keys (%s)", alg), nil
		}
	default:
		write = ks.applyConfigChange(old.JWT, merged.JWT)
	}
	if !write {
		return nil, "", nil
	}
	return func(ctx context.Context, s logical.Storage) error {
		return putJSON(ctx, s, storageKeySet, ks)
	}, "", nil
}

func (jwtType) configData(cfg *storedConfig) map[string]interface{} {
	if cfg.JWT == nil {
		return nil
	}
	return map[string]interface{}{
		"issuer":           cfg.JWT.Issuer,
		"alg":              cfg.JWT.Alg,
		"rotation_period":  int(cfg.JWT.RotationPeriod.Seconds()),
		"max_ttl":          int(cfg.JWT.MaxTTL.Seconds()),
		"verification_ttl": int(cfg.JWT.VerificationTTL.Seconds()),
	}
}

func (jwtType) mergeRole(cfg *storedConfig, existing, r *role, d *framework.FieldData) string {
	if v, ok := d.GetOk("aud"); ok {
		r.Aud = v.(string)
	}
	ttlSent := false
	if v, ok := d.GetOk("ttl"); ok {
		r.TTL = time.Duration(v.(int)) * time.Second
		ttlSent = true
	}
	if v, ok := d.GetOk("nonce_in_token"); ok {
		r.NonceInToken = v.(bool)
	}
	// A ttl that was not sent on creation resolves to min(10m, max_ttl) and the
	// resolved value is stored.
	if existing == nil {
		if !ttlSent && cfg.JWT != nil {
			r.TTL = min(defaultRoleTTL, cfg.JWT.MaxTTL)
			if window := deliveryWindow(&cfg.mountConfig); r.TTL < minRoleTTL || r.TTL <= window {
				return fmt.Sprintf("ttl was not sent and the default min(10m, max_ttl) = %s is not valid on this mount; set ttl", r.TTL)
			}
		}
	}
	return ""
}

func (jwtType) validateRole(r *role, cfg *storedConfig) error {
	return validateJWTRole(r, &cfg.mountConfig, cfg.JWT)
}

func (jwtType) roleData(r *role) map[string]interface{} {
	return map[string]interface{}{
		"aud":            r.Aud,
		"ttl":            int(r.TTL.Seconds()),
		"nonce_in_token": r.NonceInToken,
	}
}
