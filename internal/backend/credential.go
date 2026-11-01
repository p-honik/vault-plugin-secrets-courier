package backend

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// A mount serves exactly one credential type, chosen by the mount option `type`
// when the mount is enabled. The type decides what the
// config and the roles hold, so neither is a union of every type's fields: the
// generic code here and in the path files handles the delivery settings and the
// delivery mechanics (allowlist, nonce, limits, network policy, delivery), and
// the type supplies the rest through this interface.
type credentialType interface {
	// name is the value of the mount option and what the delivery payload reports
	// as `type`.
	name() string

	// Schemas the type adds to courier/config and to roles/:name.
	configFields() map[string]*framework.FieldSchema
	roleFields() map[string]*framework.FieldSchema

	// paths are the type's own endpoints; unauthenticated lists the patterns among
	// them that need no token, and sealWrap the storage prefixes that hold key
	// material.
	paths(b *backend) []*framework.Path
	unauthenticated() []string
	sealWrap() []string

	// mergeConfig applies the type's parameters from a config write onto cfg, a
	// working copy, and returns a message for the caller if one is rejected.
	mergeConfig(cfg *storedConfig, d *framework.FieldData, first bool) string
	// validateConfig checks the merged config, including its effect on the
	// existing roles.
	validateConfig(cfg *storedConfig, roles map[string]*role) error
	// prepareWrite does what the type needs before the config is stored (the jwt
	// type creates or updates its key set). It must not write storage itself: the
	// returned store function does that, called before the config entry is
	// written. old is nil on the first write.
	prepareWrite(ctx context.Context, s logical.Storage, old, merged *storedConfig, now time.Time) (store func(context.Context, logical.Storage) error, userErr string, err error)
	// configData is what a config read returns for the type.
	configData(cfg *storedConfig) map[string]interface{}

	// mergeRole applies the type's role parameters onto r; existing is nil on
	// creation. validateRole checks the merged role against the config. roleData
	// is what a role read returns for the type.
	mergeRole(cfg *storedConfig, existing, r *role, d *framework.FieldData) string
	validateRole(r *role, cfg *storedConfig) error
	roleData(r *role) map[string]interface{}
}

// credentialTypes are the types this build supports.
var credentialTypes = map[string]func() credentialType{
	"jwt": func() credentialType { return jwtType{} },
}

// defaultCredentialType is used when the mount option is not set.
const defaultCredentialType = "jwt"

// copyConfig returns a deep copy a writer can modify.
func copyConfig(cfg *storedConfig) *storedConfig {
	c := *cfg
	c.AllowedNetworks = append([]string{}, cfg.AllowedNetworks...)
	c.DeniedNetworks = append([]string{}, cfg.DeniedNetworks...)
	if cfg.JWT != nil {
		j := *cfg.JWT
		c.JWT = &j
	}
	return &c
}
