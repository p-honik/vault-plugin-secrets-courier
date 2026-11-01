package backend

import "time"

// Stored shapes. Field names follow the API parameter names.

// mountConfig holds the delivery settings (courier/config).
type mountConfig struct {
	DeliveryRetry   string        `json:"delivery_retry"`
	RetryDelay      time.Duration `json:"retry_delay"`
	DeliveryTimeout time.Duration `json:"delivery_timeout"`
	MaxInflight     int           `json:"max_inflight"`
	AllowedNetworks []string      `json:"allowed_networks"`
	DeniedNetworks  []string      `json:"denied_networks"`
}

// defaultMountConfig returns the effective configuration before any write.
func defaultMountConfig() *mountConfig {
	return &mountConfig{
		DeliveryRetry:   defaultDeliveryRetry,
		RetryDelay:      defaultRetryDelay,
		DeliveryTimeout: defaultDeliveryTimeout,
		MaxInflight:     defaultMaxInflight,
		AllowedNetworks: []string{},
		DeniedNetworks:  []string{},
	}
}

// storedConfig is the one config entry at storageConfig (courier/config). Type is
// the mount's credential type, recorded on the first write so that a mount whose
// type option later differs is refused rather than read as another type. The
// delivery settings are flattened into it; JWT holds the parameters of the jwt
// type and is nil until the first write.
type storedConfig struct {
	Type string `json:"type"`
	mountConfig
	JWT *jwtConfig `json:"jwt,omitempty"`
}

// jwtConfig holds the parameters of the jwt credential type. Its absence means
// the mount is unconfigured: the .well-known endpoints return 404 and no role can
// exist.
type jwtConfig struct {
	Issuer          string        `json:"issuer"`
	Alg             string        `json:"alg"`
	RotationPeriod  time.Duration `json:"rotation_period"`
	MaxTTL          time.Duration `json:"max_ttl"`
	VerificationTTL time.Duration `json:"verification_ttl"`
}

// role is stored at storageRolePrefix + name. It holds the delivery fields every
// type shares plus exactly the fields of the mount's type (embedded, so the
// stored shape is flat); it carries nothing for any other type.
type role struct {
	AllowedReceiptURLs []string      `json:"allowed_receipt_urls"`
	RequireNonce       bool          `json:"require_nonce"`
	MinRequestInterval time.Duration `json:"min_request_interval"`
	ReceiptCAPEM       string        `json:"receipt_ca_pem"`
	jwtRole
}

// jwtRole is what a role holds on a jwt mount.
type jwtRole struct {
	Aud          string        `json:"aud"`
	TTL          time.Duration `json:"ttl"`
	NonceInToken bool          `json:"nonce_in_token"`
}

// keySet is the ONE storage entry at storageKeySet.
// Mutual exclusion between writers comes from the configuration lock, not from
// the single entry.
type keySet struct {
	Next         *nextKey     `json:"next"`
	Current      *currentKey  `json:"current"`
	Previous     []retiredKey `json:"previous"`
	NextRotation time.Time    `json:"next_rotation"`
}

// nextKey is published in the JWKS but does not sign yet.
type nextKey struct {
	KID       string    `json:"kid"` // UUIDv7, stable across promotion
	Private   []byte    `json:"private"`
	Public    []byte    `json:"public"`
	NotBefore time.Time `json:"not_before"` // earliest time it may become current
}

// currentKey signs new tokens.
type currentKey struct {
	KID        string        `json:"kid"`
	Private    []byte        `json:"private"`
	Public     []byte        `json:"public"`
	RotatedAt  time.Time     `json:"rotated_at"`
	LongestTTL time.Duration `json:"longest_ttl"` // high-water mark of max_ttl
}

// retiredKey holds the public part only; its private key is dropped on
// retirement.
type retiredKey struct {
	KID      string    `json:"kid"`
	Public   []byte    `json:"public"`
	RetireAt time.Time `json:"retire_at"`
}
