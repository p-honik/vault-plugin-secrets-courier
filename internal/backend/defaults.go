package backend

import "time"

// Defaults and fixed constants. Fixed values are not configurable.
const (
	// Mount config (courier/config).
	defaultDeliveryRetry   = "never"
	defaultRetryDelay      = 2 * time.Second
	defaultDeliveryTimeout = 5 * time.Second
	defaultMaxInflight     = 100
	maxNetworkEntries      = 64

	// JWT parameters of courier/config.
	defaultAlg             = "ES256"
	defaultRotationPeriod  = 24 * time.Hour
	defaultMaxTTL          = 30 * time.Minute
	defaultVerificationTTL = time.Hour
	maxVerificationFactor  = 10 // verification_ttl <= 10 x rotation_period

	// Role.
	defaultRoleTTL            = 10 * time.Minute
	defaultMinRequestInterval = 5 * time.Second
	maxReceiptURLs            = 64

	// Parameter bounds.
	minDelivery           = time.Second // retry_delay, delivery_timeout: 1s to 60s
	maxDelivery           = 60 * time.Second
	maxInflightLimit      = 10000
	minRoleTTL            = 2 * clockSkew // twice the clock skew allowance
	maxMinRequestInterval = time.Hour
	maxAudBytes           = 256
	maxCAPEMBytes         = 64 << 10
	maxIssuerBytes        = 2048

	// Fixed timing constants.
	clockSkew  = 60 * time.Second // fixed, not configurable
	jwksMaxAge = 5 * time.Minute  // fixed Cache-Control max-age, not configurable
	// minRotationPeriod is the JWKS max-age plus clock skew (6 minutes).
	minRotationPeriod = jwksMaxAge + clockSkew
)

// Storage keys. The config is ONE entry (it records the mount's type) and the
// whole key set is ONE entry.
const (
	storageConfig     = "config"
	storageKeySet     = "keys/set"
	storageRolePrefix = "roles/"
)
