package backend

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Cross-validation rules between settings. Every function here is pure so
// it can be run on the merged configuration under the configuration lock.

// deliveryWindow is retry_delay + 2 x delivery_timeout when delivery_retry is
// "once", and delivery_timeout when it is "never".
func deliveryWindow(mc *mountConfig) time.Duration {
	if mc.DeliveryRetry == "once" {
		return mc.RetryDelay + 2*mc.DeliveryTimeout
	}
	return mc.DeliveryTimeout
}

// validateMountConfig checks the delivery settings of a merged config.
func validateMountConfig(mc *mountConfig) error {
	if mc.DeliveryRetry != "never" && mc.DeliveryRetry != "once" {
		return errors.New("delivery_retry must be never or once")
	}
	if mc.RetryDelay < minDelivery || mc.RetryDelay > maxDelivery {
		return fmt.Errorf("retry_delay must be between 1s and 60s, got %s after truncation to whole seconds", mc.RetryDelay)
	}
	if mc.DeliveryTimeout < minDelivery || mc.DeliveryTimeout > maxDelivery {
		return fmt.Errorf("delivery_timeout must be between 1s and 60s, got %s after truncation to whole seconds", mc.DeliveryTimeout)
	}
	if mc.MaxInflight < 1 || mc.MaxInflight > maxInflightLimit {
		return fmt.Errorf("max_inflight must be between 1 and %d", maxInflightLimit)
	}
	if _, err := newNetworkPolicy(mc.AllowedNetworks, mc.DeniedNetworks); err != nil {
		return err
	}
	return nil
}

// validateRolesAgainstWindow rejects delivery settings under which an existing
// role's ttl would no longer exceed the delivery window.
func validateRolesAgainstWindow(mc *mountConfig, roles map[string]*role) error {
	window := deliveryWindow(mc)
	for name, r := range roles {
		if r.TTL <= window {
			return fmt.Errorf("role %q ttl %s would no longer exceed the delivery window %s", name, r.TTL, window)
		}
	}
	return nil
}

// validateJWTConfig checks the merged JWT parameters and their effect on the existing
// jwt roles.
func validateJWTConfig(jc *jwtConfig, roles map[string]*role) error {
	if err := validateIssuer(jc.Issuer); err != nil {
		return err
	}
	if jc.Alg != "ES256" && jc.Alg != "RS256" {
		return errors.New("alg must be ES256 or RS256")
	}
	if jc.RotationPeriod < minRotationPeriod {
		return fmt.Errorf("rotation_period must be at least %s, got %s after truncation to whole seconds", minRotationPeriod, jc.RotationPeriod)
	}
	if jc.MaxTTL <= 0 {
		return errors.New("max_ttl must be positive")
	}
	if min := jc.MaxTTL + jwksMaxAge + clockSkew; jc.VerificationTTL < min {
		return fmt.Errorf("verification_ttl must be at least max_ttl plus the JWKS max-age plus clock skew (%s), got %s after truncation to whole seconds", min, jc.VerificationTTL)
	}
	if max := time.Duration(maxVerificationFactor) * jc.RotationPeriod; jc.VerificationTTL > max {
		return fmt.Errorf("verification_ttl must be at most 10 x rotation_period (%s), got %s after truncation to whole seconds", max, jc.VerificationTTL)
	}
	for name, r := range roles {
		if r.TTL > jc.MaxTTL {
			return fmt.Errorf("max_ttl is below the ttl of role %q", name)
		}
	}
	return nil
}

// validateIssuer: an https URL with no query or fragment (OIDC requirement).
func validateIssuer(issuer string) error {
	if issuer == "" {
		return errors.New("issuer is required")
	}
	if len(issuer) > maxIssuerBytes {
		return fmt.Errorf("issuer must be at most %d bytes", maxIssuerBytes)
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("issuer must be an https URL")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return errors.New("issuer must not contain a query or fragment")
	}
	if u.User != nil {
		return errors.New("issuer must not contain userinfo")
	}
	if strings.HasSuffix(issuer, "/") {
		return errors.New("issuer must not end with a slash")
	}
	return nil
}

// validateRoleGeneric checks the delivery fields every type shares.
func validateRoleGeneric(name string, r *role) error {
	if !validRoleName(name) {
		return errors.New("role name must match [a-z0-9]([a-z0-9_-]*[a-z0-9])? and be at most 64 characters")
	}
	if len(r.AllowedReceiptURLs) == 0 {
		return errors.New("allowed_receipt_urls is required")
	}
	if len(r.AllowedReceiptURLs) > maxReceiptURLs {
		return fmt.Errorf("allowed_receipt_urls has more than %d entries", maxReceiptURLs)
	}
	seen := make(map[string]bool, len(r.AllowedReceiptURLs))
	for _, u := range r.AllowedReceiptURLs {
		if err := validateReceiptURL(u); err != nil {
			return fmt.Errorf("allowed_receipt_urls: %w", err)
		}
		if seen[u] {
			return errors.New("allowed_receipt_urls contains a duplicate entry")
		}
		seen[u] = true
	}
	if r.MinRequestInterval < 0 || r.MinRequestInterval > maxMinRequestInterval {
		return fmt.Errorf("min_request_interval must be between 0 and 1h, got %s after truncation to whole seconds", r.MinRequestInterval)
	}
	return validateCAPEM(r.ReceiptCAPEM)
}

// validateJWTRole checks the jwt fields of a role against the config. jc is nil
// when the config has not been written.
func validateJWTRole(r *role, mc *mountConfig, jc *jwtConfig) error {
	if err := validateAud(r.Aud); err != nil {
		return err
	}
	if jc == nil {
		return errors.New("a role cannot be created before config is written")
	}
	if r.TTL < minRoleTTL {
		return fmt.Errorf("ttl must be at least %s (twice the clock skew), got %s after truncation to whole seconds", minRoleTTL, r.TTL)
	}
	if r.TTL > jc.MaxTTL {
		return fmt.Errorf("ttl must not exceed max_ttl (%s), got %s after truncation to whole seconds", jc.MaxTTL, r.TTL)
	}
	if window := deliveryWindow(mc); r.TTL <= window {
		return fmt.Errorf("ttl must exceed the delivery window (%s), got %s after truncation to whole seconds", window, r.TTL)
	}
	return nil
}

func validateAud(aud string) error {
	if aud == "" {
		return errors.New("aud is required for type jwt")
	}
	if len(aud) > maxAudBytes {
		return fmt.Errorf("aud must be at most %d bytes", maxAudBytes)
	}
	for i := 0; i < len(aud); i++ {
		if aud[i] < 0x20 || aud[i] == 0x7f {
			return errors.New("aud must not contain control characters")
		}
	}
	return nil
}

// validateCAPEM: empty is allowed (system roots). Otherwise at least one PEM
// CERTIFICATE block and nothing else: any other block, a private key above all,
// is rejected because the value is stored and returned on role reads.
func validateCAPEM(pemData string) error {
	if pemData == "" {
		return nil
	}
	if len(pemData) > maxCAPEMBytes {
		return fmt.Errorf("receipt_ca_pem must be at most %d bytes", maxCAPEMBytes)
	}
	rest := []byte(pemData)
	certs := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return errors.New("receipt_ca_pem may contain CERTIFICATE blocks only")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return errors.New("receipt_ca_pem contains an invalid certificate")
		}
		certs++
	}
	if certs == 0 {
		return errors.New("receipt_ca_pem contains no PEM certificate")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("receipt_ca_pem may contain CERTIFICATE blocks only")
	}
	return nil
}
