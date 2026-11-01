package backend

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

// Key handling. Keys are go-jose JSONWebKeys; the private
// and public halves are stored as JWK JSON inside the single keys/set entry.
// Everything here is pure (no storage, no clock) so rotation can be tested by
// passing in the time.

const rsaBits = 2048

// newKeyID returns a UUIDv7. The kid is generated once,
// when the key pair is created, and never changes.
func newKeyID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// generateKey creates a key pair for alg and returns its kid and the JWK JSON of
// the private and the public half.
func generateKey(alg string) (kid string, private, public []byte, err error) {
	var key interface{}
	switch alg {
	case "ES256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "RS256":
		key, err = rsa.GenerateKey(rand.Reader, rsaBits)
	default:
		return "", nil, nil, fmt.Errorf("unsupported alg %q", alg)
	}
	if err != nil {
		return "", nil, nil, err
	}
	if kid, err = newKeyID(); err != nil {
		return "", nil, nil, err
	}
	jwk := jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: alg, Use: "sig"}
	if private, err = jwk.MarshalJSON(); err != nil {
		return "", nil, nil, err
	}
	pub := jwk.Public()
	if public, err = pub.MarshalJSON(); err != nil {
		return "", nil, nil, err
	}
	return kid, private, public, nil
}

// genKey is generateKey; tests replace it to inject a key-generation failure.
var genKey = generateKey

func newNextKey(alg string, now time.Time) (*nextKey, error) {
	kid, priv, pub, err := genKey(alg)
	if err != nil {
		return nil, err
	}
	return &nextKey{KID: kid, Private: priv, Public: pub, NotBefore: now.Add(jwksMaxAge + clockSkew)}, nil
}

func newCurrentKey(alg string, now time.Time, maxTTL time.Duration) (*currentKey, error) {
	kid, priv, pub, err := genKey(alg)
	if err != nil {
		return nil, err
	}
	return &currentKey{KID: kid, Private: priv, Public: pub, RotatedAt: now, LongestTTL: maxTTL}, nil
}

// newKeySet builds the initial key set written by the first config write:
// both current and next, with next_rotation = now + rotation_period.
func newKeySet(jc *jwtConfig, now time.Time) (*keySet, error) {
	cur, err := newCurrentKey(jc.Alg, now, jc.MaxTTL)
	if err != nil {
		return nil, err
	}
	next, err := newNextKey(jc.Alg, now)
	if err != nil {
		return nil, err
	}
	return &keySet{Current: cur, Next: next, NextRotation: now.Add(jc.RotationPeriod)}, nil
}

// keySetAlg returns the algorithm of the stored keys.
func keySetAlg(ks *keySet) (string, error) {
	if ks == nil || ks.Current == nil {
		return "", errors.New("key set has no current key")
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(ks.Current.Public); err != nil {
		return "", err
	}
	return jwk.Algorithm, nil
}

// retireAt is the time an old current key leaves the JWKS:
// now + max(verification_ttl, longest_ttl + JWKS max-age + clock skew).
func retireAt(now time.Time, jc *jwtConfig, longestTTL time.Duration) time.Time {
	d := longestTTL + jwksMaxAge + clockSkew
	if jc.VerificationTTL > d {
		d = jc.VerificationTTL
	}
	return now.Add(d)
}

// retire moves the current key into previous, public half only.
func (ks *keySet) retireCurrent(now time.Time, jc *jwtConfig) {
	ks.Previous = append(ks.Previous, retiredKey{
		KID:      ks.Current.KID,
		Public:   ks.Current.Public,
		RetireAt: retireAt(now, jc, ks.Current.LongestTTL),
	})
}

// dropExpired removes retired keys past their retire_at and reports whether it
// removed any. They hold no private key, so there is nothing secret to wipe.
func (ks *keySet) dropExpired(now time.Time) bool {
	expired := 0
	for _, p := range ks.Previous {
		if !now.Before(p.RetireAt) {
			expired++
		}
	}
	if expired == 0 {
		return false // nothing to drop: no allocation
	}
	kept := make([]retiredKey, 0, len(ks.Previous)-expired)
	for _, p := range ks.Previous {
		if now.Before(p.RetireAt) {
			kept = append(kept, p)
		}
	}
	ks.Previous = kept
	return true
}

// rotationDue reports whether the tick must rotate: now >= next_rotation and
// now >= next.not_before.
func (ks *keySet) rotationDue(now time.Time) bool {
	return !now.Before(ks.NextRotation) && !now.Before(ks.Next.NotBefore)
}

// rotateScheduled performs the scheduled rotation.
// It generates one key, so with RS256 it can take a moment.
func (ks *keySet) rotateScheduled(jc *jwtConfig, now time.Time) error {
	newNext, err := newNextKey(jc.Alg, now)
	if err != nil {
		return err
	}
	ks.retireCurrent(now, jc)
	ks.Current = &currentKey{
		KID: ks.Next.KID, Private: ks.Next.Private, Public: ks.Next.Public,
		RotatedAt: now, LongestTTL: jc.MaxTTL,
	}
	ks.Next = newNext
	ks.dropExpired(now)
	ks.NextRotation = now.Add(jc.RotationPeriod)
	return nil
}

// rotateManual performs keys/rotate: a fresh current is installed at once
// (the stored next is never promoted) and next is replaced by another fresh key.
// With revokePrevious every retired key, including the one just replaced, is
// dropped from the JWKS.
func (ks *keySet) rotateManual(jc *jwtConfig, now time.Time, revokePrevious bool) error {
	cur, err := newCurrentKey(jc.Alg, now, jc.MaxTTL)
	if err != nil {
		return err
	}
	next, err := newNextKey(jc.Alg, now)
	if err != nil {
		return err
	}
	ks.retireCurrent(now, jc)
	if revokePrevious {
		ks.Previous = nil
	}
	ks.Current = cur
	ks.Next = next
	ks.dropExpired(now)
	ks.NextRotation = now.Add(jc.RotationPeriod)
	return nil
}

// applyConfigChange updates the stored key state after a config write on
// existing keys.
//
// It reports whether the key set changed, so a config write that changes
// nothing about the keys does not rewrite the private keys.
func (ks *keySet) applyConfigChange(old, new *jwtConfig) (changed bool) {
	if new.MaxTTL > ks.Current.LongestTTL {
		ks.Current.LongestTTL = new.MaxTTL
		changed = true
	}
	if old.RotationPeriod != new.RotationPeriod {
		next := ks.Current.RotatedAt.Add(new.RotationPeriod)
		if next.Before(ks.Next.NotBefore) {
			next = ks.Next.NotBefore
		}
		if !next.Equal(ks.NextRotation) {
			ks.NextRotation = next
			changed = true
		}
	}
	return changed
}

// publicJWKS returns the JWK JSON of every key that belongs in the JWKS: current,
// next and the unexpired retired keys.
func (ks *keySet) publicJWKS(now time.Time) []json.RawMessage {
	var keys []json.RawMessage
	if ks.Current != nil {
		keys = append(keys, ks.Current.Public)
	}
	if ks.Next != nil {
		keys = append(keys, ks.Next.Public)
	}
	for _, p := range ks.Previous {
		if now.Before(p.RetireAt) {
			keys = append(keys, p.Public)
		}
	}
	return keys
}

// newSigner returns a go-jose signer for a parsed signing key.
func newSigner(key jose.SigningKey) (jose.Signer, error) {
	return jose.NewSigner(key, (&jose.SignerOptions{}).WithType("JWT"))
}
