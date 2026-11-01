package backend

import (
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
)

// tokenClaims are the claims of a delivered token:
// iss, sub (the receipt URL), aud, iat, exp, jti, and nonce only when the request
// supplied one and the role sets nonce_in_token.
type tokenClaims struct {
	jwt.Claims
	Nonce string `json:"nonce,omitempty"`
}

// signToken signs a token for the role with the current key. It reads the key
// set and never writes storage or rotates.
func signToken(ks *keySnapshot, jc *jwtConfig, r *role, receiptURL, nonce string, now time.Time) (string, error) {
	key, err := ks.signingKey(jc.Alg)
	if err != nil {
		return "", err
	}
	signer, err := newSigner(key)
	if err != nil {
		return "", err
	}
	jti, err := newKeyID() // a UUIDv7 per token, same generator as kid
	if err != nil {
		return "", err
	}
	claims := tokenClaims{Claims: jwt.Claims{
		Issuer:   jc.Issuer,
		Subject:  receiptURL,
		Audience: jwt.Audience{r.Aud},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(r.TTL)),
		ID:       jti,
	}}
	if r.NonceInToken && nonce != "" {
		claims.Nonce = nonce
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	return token, nil
}
