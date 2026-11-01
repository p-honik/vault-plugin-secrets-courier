package backend

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func benchEnv(b *testing.B, alg string) *env {
	e := newEnv(b)
	e.configureJWT(map[string]interface{}{"alg": alg})
	e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{"https://localhost:1/x"}, "min_request_interval": 3600})
	return e
}

// JWKS: the public, unauthenticated GET that verifiers and probes hit.
func BenchmarkJWKS(b *testing.B) {
	for _, alg := range []string{"ES256", "RS256"} {
		b.Run(alg, func(b *testing.B) {
			e := benchEnv(b, alg)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				e.do(logical.ReadOperation, ".well-known/jwks.json", nil)
			}
		})
	}
}

// A request dropped by the interval: the flood case.
func BenchmarkRequestDroppedByInterval(b *testing.B) {
	e := benchEnv(b, "ES256")
	req := map[string]interface{}{"receipt_url": "https://localhost:1/x"}
	e.b.state.lastAccepted[roleURL{"r", "https://localhost:1/x"}] = e.clock
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.do(logical.UpdateOperation, "request/r", req)
	}
}

// A request for an unknown role.
func BenchmarkRequestUnknownRole(b *testing.B) {
	e := benchEnv(b, "ES256")
	req := map[string]interface{}{"receipt_url": "https://localhost:1/x"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.do(logical.UpdateOperation, "request/nope", req)
	}
}

// Signing a token as the handler does for an accepted request.
func BenchmarkSignToken(b *testing.B) {
	for _, alg := range []string{"ES256", "RS256"} {
		b.Run(alg, func(b *testing.B) {
			e := benchEnv(b, alg)
			ctx := context.Background()
			jc, _ := loadJWTConfig(ctx, e.s)
			ks, _ := e.b.cachedKeySet(ctx, e.s)
			r, _ := loadRole(ctx, e.s, "r")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := signToken(ks, jc, r, "https://localhost:1/x", "", time.Now()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkReserve(b *testing.B) {
	s := newRateState()
	now := time.Now()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if r, ok := s.reserve("r", "u", "", now.Add(time.Duration(i)*time.Hour), time.Second, 100); ok {
			r.finish()
		}
	}
}

func BenchmarkValidateReceiptURL(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = validateReceiptURL("https://billing.internal/courier/receive")
	}
}
