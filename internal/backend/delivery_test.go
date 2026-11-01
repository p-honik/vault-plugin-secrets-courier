package backend

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/vault/sdk/logical"
)

// receiver is a TLS server with a certificate for "localhost" that records
// deliveries.
type receiver struct {
	srv    *httptest.Server
	caPEM  string
	mu     sync.Mutex
	posts  []map[string]string
	status []int // status to answer per call; the last one repeats
	calls  int
	redir  string
}

func newReceiver(t *testing.T, status ...int) *receiver {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	rc := &receiver{status: status}
	if len(rc.status) == 0 {
		rc.status = []int{204}
	}
	rc.caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	rc.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc.mu.Lock()
		defer rc.mu.Unlock()
		code := rc.status[min(rc.calls, len(rc.status)-1)]
		rc.calls++
		if err := r.ParseMultipartForm(1 << 20); err == nil {
			post := map[string]string{}
			for k, v := range r.MultipartForm.Value {
				post[k] = v[0]
			}
			rc.posts = append(rc.posts, post)
		}
		if rc.redir != "" {
			http.Redirect(w, r, rc.redir, http.StatusFound)
			return
		}
		w.WriteHeader(code)
	}))
	rc.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	rc.srv.StartTLS()
	t.Cleanup(rc.srv.Close)
	return rc
}

// url is a receipt URL with a DNS host name, as the strict format requires.
func (rc *receiver) url(path string) string {
	u, _ := url.Parse(rc.srv.URL)
	return fmt.Sprintf("https://localhost:%s%s", u.Port(), path)
}

func (rc *receiver) received() []map[string]string {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]map[string]string(nil), rc.posts...)
}

func (rc *receiver) attempts() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.calls
}

// request posts to request/<role> and waits for any started delivery to end.
func (e *env) request(role string, data map[string]interface{}) *logical.Response {
	e.t.Helper()
	resp, err := e.do(logical.UpdateOperation, "request/"+role, data)
	if err != nil {
		e.t.Fatal(err)
	}
	e.b.wg.Wait()
	return resp
}

func TestEndToEndDelivery(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t)
	e.configureJWT(nil)
	e.createRole("billing-svc", map[string]interface{}{
		"allowed_receipt_urls": []string{rc.url("/courier/receive")},
		"receipt_ca_pem":       rc.caPEM,
		"nonce_in_token":       true,
	})

	nonce := "k3Jx9wQ2mZpL7vTa"
	if r := e.request("billing-svc", map[string]interface{}{"receipt_url": rc.url("/courier/receive"), "nonce": nonce}); r != nil {
		t.Fatalf("response = %v, want nil (204)", r)
	}
	posts := rc.received()
	if len(posts) != 1 {
		t.Fatalf("receiver got %d deliveries, want 1", len(posts))
	}
	p := posts[0]
	if p["name"] != "billing-svc" || p["type"] != "jwt" || p["nonce"] != nonce || p["token"] == "" {
		t.Fatalf("delivery fields = %v", p)
	}

	// Verify the token against the published JWKS, as a receiver would.
	var jwks struct{ Keys []json.RawMessage }
	rawBody(t, e.ok(logical.ReadOperation, ".well-known/jwks.json", nil), &jwks)
	set := jose.JSONWebKeySet{}
	for _, k := range jwks.Keys {
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON(k); err != nil {
			t.Fatal(err)
		}
		set.Keys = append(set.Keys, jwk)
	}
	tok, err := jwt.ParseSigned(p["token"], []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	kid := tok.Headers[0].KeyID
	keys := set.Key(kid)
	if len(keys) != 1 {
		t.Fatalf("kid %q not in the JWKS", kid)
	}
	if kid != e.keySet().Current.KID {
		t.Fatal("token must be signed by the current key")
	}
	var claims tokenClaims
	if err := tok.Claims(keys[0], &claims); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	if claims.Issuer != "https://vault.example.com/v1/courier" ||
		claims.Subject != rc.url("/courier/receive") ||
		len(claims.Audience) != 1 || claims.Audience[0] != "payments-api" ||
		claims.Nonce != nonce || claims.ID == "" {
		t.Fatalf("claims = %+v", claims)
	}
	if claims.Expiry.Time().Sub(claims.IssuedAt.Time()) != 10*time.Minute {
		t.Fatalf("exp - iat = %v, want the role ttl", claims.Expiry.Time().Sub(claims.IssuedAt.Time()))
	}
	if tok.Headers[0].ExtraHeaders[jose.HeaderType] != "JWT" {
		t.Fatalf("typ header = %v", tok.Headers[0].ExtraHeaders)
	}
}

func TestNonceOnlyWhenSupplied(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t)
	e.configureJWT(nil)
	e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM, "nonce_in_token": true})
	e.request("r", map[string]interface{}{"receipt_url": rc.url("/x")})
	posts := rc.received()
	if len(posts) != 1 {
		t.Fatalf("got %d deliveries", len(posts))
	}
	if _, has := posts[0]["nonce"]; has {
		t.Fatal("no nonce was supplied: the nonce field must be absent, not empty")
	}
	tok, _ := jwt.ParseSigned(posts[0]["token"], []jose.SignatureAlgorithm{jose.ES256})
	var c map[string]interface{}
	_ = tok.UnsafeClaimsWithoutVerification(&c)
	if _, has := c["nonce"]; has {
		t.Fatal("the nonce claim must be absent when no nonce was supplied")
	}
}

func TestRequestSilentDrops(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t)
	e.configureJWT(nil)
	e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM})

	for name, data := range map[string]struct {
		role string
		body map[string]interface{}
	}{
		"unknown role":       {"nope", map[string]interface{}{"receipt_url": rc.url("/x")}},
		"invalid role name":  {"Bad.Name", map[string]interface{}{"receipt_url": rc.url("/x")}},
		"url not on list":    {"r", map[string]interface{}{"receipt_url": rc.url("/y")}},
		"different spelling": {"r", map[string]interface{}{"receipt_url": rc.url("/x") + "/"}},
	} {
		if r := e.request(data.role, data.body); r != nil {
			t.Errorf("%s: response %v, want the empty 204", name, r)
		}
	}
	if n := rc.attempts(); n != 0 {
		t.Fatalf("drops delivered %d times", n)
	}
	if e.b.state.inflightCount() != 0 || len(e.b.state.lastAccepted) != 0 {
		t.Fatal("a dropped request must allocate no state")
	}
}

func TestRequireNonce(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t)
	e.configureJWT(nil)
	e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM, "require_nonce": true})
	resp, _ := e.do(logical.UpdateOperation, "request/r", map[string]interface{}{"receipt_url": rc.url("/x")})
	if resp == nil || !resp.IsError() {
		t.Fatal("a missing nonce on a require_nonce role must be a 400")
	}
	// An unknown role is still a silent drop, whatever the nonce.
	if resp, _ := e.do(logical.UpdateOperation, "request/nope", map[string]interface{}{"receipt_url": rc.url("/x")}); resp != nil {
		t.Fatal("unknown role must be a silent drop")
	}
	e.request("r", map[string]interface{}{"receipt_url": rc.url("/x"), "nonce": "k3Jx9wQ2mZpL7vTa"})
	if len(rc.received()) != 1 {
		t.Fatal("request with a nonce must be delivered")
	}
}

func TestMinRequestIntervalPerRoleAndURL(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t)
	e.configureJWT(nil)
	for _, name := range []string{"r1", "r2"} {
		e.createRole(name, map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM, "min_request_interval": 5})
	}
	req := map[string]interface{}{"receipt_url": rc.url("/x")}
	e.request("r1", req)
	e.request("r1", req) // inside the interval: dropped
	if n := len(rc.received()); n != 1 {
		t.Fatalf("got %d deliveries, want 1", n)
	}
	e.request("r2", req) // another role, same URL: not suppressed
	if n := len(rc.received()); n != 2 {
		t.Fatalf("got %d deliveries, want 2 (the key is (role, URL))", n)
	}
	e.advance(5 * time.Second)
	e.request("r1", req)
	if n := len(rc.received()); n != 3 {
		t.Fatalf("got %d deliveries, want 3 after the interval", n)
	}
}

func TestRetryPolicy(t *testing.T) {
	cases := []struct {
		name     string
		retry    string
		statuses []int
		want     int // attempts
	}{
		{"never, 503", "never", []int{503, 204}, 1},
		{"once, 503 then ok", "once", []int{503, 204}, 2},
		{"once, 503 twice", "once", []int{503, 503, 204}, 2},
		{"once, 4xx is final", "once", []int{400, 204}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			rc := newReceiver(t, c.statuses...)
			e.configureJWT(map[string]interface{}{"delivery_retry": c.retry, "retry_delay": 1, "delivery_timeout": 2})
			e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM})
			e.request("r", map[string]interface{}{"receipt_url": rc.url("/x"), "nonce": "k3Jx9wQ2mZpL7vTa"})
			if got := rc.attempts(); got != c.want {
				t.Fatalf("attempts = %d, want %d", got, c.want)
			}
			posts := rc.received()
			for _, p := range posts {
				if p["nonce"] != "k3Jx9wQ2mZpL7vTa" {
					t.Fatalf("every attempt must carry the same nonce: %v", posts)
				}
			}
			if e.b.state.inflightCount() != 0 {
				t.Fatal("the in-flight entry must be removed when the delivery ends")
			}
		})
	}
}

func TestRetryResendsSameToken(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t, 503, 204)
	e.configureJWT(map[string]interface{}{"delivery_retry": "once", "retry_delay": 1, "delivery_timeout": 2})
	e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM})
	var tokens []string
	rc.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseMultipartForm(1 << 20)
		rc.mu.Lock()
		tokens = append(tokens, r.MultipartForm.Value["token"][0])
		n := len(tokens)
		rc.mu.Unlock()
		if n == 1 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	})
	e.request("r", map[string]interface{}{"receipt_url": rc.url("/x")})
	if len(tokens) != 2 || tokens[0] != tokens[1] {
		t.Fatalf("a retry must resend the same token (same jti): %v", tokens)
	}
}

func TestRedirectsAreNeverFollowed(t *testing.T) {
	e := newEnv(t)
	other := newReceiver(t)
	rc := newReceiver(t)
	rc.redir = other.url("/elsewhere")
	e.configureJWT(map[string]interface{}{"delivery_retry": "once", "retry_delay": 1})
	e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM})
	e.request("r", map[string]interface{}{"receipt_url": rc.url("/x")})
	if other.attempts() != 0 {
		t.Fatal("a redirect was followed")
	}
	if rc.attempts() != 1 {
		t.Fatalf("a 3xx is final and must not be retried, attempts = %d", rc.attempts())
	}
}

func TestVerifiedTLSIsRequired(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t)
	e.configureJWT(nil)
	// No receipt_ca_pem: the test certificate is not in the system roots.
	e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}})
	e.request("r", map[string]interface{}{"receipt_url": rc.url("/x")})
	if rc.attempts() != 0 {
		t.Fatal("the token was delivered over an unverified TLS connection")
	}
}

func TestNetworkPolicyBlocksDeliveryAndIsFinal(t *testing.T) {
	rc := newReceiver(t)
	d := &delivery{
		roleName: "r", credential: "jwt", token: "t", receiptURL: rc.url("/x"),
		retry: true, retryDelay: time.Second, deliveryTimeout: 2 * time.Second, caPEM: rc.caPEM,
		policy: func() *networkPolicy { p, _ := newNetworkPolicy(nil, []string{"127.0.0.0/8", "::1/128"}); return p },
	}
	class, attempts := d.run(t.Context())
	if class != failureBlockedAddress || attempts != 1 {
		t.Fatalf("class %q after %d attempts, want blocked_address after 1 (final, no retry)", class, attempts)
	}
	if rc.attempts() != 0 {
		t.Fatal("a blocked address must never be connected to")
	}

	// An allowed_networks list that contains the receiver permits it.
	d.policy = func() *networkPolicy { p, _ := newNetworkPolicy([]string{"127.0.0.0/8", "::1/128"}, nil); return p }
	if class, _ := d.run(t.Context()); class != "" {
		t.Fatalf("class = %q, want delivered", class)
	}
}

func TestNetworkPolicyTighteningAppliesToRetry(t *testing.T) {
	rc := newReceiver(t, 503, 204)
	var mu sync.Mutex
	block := false
	d := &delivery{
		roleName: "r", credential: "jwt", token: "t", receiptURL: rc.url("/x"),
		retry: true, retryDelay: time.Second, deliveryTimeout: 2 * time.Second, caPEM: rc.caPEM,
		policy: func() *networkPolicy {
			mu.Lock()
			defer mu.Unlock()
			if block {
				p, _ := newNetworkPolicy(nil, []string{"127.0.0.0/8", "::1/128"})
				return p
			}
			return &networkPolicy{}
		},
	}
	go func() { // tighten while the retry waits
		time.Sleep(300 * time.Millisecond)
		mu.Lock()
		block = true
		mu.Unlock()
	}()
	class, attempts := d.run(t.Context())
	if class != failureBlockedAddress || attempts != 2 || rc.attempts() != 1 {
		t.Fatalf("class %q, attempts %d, receiver calls %d: the retry must see the tightened policy", class, attempts, rc.attempts())
	}
}

func TestProxyEnvironmentIsIgnored(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	rc := newReceiver(t)
	d := &delivery{
		roleName: "r", credential: "jwt", token: "t", receiptURL: rc.url("/x"),
		deliveryTimeout: 2 * time.Second, caPEM: rc.caPEM, policy: func() *networkPolicy { return &networkPolicy{} },
	}
	if class, _ := d.run(t.Context()); class != "" {
		t.Fatalf("class = %q: the delivery client must connect directly", class)
	}
}

func TestMaxInflight(t *testing.T) {
	s := newRateState()
	now := time.Now()
	r1, ok := s.reserve("a", "u1", "", now, time.Second, 2)
	if !ok {
		t.Fatal("first reservation refused")
	}
	if _, ok := s.reserve("a", "u1", "", now, 0, 2); ok {
		t.Fatal("duplicate in flight must be dropped")
	}
	if _, ok := s.reserve("a", "u2", "", now, time.Second, 2); !ok {
		t.Fatal("second reservation refused")
	}
	// max_inflight reached: dropped, and the drop leaves no timer behind.
	if _, ok := s.reserve("a", "u3", "", now, time.Second, 2); ok {
		t.Fatal("max_inflight must drop")
	}
	if _, has := s.lastAccepted[roleURL{"a", "u3"}]; has {
		t.Fatal("a dropped request must not refresh or create a timer")
	}
	r1.finish()
	if _, ok := s.reserve("a", "u3", "", now, time.Second, 2); !ok {
		t.Fatal("a freed slot must be usable at once")
	}
}

func TestReservationAbortRestoresTimer(t *testing.T) {
	s := newRateState()
	t0 := time.Now()
	r, _ := s.reserve("a", "u", "", t0, time.Second, 10)
	r.finish()
	t1 := t0.Add(2 * time.Second)
	r2, ok := s.reserve("a", "u", "", t1, time.Second, 10)
	if !ok {
		t.Fatal("refused after the interval")
	}
	r2.abort()
	if got := s.lastAccepted[roleURL{"a", "u"}]; !got.Equal(t0) {
		t.Fatalf("abort must restore the previous timestamp, got %v", got)
	}
	if s.inflightCount() != 0 {
		t.Fatal("abort must remove the in-flight entry")
	}
}

func TestDuplicateAcrossNonces(t *testing.T) {
	s := newRateState()
	now := time.Now()
	if _, ok := s.reserve("a", "u", "n1", now, 0, 10); !ok {
		t.Fatal("refused")
	}
	// With the interval at 0 only duplicates and max_inflight apply: another
	// nonce is not a duplicate.
	if _, ok := s.reserve("a", "u", "n2", now, 0, 10); !ok {
		t.Fatal("a different nonce must not be coalesced")
	}
	if _, ok := s.reserve("a", "u", "n1", now, 0, 10); ok {
		t.Fatal("the same nonce in flight must be coalesced")
	}
}

func TestEvict(t *testing.T) {
	s := newRateState()
	t0 := time.Now()
	s.lastAccepted[roleURL{"keep", "u"}] = t0
	s.lastAccepted[roleURL{"expired", "u"}] = t0.Add(-time.Hour)
	s.lastAccepted[roleURL{"gone", "u"}] = t0
	s.evict(t0, func(role, _ string) (time.Duration, bool) {
		if role == "gone" {
			return 0, false
		}
		return time.Minute, true
	})
	if len(s.lastAccepted) != 1 {
		t.Fatalf("lastAccepted = %v", s.lastAccepted)
	}
	if _, ok := s.lastAccepted[roleURL{"keep", "u"}]; !ok {
		t.Fatal("wrong entry kept")
	}
}

func TestCleanCancelsDeliveryContext(t *testing.T) {
	e := newEnv(t)
	ctx := e.b.deliveryContext()
	e.b.clean(ctx)
	select {
	case <-ctx.Done():
	default:
		t.Fatal("clean must cancel the delivery context")
	}
}
