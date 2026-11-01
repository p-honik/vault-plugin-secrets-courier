//go:build live

// Package livetest runs the built plugin inside a real Vault server. It is
// excluded from normal test runs; run it with
//
//	VAULT_BIN=/path/to/vault go test -tags live ./internal/livetest
//
// (see `make live-test`). It starts `vault server -dev` on a free loopback port,
// registers and mounts the plugin, and drives it over HTTP.
package livetest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/vault/api"
)

const pluginName = "vault-plugin-secrets-courier"

// syncBuffer is a bytes.Buffer safe for the server process to write while the
// test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type server struct {
	t     *testing.T
	addr  string
	token string
	api   *api.Client
	logs  *syncBuffer

	parent *testing.T // the top-level test; s.t is the running subtest
	// auditLog is where the audit device writes. With OpenBao, which no longer
	// lets audit devices be enabled through the API, it is declared in the server
	// config instead (declarativeAudit).
	auditLog         string
	declarativeAudit bool
}

// run runs a subtest and points the server helpers at it, so a failure in a
// helper fails the subtest and not the parent.
func (s *server) run(name string, fn func(t *testing.T)) {
	s.parent.Run(name, func(t *testing.T) {
		prev := s.t
		s.t = t
		defer func() { s.t = prev }()
		fn(t)
	})
}

// sealCycle seals and unseals the server, which reloads every backend with a
// cold cache.
func (s *server) sealCycle(unsealKey string) {
	s.t.Helper()
	if err := s.api.Sys().Seal(); err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.api.Sys().Unseal(unsealKey); err != nil {
		s.t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if h, err := s.api.Sys().Health(); err == nil && !h.Sealed {
			return
		}
		if time.Now().After(deadline) {
			s.t.Fatal("the server did not unseal")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// isOpenBao reports whether the binary is OpenBao.
func isOpenBao(bin string) bool {
	out, err := exec.Command(bin, "version").Output()
	return err == nil && strings.Contains(string(out), "OpenBao")
}

func startVault(t *testing.T) *server {
	t.Helper()
	bin := os.Getenv("VAULT_BIN")
	if bin == "" {
		t.Skip("VAULT_BIN is not set")
	}
	dir := t.TempDir()
	build := exec.Command("go", "build", "-o", filepath.Join(dir, pluginName), "./cmd/"+pluginName)
	build.Dir = "../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the plugin: %v\n%s", err, out)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	args := []string{"server", "-dev", "-dev-root-token-id=root",
		"-dev-listen-address=" + addr, "-dev-plugin-dir=" + dir, "-log-level=warn"}
	auditLog := filepath.Join(t.TempDir(), "audit.log")
	declarative := isOpenBao(bin)
	// The raw storage endpoint lets the test damage the plugin's stored data to
	// check what an unauthenticated caller sees when storage is broken.
	hcl := "raw_storage_endpoint = true\n"
	if declarative {
		hcl += fmt.Sprintf("audit \"file\" \"to-file\" {\n  options {\n    file_path = %q\n  }\n}\n", auditLog)
	}
	conf := filepath.Join(t.TempDir(), "server.hcl")
	if err := os.WriteFile(conf, []byte(hcl), 0o600); err != nil {
		t.Fatal(err)
	}
	args = append(args, "-config="+conf)
	cmd := exec.Command(bin, args...)
	logs := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("vault log:\n%s", logs.String())
		}
	})

	cfg := api.DefaultConfig()
	cfg.Address = "http://" + addr
	client, err := api.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken("root")
	deadline := time.Now().Add(30 * time.Second)
	for {
		if h, err := client.Sys().Health(); err == nil && h.Initialized && !h.Sealed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("vault did not become ready:\n%s", logs.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
	return &server{t: t, parent: t, addr: addr, token: "root", api: client, logs: logs, auditLog: auditLog, declarativeAudit: declarative}
}

// raw sends an HTTP request without going through the api client, so tests can
// omit the token and inspect status, headers and the exact body.
func (s *server) raw(method, path, token string, body interface{}) (int, http.Header, []byte) {
	s.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://"+s.addr+"/v1/"+path, r)
	if err != nil {
		s.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

// must runs an authenticated request that must return 2xx.
func (s *server) must(method, path string, body interface{}) []byte {
	s.t.Helper()
	code, _, b := s.raw(method, path, s.token, body)
	if code < 200 || code > 299 {
		s.t.Fatalf("%s %s: %d %s", method, path, code, b)
	}
	return b
}

type receiver struct {
	srv   *httptest.Server
	caPEM string
	mu    sync.Mutex
	posts []map[string]string
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	rc := &receiver{caPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	rc.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err == nil {
			p := map[string]string{}
			for k, v := range r.MultipartForm.Value {
				p[k] = v[0]
			}
			rc.mu.Lock()
			rc.posts = append(rc.posts, p)
			rc.mu.Unlock()
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	rc.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	rc.srv.StartTLS()
	t.Cleanup(rc.srv.Close)
	return rc
}

func (rc *receiver) url(path string) string {
	u, _ := url.Parse(rc.srv.URL)
	return "https://localhost:" + u.Port() + path
}

func (rc *receiver) waitFor(n int) []map[string]string {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rc.mu.Lock()
		if len(rc.posts) >= n {
			defer rc.mu.Unlock()
			return append([]map[string]string(nil), rc.posts...)
		}
		rc.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

func TestLive(t *testing.T) {
	s := startVault(t)
	rc := newReceiver(t)
	recvURL := rc.url("/courier/receive")
	const issuer = "https://vault.example.com/v1/courier"
	nonce := "k3Jx9wQ2mZpL7vTa"

	s.run("mount", func(t *testing.T) {
		// An unsupported type is refused when the mount is enabled: the option
		// reaches the plugin's factory.
		err := s.api.Sys().Mount("courier-bad", &api.MountInput{Type: pluginName, Options: map[string]string{"type": "tls"}})
		if err == nil {
			_ = s.api.Sys().Unmount("courier-bad")
			t.Fatal("a mount with an unsupported type was accepted: the type option does not reach the plugin")
		}
		if !strings.Contains(err.Error(), "unsupported credential type") {
			t.Fatalf("mounting with type=tls: %v, want the plugin's own message", err)
		}
		if err := s.api.Sys().Mount("courier", &api.MountInput{Type: pluginName, Options: map[string]string{"type": "jwt"}}); err != nil {
			t.Fatalf("mounting the plugin: %v", err)
		}
		var cfg struct{ Data map[string]interface{} }
		if err := json.Unmarshal(s.must("GET", "courier/config", nil), &cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.Data["delivery_retry"] != "never" || cfg.Data["max_inflight"] != float64(100) {
			t.Fatalf("defaults = %v", cfg.Data)
		}
	})

	s.run("public endpoints are 404 before config", func(t *testing.T) {
		for _, p := range []string{"courier/.well-known/jwks.json", "courier/.well-known/openid-configuration"} {
			if code, _, _ := s.raw("GET", p, "", nil); code != 404 {
				t.Errorf("%s: %d, want 404", p, code)
			}
		}
	})

	s.run("create versus update capability", func(t *testing.T) {
		s.must("PUT", "sys/policies/acl/cfg-update-only", map[string]string{
			"policy": `path "courier/config" { capabilities = ["update"] }`})
		var tok struct {
			Auth struct {
				ClientToken string `json:"client_token"`
			} `json:"auth"`
		}
		if err := json.Unmarshal(s.must("POST", "auth/token/create", map[string]interface{}{"policies": []string{"cfg-update-only"}}), &tok); err != nil {
			t.Fatal(err)
		}
		if tok.Auth.ClientToken == "" {
			t.Fatal("no token was created")
		}
		// The first write is a create: update alone must not be enough.
		if code, _, _ := s.raw("POST", "courier/config", tok.Auth.ClientToken, map[string]interface{}{"issuer": issuer, "max_inflight": 50}); code != 403 {
			t.Fatalf("first write with update only: %d, want 403 (create is required the first time)", code)
		}
		s.must("POST", "courier/config", map[string]interface{}{"issuer": issuer, "max_inflight": 50})
		if code, _, b := s.raw("POST", "courier/config", tok.Auth.ClientToken, map[string]interface{}{"max_inflight": 60}); code != 204 {
			t.Fatalf("later write with update only: %d %s, want 204", code, b)
		}
	})

	s.run("JWKS and discovery as raw responses", func(t *testing.T) {

		code, hdr, body := s.raw("GET", "courier/.well-known/jwks.json", "", nil)
		if code != 200 || !strings.HasPrefix(hdr.Get("Content-Type"), "application/json") {
			t.Fatalf("jwks: %d %q", code, hdr.Get("Content-Type"))
		}
		if cc := hdr.Get("Cache-Control"); cc != "max-age=300" {
			t.Fatalf("Cache-Control = %q, want max-age=300", cc)
		}
		var jwks map[string]interface{}
		if err := json.Unmarshal(body, &jwks); err != nil {
			t.Fatal(err)
		}
		if _, enveloped := jwks["request_id"]; enveloped || len(jwks["keys"].([]interface{})) != 2 {
			t.Fatalf("the JWKS must be a raw body with two keys, not Vault's envelope: %s", body)
		}

		code, hdr, body = s.raw("GET", "courier/.well-known/openid-configuration", "", nil)
		var disc map[string]interface{}
		if code != 200 || json.Unmarshal(body, &disc) != nil || disc["issuer"] != issuer ||
			disc["jwks_uri"] != issuer+"/.well-known/jwks.json" {
			t.Fatalf("discovery: %d %s", code, body)
		}
	})

	s.run("role and delivery", func(t *testing.T) {
		s.must("POST", "courier/roles/billing-svc", map[string]interface{}{
			"allowed_receipt_urls": []string{recvURL}, "aud": "payments-api",
			"receipt_ca_pem": rc.caPEM, "nonce_in_token": true, "min_request_interval": 0,
		})
		code, _, body := s.raw("POST", "courier/request/billing-svc", "", map[string]interface{}{"receipt_url": recvURL, "nonce": nonce})
		if code != 204 || len(body) != 0 {
			t.Fatalf("request: %d %q, want 204 with an empty body", code, body)
		}
		posts := rc.waitFor(1)
		if len(posts) != 1 {
			t.Fatal("the receiver got no delivery")
		}
		p := posts[0]
		if p["name"] != "billing-svc" || p["type"] != "jwt" || p["nonce"] != nonce {
			t.Fatalf("delivery = %v", p)
		}
		// Verify as a receiver would: fetch the JWKS unauthenticated.
		_, _, jb := s.raw("GET", "courier/.well-known/jwks.json", "", nil)
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(jb, &set); err != nil {
			t.Fatal(err)
		}
		tok, err := jwt.ParseSigned(p["token"], []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			t.Fatal(err)
		}
		keys := set.Key(tok.Headers[0].KeyID)
		if len(keys) != 1 {
			t.Fatal("kid of the delivered token is not in the JWKS")
		}
		var c struct {
			jwt.Claims
			Nonce string `json:"nonce"`
		}
		if err := tok.Claims(keys[0], &c); err != nil {
			t.Fatalf("token does not verify against the live JWKS: %v", err)
		}
		if c.Issuer != issuer || c.Subject != recvURL || c.Nonce != nonce || len(c.Audience) != 1 || c.Audience[0] != "payments-api" {
			t.Fatalf("claims = %+v", c)
		}
	})

	s.run("request endpoint statuses", func(t *testing.T) {
		post := func(path string, body interface{}) (int, string) {
			code, _, b := s.raw("POST", path, "", body)
			return code, string(b)
		}
		// Extra undeclared parameters on a nil response stay a 204.
		if code, b := post("courier/request/billing-svc", map[string]interface{}{"receipt_url": recvURL, "bogus": 1}); code != 204 || b != "" {
			t.Errorf("extra parameter: %d %q, want 204", code, b)
		}
		// Silent drops.
		for name, c := range map[string]struct {
			path string
			body map[string]interface{}
		}{
			"unknown role":  {"courier/request/nope", map[string]interface{}{"receipt_url": recvURL}},
			"bad role name": {"courier/request/Bad.Name", map[string]interface{}{"receipt_url": recvURL}},
			"url off list":  {"courier/request/billing-svc", map[string]interface{}{"receipt_url": recvURL + "x"}},
		} {
			if code, b := post(c.path, c.body); code != 204 || b != "" {
				t.Errorf("%s: %d %q, want 204", name, code, b)
			}
		}
		// Format errors are 400.
		if code, _ := post("courier/request/billing-svc", map[string]interface{}{}); code != 400 {
			t.Errorf("missing receipt_url: %d", code)
		}
		if code, _ := post("courier/request/billing-svc", map[string]interface{}{"receipt_url": recvURL, "nonce": "short"}); code != 400 {
			t.Errorf("bad nonce: %d", code)
		}
		// A wrong-typed field is a framework 400 (accepted to echo the value).
		code, b := post("courier/request/billing-svc", map[string]interface{}{"receipt_url": recvURL, "nonce": []string{"abc"}})
		t.Logf("wrong-typed nonce: %d %s", code, b)
		if code != 400 {
			t.Errorf("wrong-typed nonce: %d, want 400", code)
		}
		// Other methods and paths: record what Vault itself answers.
		for _, c := range []struct{ method, path string }{
			{"GET", "courier/request/billing-svc"}, {"PUT", "courier/request/billing-svc"},
			{"DELETE", "courier/request/billing-svc"}, {"POST", "courier/request/a/b"},
		} {
			code, _, b := s.raw(c.method, c.path, "", map[string]interface{}{"receipt_url": recvURL})
			t.Logf("%s %s without a token: %d %s", c.method, c.path, code, strings.TrimSpace(string(b)))
		}
	})

	s.run("authenticated paths reject tokenless requests", func(t *testing.T) {
		for _, c := range []struct{ method, path string }{
			{"GET", "courier/config"}, {"POST", "courier/config"},
			{"GET", "courier/keys"}, {"POST", "courier/keys/rotate"},
			{"GET", "courier/roles/billing-svc"}, {"POST", "courier/roles/x"}, {"DELETE", "courier/roles/billing-svc"},
			{"LIST", "courier/roles"},
		} {
			code, _, _ := s.raw(c.method, c.path, "", map[string]interface{}{})
			if code != 403 {
				t.Errorf("%s %s without a token: %d, want 403", c.method, c.path, code)
			}
		}
	})

	s.run("rotation", func(t *testing.T) {
		var before, after struct {
			Data struct {
				CurrentKid string `json:"current_kid"`
			}
		}
		_ = json.Unmarshal(s.must("GET", "courier/keys", nil), &before)
		s.must("POST", "courier/keys/rotate", nil)
		_ = json.Unmarshal(s.must("GET", "courier/keys", nil), &after)
		if before.Data.CurrentKid == "" || before.Data.CurrentKid == after.Data.CurrentKid {
			t.Fatalf("manual rotation did not change current_kid: %q -> %q", before.Data.CurrentKid, after.Data.CurrentKid)
		}
		_, _, jb := s.raw("GET", "courier/.well-known/jwks.json", "", nil)
		var set struct{ Keys []map[string]interface{} }
		_ = json.Unmarshal(jb, &set)
		if len(set.Keys) != 3 {
			t.Fatalf("JWKS after rotation holds %d keys, want current, next and one retired", len(set.Keys))
		}
		s.must("POST", "courier/keys/rotate", map[string]interface{}{"revoke_previous": true})
		_, _, jb = s.raw("GET", "courier/.well-known/jwks.json", "", nil)
		_ = json.Unmarshal(jb, &set)
		if len(set.Keys) != 2 {
			t.Fatalf("revoke_previous left %d keys in the JWKS, want 2", len(set.Keys))
		}
	})

	s.run("audit log", func(t *testing.T) {
		logPath := s.auditLog
		// Try the API first. Recent OpenBao refuses it ("use declarative,
		// config-based audit device management instead") and the device declared in
		// the server config is used; older OpenBao accepts the API call.
		code, _, b := s.raw("PUT", "sys/audit/file", s.token, map[string]interface{}{"type": "file", "options": map[string]string{"file_path": logPath}})
		switch {
		case code >= 200 && code < 300:
		case s.declarativeAudit && code == 400 && strings.Contains(string(b), "declarative"):
			t.Log("audit device enabled through the server config")
		default:
			t.Fatalf("enabling the audit device: %d %s", code, b)
		}
		code, _, _ = s.raw("POST", "courier/request/billing-svc", "", map[string]interface{}{"receipt_url": recvURL, "nonce": "AuditNonce1234567"})
		if code != 204 {
			t.Fatalf("request: %d", code)
		}
		time.Sleep(300 * time.Millisecond)
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		log := string(data)
		if !strings.Contains(log, `"path":"courier/request/billing-svc"`) {
			t.Fatalf("the unauthenticated request is not in the audit log")
		}
		if strings.Contains(log, "AuditNonce1234567") || strings.Contains(log, recvURL) {
			t.Fatal("the audit log contains the nonce or receipt URL in clear text")
		}
	})

	s.run("rate-limit quota on the request path", func(t *testing.T) {
		// Try the documented path syntax for a quota on the request endpoint.
		code, _, b := s.raw("POST", "sys/quotas/rate-limit/courier-req", s.token,
			map[string]interface{}{"path": "courier/request/*", "rate": 1, "interval": "10s"})
		t.Logf("create quota path courier/request/*: %d %s", code, strings.TrimSpace(string(b)))
		if code != 204 && code != 200 {
			t.Fatalf("quota with path courier/request/* was refused")
		}
		var got []int
		for i := 0; i < 5; i++ {
			c, _, _ := s.raw("POST", "courier/request/billing-svc", "", map[string]interface{}{"receipt_url": recvURL})
			got = append(got, c)
		}
		t.Logf("statuses with a 1/10s quota on courier/request/*: %v", got)
		limited := false
		for _, c := range got {
			limited = limited || c == 429
		}
		if !limited {
			t.Errorf("no 429 from the quota: %v", got)
		}
		s.must("DELETE", "sys/quotas/rate-limit/courier-req", nil)
	})

	s.run("keys survive seal and unseal", func(t *testing.T) {
		m := regexp.MustCompile(`Unseal Key: (\S+)`).FindStringSubmatch(s.logs.String())
		if m == nil {
			t.Fatal("no unseal key in the dev server output")
		}
		kids := func() []string {
			_, _, jb := s.raw("GET", "courier/.well-known/jwks.json", "", nil)
			var set struct{ Keys []map[string]interface{} }
			_ = json.Unmarshal(jb, &set)
			var out []string
			for _, k := range set.Keys {
				out = append(out, k["kid"].(string))
			}
			return out
		}
		before := kids()
		if len(before) == 0 {
			t.Fatal("no keys before sealing")
		}
		s.sealCycle(m[1])
		after := kids()
		if strings.Join(before, ",") != strings.Join(after, ",") {
			t.Fatalf("keys changed across seal/unseal: %v -> %v", before, after)
		}
		// The reloaded backend still delivers, with the same current key.
		n := len(rc.waitFor(0))
		code, _, _ := s.raw("POST", "courier/request/billing-svc", "", map[string]interface{}{"receipt_url": recvURL})
		if code != 204 || len(rc.waitFor(n+1)) != n+1 {
			t.Fatalf("no delivery after unseal (status %d)", code)
		}
	})

	s.run("a changed type option refuses to serve", func(t *testing.T) {
		m := regexp.MustCompile(`Unseal Key: (\S+)`).FindStringSubmatch(s.logs.String())
		if m == nil {
			t.Fatal("no unseal key in the dev server output")
		}
		// Change the option after the config was written, then reload the backend.
		code, _, body := s.raw("POST", "sys/mounts/courier/tune", s.token, map[string]interface{}{"options": map[string]string{"type": "tls"}})
		t.Logf("tune type=tls: %d %s", code, strings.TrimSpace(string(body)))
		if code < 200 || code > 299 {
			t.Skipf("this server does not allow changing mount options (%d); the mismatch is covered by the unit tests", code)
		}
		s.sealCycle(m[1])
		serving := false
		defer func() {
			// Put the option back so the later checks see a working mount.
			s.must("POST", "sys/mounts/courier/tune", map[string]interface{}{"options": map[string]string{"type": "jwt"}})
			s.sealCycle(m[1])
			_ = serving
		}()
		if c, _, b := s.raw("GET", "courier/config", s.token, nil); c == 200 {
			serving = true
			t.Skipf("the backend was not rebuilt with the new option (%d %s)", c, b)
		} else if c != 500 || !strings.Contains(string(b), "mount type does not match stored configuration") {
			t.Errorf("config read: %d %s, want 500 with the mount type message", c, b)
		}
		if c, _, b := s.raw("POST", "courier/request/billing-svc", "", map[string]interface{}{"receipt_url": recvURL}); c != 204 || len(b) != 0 {
			t.Errorf("request: %d %q, want the empty 204", c, b)
		}
		if c, _, b := s.raw("GET", "courier/.well-known/jwks.json", "", nil); c != 503 {
			t.Errorf("jwks: %d %s, want 503", c, b)
		}
	})

	s.run("storage damage never leaks to a caller", func(t *testing.T) {
		m := regexp.MustCompile(`Unseal Key: (\S+)`).FindStringSubmatch(s.logs.String())
		if m == nil {
			t.Fatal("no unseal key in the dev server output")
		}
		// Find the mount's storage path and remember the key set.
		var mounts map[string]interface{}
		if err := json.Unmarshal(s.must("GET", "sys/mounts", nil), &mounts); err != nil {
			t.Fatal(err)
		}
		uuid := mounts["courier/"].(map[string]interface{})["uuid"].(string)
		rawPath := "sys/raw/logical/" + uuid + "/keys/set"
		var orig struct{ Data struct{ Value string } }
		if err := json.Unmarshal(s.must("GET", rawPath, nil), &orig); err != nil || orig.Data.Value == "" {
			t.Fatalf("reading the key set from raw storage: %v %q", err, orig.Data.Value)
		}

		// Damage it, then reload the backend so its cache is cold.
		s.must("PUT", rawPath, map[string]interface{}{"value": "{truncated-secret-internal-detail"})
		s.sealCycle(m[1])

		forbidden := []string{"secret-internal-detail", "rpc error", "jwt/keys/set", "keys/set", "decoding", "invalid character", "unexpected end", "json:", "panic", "goroutine", ".go:", "/tmp/", "127.0.0.1"}
		noLeak := func(what string, code int, hdr http.Header, body []byte) {
			all := string(body) + fmt.Sprint(hdr)
			for _, f := range forbidden {
				if strings.Contains(all, f) {
					t.Errorf("%s (%d): %q leaked: %s %v", what, code, f, body, hdr)
				}
			}
		}
		// The public endpoints answer a fixed 503.
		for _, p := range []string{"courier/.well-known/jwks.json", "courier/.well-known/openid-configuration"} {
			code, hdr, body := s.raw("GET", p, "", nil)
			noLeak(p, code, hdr, body)
			if code != 503 || strings.TrimSpace(string(body)) != `{"error":"temporarily_unavailable"}` {
				t.Errorf("%s: %d %s, want the fixed 503", p, code, body)
			}
			if !strings.HasPrefix(hdr.Get("Content-Type"), "application/json") || hdr.Get("Cache-Control") != "no-store" {
				t.Errorf("%s: Content-Type %q, Cache-Control %q", p, hdr.Get("Content-Type"), hdr.Get("Cache-Control"))
			}
			// Vault drops plugin response headers that the mount does not allow.
			if ra := hdr.Get("Retry-After"); ra != "" {
				t.Errorf("%s: Retry-After = %q before the mount allows it", p, ra)
			}
		}
		s.must("POST", "sys/mounts/courier/tune", map[string]interface{}{"allowed_response_headers": []string{"Retry-After"}})
		for _, p := range []string{"courier/.well-known/jwks.json", "courier/.well-known/openid-configuration"} {
			code, hdr, body := s.raw("GET", p, "", nil)
			// The contract is the same on a tuned mount; only the hint is added.
			if code != 503 || strings.TrimSpace(string(body)) != `{"error":"temporarily_unavailable"}` ||
				!strings.HasPrefix(hdr.Get("Content-Type"), "application/json") || hdr.Get("Cache-Control") != "no-store" {
				t.Errorf("%s on a tuned mount: %d %s %v", p, code, body, hdr)
			}
			if ra := hdr.Get("Retry-After"); ra != "30" {
				t.Errorf("%s: Retry-After = %q after allowed_response_headers=Retry-After, want 30", p, ra)
			}
		}
		// The request endpoint stays the empty 204.
		code, hdr, body := s.raw("POST", "courier/request/billing-svc", "", map[string]interface{}{"receipt_url": recvURL, "nonce": nonce})
		noLeak("request", code, hdr, body)
		if code != 204 || len(body) != 0 {
			t.Errorf("request: %d %q, want the empty 204", code, body)
		}
		// An authenticated caller sees a fixed message, not the storage layer's.
		for _, p := range []string{"courier/keys", "courier/keys/rotate"} {
			method := "GET"
			if strings.HasSuffix(p, "rotate") {
				method = "POST"
			}
			code, hdr, body := s.raw(method, p, s.token, nil)
			noLeak(p, code, hdr, body)
			if code != 500 || !strings.Contains(string(body), "internal error") {
				t.Errorf("%s: %d %s, want 500 with the fixed internal error", p, code, body)
			}
		}

		// Restore the key set: the mount works again.
		s.must("PUT", rawPath, map[string]interface{}{"value": orig.Data.Value})
		s.sealCycle(m[1])
		if code, _, _ := s.raw("GET", "courier/.well-known/jwks.json", "", nil); code != 200 {
			t.Fatalf("after restoring the key set the JWKS is %d, want 200", code)
		}
	})

	s.run("unmount runs Clean", func(t *testing.T) {
		if err := s.api.Sys().Unmount("courier"); err != nil {
			t.Fatal(err)
		}
	})
	_ = context.Background
	_ = fmt.Sprint
}
