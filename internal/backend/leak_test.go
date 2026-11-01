package backend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
)

// Leak tests: no response body, header,
// warning or error message from any Courier path may carry internal detail,
// whatever fails inside. Each scenario injects a failure with a canary in its
// text and runs every Courier path, then scans everything a caller could see.
//
// What this cannot cover: Vault core authenticates and authorizes requests before
// they reach the plugin, so "no token" and "token lacking the capability" are
// answered by Vault itself (the live test checks the 403 status for every
// authenticated path); these tests run the plugin's handlers directly, as a fully
// privileged caller would reach them.

const canary = "secret-internal-detail"

// jwtShape matches a compact JWT, which must never be logged.
var jwtShape = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

// internalPatterns must not appear in anything a caller can see. They are the
// wording of the storage layer, gRPC, key paths, file paths, stack traces and
// library errors.
var internalPatterns = []string{
	canary, "rpc error", "code = ", "jwt/keys/set", "keys/set", "storage is down",
	".go:", "goroutine ", "panic", "runtime error", "/home/", "/tmp/", "127.0.0.1", "[::1]",
	"decoding ", "invalid character", "unexpected end of JSON", "go-jose", "x509:", "tls:",
	"dial tcp", "connection refused", "json:", "unmarshal", "Stack",
}

type op struct {
	name string
	op   logical.Operation
	path string
	data map[string]interface{}
	kind handlerKind
}

// allOps is every Courier endpoint with every operation it supports.
func allOps(recvURL string) []op {
	req := map[string]interface{}{"receipt_url": recvURL, "nonce": "LeakNonce123456789"}
	return []op{
		{"config read", logical.ReadOperation, "config", nil, kindAuthenticated},
		{"config write", logical.UpdateOperation, "config", map[string]interface{}{"max_inflight": 5}, kindAuthenticated},
		{"jwt config read", logical.ReadOperation, "config", nil, kindAuthenticated},
		{"jwt config write", logical.UpdateOperation, "config", map[string]interface{}{"max_ttl": 600}, kindAuthenticated},
		{"keys read", logical.ReadOperation, "keys", nil, kindAuthenticated},
		{"keys rotate", logical.UpdateOperation, "keys/rotate", nil, kindAuthenticated},
		{"keys rotate revoke", logical.UpdateOperation, "keys/rotate", map[string]interface{}{"revoke_previous": true}, kindAuthenticated},
		{"role read", logical.ReadOperation, "roles/r", nil, kindAuthenticated},
		{"role write", logical.UpdateOperation, "roles/r", map[string]interface{}{"ttl": 150}, kindAuthenticated},
		{"role create", logical.CreateOperation, "roles/new", map[string]interface{}{"allowed_receipt_urls": []string{recvURL}, "aud": "a"}, kindAuthenticated},
		{"role delete", logical.DeleteOperation, "roles/r", nil, kindAuthenticated},
		{"role list", logical.ListOperation, "roles/", nil, kindAuthenticated},
		{"request", logical.UpdateOperation, "request/r", req, kindRequest},
		{"jwks", logical.ReadOperation, ".well-known/jwks.json", nil, kindPublic},
		{"discovery", logical.ReadOperation, ".well-known/openid-configuration", nil, kindPublic},
	}
}

// visible collects every string a caller can see in a response or an error.
func visible(resp *logical.Response, err error) string {
	var sb strings.Builder
	if err != nil {
		sb.WriteString(err.Error())
		sb.WriteString("\n")
		var coded logical.HTTPCodedError
		if errors.As(err, &coded) {
			sb.WriteString(coded.Error())
		}
	}
	if resp != nil {
		for k, v := range resp.Data {
			sb.WriteString(k + "=")
			if b, ok := v.([]byte); ok {
				sb.Write(b)
			} else {
				fmt.Fprintf(&sb, "%v", v)
			}
			sb.WriteString("\n")
		}
		for _, w := range resp.Warnings {
			sb.WriteString(w + "\n")
		}
		for k, v := range resp.Headers {
			fmt.Fprintf(&sb, "%s: %v\n", k, v)
		}
	}
	return sb.String()
}

// assertNoLeak fails if anything visible matches an internal pattern, and checks
// the status against the documented status tables.
func assertNoLeak(t *testing.T, o op, resp *logical.Response, err error, allowed ...string) {
	t.Helper()
	seen := visible(resp, err)
	for _, a := range allowed { // an input the framework may echo back to its own sender
		seen = strings.ReplaceAll(seen, a, "")
	}
	for _, p := range internalPatterns {
		if strings.Contains(seen, p) {
			t.Errorf("%s: %q leaked to the caller:\n%s", o.name, p, seen)
		}
	}
	switch o.kind {
	case kindRequest:
		// Only the empty 204 (nil response) and a 400 (error response) exist.
		if err != nil && !errors.Is(err, logical.ErrReadOnly) {
			t.Errorf("%s: the request endpoint returned an error: %v", o.name, err)
		}
		if resp != nil && !resp.IsError() {
			t.Errorf("%s: the request endpoint returned a body: %v", o.name, resp.Data)
		}
	case kindPublic:
		if err != nil {
			t.Errorf("%s: a public endpoint returned an error: %v", o.name, err)
			return
		}
		if resp == nil {
			t.Errorf("%s: a public endpoint returned an empty response", o.name)
			return
		}
		switch resp.Data[logical.HTTPStatusCode] {
		case 200, 404, 503:
		default:
			t.Errorf("%s: public endpoint status %v is not in the table", o.name, resp.Data[logical.HTTPStatusCode])
		}
	case kindAuthenticated:
		if err != nil && !errors.Is(err, logical.ErrReadOnly) && !strings.Contains(err.Error(), internalErrorMessage) {
			t.Errorf("%s: an authenticated path returned an error other than the fixed one: %v", o.name, err)
		}
	}
}

// faultyStorage injects failures per operation. A nil hook means no failure.
type faultyStorage struct {
	*logical.InmemStorage
	get, put, del, list func(key string) error
	panicOnGet          bool
}

func (f *faultyStorage) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	if f.panicOnGet {
		panic(canary)
	}
	if f.get != nil {
		if err := f.get(key); err != nil {
			return nil, err
		}
	}
	return f.InmemStorage.Get(ctx, key)
}

func (f *faultyStorage) Put(ctx context.Context, e *logical.StorageEntry) error {
	if f.put != nil {
		if err := f.put(e.Key); err != nil {
			return err
		}
	}
	return f.InmemStorage.Put(ctx, e)
}

func (f *faultyStorage) Delete(ctx context.Context, key string) error {
	if f.del != nil {
		if err := f.del(key); err != nil {
			return err
		}
	}
	return f.InmemStorage.Delete(ctx, key)
}

func (f *faultyStorage) List(ctx context.Context, prefix string) ([]string, error) {
	if f.list != nil {
		if err := f.list(prefix); err != nil {
			return nil, err
		}
	}
	return f.InmemStorage.List(ctx, prefix)
}

func canaryErr(string) error {
	return errors.New("rpc error: code = Unavailable desc = " + canary + " at /home/vault/storage.go:42")
}

// syncBuf is a log sink safe for concurrent writers.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// leakEnv is a configured mount (jwt config, a role, a receiver) on faulty
// storage, with a node whose log is captured.
type leakEnv struct {
	*env
	fs   *faultyStorage
	rc   *receiver
	logs *syncBuf
	n    *backend // the node under test
}

func newLeakEnv(t *testing.T, state consts.ReplicationState) *leakEnv {
	t.Helper()
	e := newEnv(t)
	fs := &faultyStorage{InmemStorage: &logical.InmemStorage{}}
	e.s = fs
	rc := newReceiver(t)
	e.configureJWT(nil)
	e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM, "min_request_interval": 0})
	e.ok(logical.UpdateOperation, "keys/rotate", nil) // so a retired key exists

	logs := &syncBuf{}
	conf := logical.TestBackendConfig()
	conf.StorageView = fs
	conf.Logger = hclog.New(&hclog.LoggerOptions{Output: logs, Level: hclog.Trace})
	conf.System = &sysView{state: state}
	lb, err := Factory(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}
	n := lb.(*backend)
	n.now = func() time.Time { return e.clock }
	return &leakEnv{env: e, fs: fs, rc: rc, logs: logs, n: n}
}

// runAll runs every op on the node under test and scans the results.
func (l *leakEnv) runAll(t *testing.T, allowed ...string) {
	t.Helper()
	for _, o := range allOps(l.rc.url("/x")) {
		l.n.invalidate() // force reads, so the injected failures are hit
		resp, err := l.n.HandleRequest(context.Background(), &logical.Request{
			Operation: o.op, Path: o.path, Data: o.data, Storage: l.fs,
		})
		l.n.wg.Wait()
		assertNoLeak(t, o, resp, err, allowed...)
	}
	// Existence checks run before the handler on authenticated writes.
	for _, p := range []string{"config", "config", "roles/r"} {
		l.n.invalidate()
		_, _, err := l.n.HandleExistenceCheck(context.Background(), &logical.Request{
			Operation: logical.CreateOperation, Path: p, Storage: l.fs, Data: map[string]interface{}{},
		})
		assertNoLeak(t, op{name: "existence " + p, kind: kindAuthenticated}, nil, err)
	}
}

func TestNoLeaksOnStorageFailures(t *testing.T) {
	scenarios := map[string]func(*faultyStorage){
		"every read fails":   func(f *faultyStorage) { f.get = canaryErr },
		"every list fails":   func(f *faultyStorage) { f.list = canaryErr },
		"every write fails":  func(f *faultyStorage) { f.put = canaryErr },
		"every delete fails": func(f *faultyStorage) { f.del = canaryErr },
		"everything fails": func(f *faultyStorage) {
			f.get, f.put, f.del, f.list = canaryErr, canaryErr, canaryErr, canaryErr
		},
		"only the key set fails": func(f *faultyStorage) {
			f.get = func(k string) error {
				if k == storageKeySet {
					return canaryErr(k)
				}
				return nil
			}
		},
		"only roles fail": func(f *faultyStorage) {
			f.get = func(k string) error {
				if strings.HasPrefix(k, storageRolePrefix) {
					return canaryErr(k)
				}
				return nil
			}
		},
		"a handler panics": func(f *faultyStorage) { f.panicOnGet = true },
	}
	for name, inject := range scenarios {
		t.Run(name, func(t *testing.T) {
			l := newLeakEnv(t, 0)
			inject(l.fs)
			l.runAll(t)
		})
	}
}

func TestNoLeaksOnCorruptAndTruncatedEntries(t *testing.T) {
	for _, key := range []string{storageConfig, storageKeySet, storageRolePrefix + "r"} {
		for _, damage := range []string{"truncate", "garbage", "empty object", "null"} {
			t.Run(key+" "+damage, func(t *testing.T) {
				l := newLeakEnv(t, 0)
				ent, _ := l.fs.InmemStorage.Get(context.Background(), key)
				value := []byte("garbage-" + canary)
				switch damage {
				case "truncate":
					if ent != nil {
						value = ent.Value[:len(ent.Value)/2]
					}
				case "empty object":
					value = []byte("{}")
				case "null":
					value = []byte("null")
				}
				_ = l.fs.InmemStorage.Put(context.Background(), &logical.StorageEntry{Key: key, Value: value})
				l.runAll(t)
			})
		}
	}
}

func TestNoLeaksOnSignerAndKeyGenerationErrors(t *testing.T) {
	t.Run("signer", func(t *testing.T) {
		l := newLeakEnv(t, 0)
		bad := `{"next":{"kid":"n","private":"e30=","public":"e30=","not_before":"2030-01-01T00:00:00Z"},` +
			`"current":{"kid":"c","private":"e30=","public":"e30=","rotated_at":"2030-01-01T00:00:00Z","longest_ttl":1800000000000},"next_rotation":"2030-01-02T00:00:00Z"}`
		_ = l.fs.InmemStorage.Put(context.Background(), &logical.StorageEntry{Key: storageKeySet, Value: []byte(bad)})
		l.runAll(t)
	})
	t.Run("key generation", func(t *testing.T) {
		l := newLeakEnv(t, 0)
		old := genKey
		genKey = func(string) (string, []byte, []byte, error) { return "", nil, nil, errors.New("rand: " + canary) }
		defer func() { genKey = old }()
		l.runAll(t)
	})
}

func TestNoLeaksOnANodeThatCannotWrite(t *testing.T) {
	for name, state := range map[string]consts.ReplicationState{
		"DR secondary":          consts.ReplicationDRSecondary,
		"performance standby":   consts.ReplicationPerformanceStandby,
		"performance secondary": consts.ReplicationPerformanceSecondary,
	} {
		t.Run(name, func(t *testing.T) {
			newLeakEnv(t, state).runAll(t)
		})
	}
}

// Malformed, oversized, wrong-typed and non-UTF-8 input on every writable
// endpoint. The framework's wrong-typed-field 400 may echo the caller's own input
// (accepted); nothing else may appear.
func TestNoLeaksOnHostileInput(t *testing.T) {
	big := strings.Repeat("A", 1<<20)
	inputs := map[string]interface{}{
		"non-UTF-8":    "\xff\xfe\xfd" + canary,
		"oversized":    big,
		"wrong type":   []interface{}{canary, 1},
		"a map":        map[string]interface{}{"k": canary},
		"nul and ctrl": "a\x00b\x1b[31m",
		"negative":     -5,
		"huge number":  1 << 62,
		"empty":        "",
		"bool":         true,
		"nested":       []interface{}{[]interface{}{canary}},
	}
	l := newLeakEnv(t, 0)
	fields := map[string][]string{
		"config":      {"delivery_retry", "retry_delay", "delivery_timeout", "max_inflight", "allowed_networks", "denied_networks", "issuer", "alg", "rotation_period", "max_ttl", "verification_ttl"},
		"roles/new":   {"allowed_receipt_urls", "aud", "ttl", "require_nonce", "nonce_in_token", "min_request_interval", "receipt_ca_pem"},
		"request/r":   {"receipt_url", "nonce"},
		"keys/rotate": {"revoke_previous"},
	}
	for path, names := range fields {
		for _, field := range names {
			for iname, val := range inputs {
				data := map[string]interface{}{field: val}
				if path == "roles/new" && field != "allowed_receipt_urls" {
					data["allowed_receipt_urls"] = []string{l.rc.url("/x")}
					data["aud"] = "a"
					data[field] = val
				}
				if path == "request/r" && field == "nonce" {
					data["receipt_url"] = l.rc.url("/x")
				}
				kind := kindAuthenticated
				var opn logical.Operation = logical.UpdateOperation
				if path == "request/r" {
					kind = kindRequest
				}
				if path == "roles/new" {
					opn = logical.CreateOperation
				}
				l.n.invalidate()
				resp, err := l.n.HandleRequest(context.Background(), &logical.Request{Operation: opn, Path: path, Data: data, Storage: l.fs})
				l.n.wg.Wait()
				o := op{name: fmt.Sprintf("%s %s=%s", path, field, iname), kind: kind}
				// The framework echoes a wrong-typed value back to its own sender;
				// drop the echoed input and the Go type words around it before scanning.
				seen := visible(resp, err)
				for _, p := range internalPatterns {
					if p == canary || p == "Stack" || p == "json:" || p == "unmarshal" {
						continue
					}
					if strings.Contains(strings.ReplaceAll(seen, canary, ""), p) && !strings.Contains(seen, "Field validation failed") {
						t.Errorf("%s: %q leaked:\n%.300s", o.name, p, seen)
					}
				}
				if kind == kindRequest && err != nil {
					t.Errorf("%s: the request endpoint returned an error: %v", o.name, err)
				}
				if kind == kindRequest && resp != nil && !resp.IsError() {
					t.Errorf("%s: the request endpoint returned a body", o.name)
				}
			}
		}
	}
}

// Delivery failures happen after the caller got its 204, so they can only leak
// through the log. A receiver's response body, the token, the nonce and key
// material must never be logged.
func TestDeliveryFailuresLeakNothingIntoTheLog(t *testing.T) {
	recvBody := strings.Repeat("receiver-body-"+canary+"-", 50000) // ~1 MB
	cases := map[string]func(*leakEnv) string{
		"receiver answers 500 with a body": func(l *leakEnv) string {
			l.rc.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(500)
				w.Write([]byte(recvBody))
			})
			return l.rc.url("/x")
		},
		"receiver redirects": func(l *leakEnv) string {
			l.rc.srv.Config.Handler = http.RedirectHandler("https://elsewhere.example/"+canary, http.StatusFound)
			return l.rc.url("/x")
		},
		"connection refused": func(l *leakEnv) string {
			l.rc.srv.Close()
			return l.rc.url("/x")
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			l := newLeakEnv(t, 0)
			u := setup(l)
			_ = u
			resp, err := l.n.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation, Path: "request/r",
				Data:    map[string]interface{}{"receipt_url": l.rc.url("/x"), "nonce": "LeakNonce123456789"},
				Storage: l.fs,
			})
			l.n.wg.Wait()
			assertNoLeak(t, op{name: "request", kind: kindRequest}, resp, err)

			ks, _ := loadKeySet(context.Background(), l.fs)
			logged := l.logs.String()
			for what, secret := range map[string]string{
				"the nonce":       "LeakNonce123456789",
				"a private key":   privateMember(ks.Current.Private),
				"receiver's body": "receiver-body-",
				"the canary":      canary,
			} {
				if secret != "" && strings.Contains(logged, secret) {
					t.Errorf("the log contains %s:\n%.400s", what, logged)
				}
			}
			if jwtShape.MatchString(logged) {
				t.Errorf("the log contains something shaped like the token:\n%.400s", logged)
			}
			if !strings.Contains(logged, "delivery failed") {
				t.Errorf("the give-up line is missing from the log:\n%s", logged)
			}
		})
	}
}

// The log carries the cause of a failure but never the nonce, a private key or
// the request body.
func TestStorageFailureLogsTheCauseButNoSecrets(t *testing.T) {
	l := newLeakEnv(t, 0)
	ks, _ := loadKeySet(context.Background(), l.fs)
	l.fs.get = func(k string) error {
		if k == storageKeySet {
			return canaryErr(k)
		}
		return nil
	}
	l.n.invalidate()
	l.n.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "request/r",
		Data: map[string]interface{}{"receipt_url": l.rc.url("/x"), "nonce": "LeakNonce123456789"}, Storage: l.fs,
	})
	l.n.wg.Wait()
	logged := l.logs.String()
	if !strings.Contains(logged, canary) {
		t.Fatalf("the cause is not in the log:\n%s", logged)
	}
	if jwtShape.MatchString(logged) {
		t.Errorf("the log contains something shaped like the token:\n%s", logged)
	}
	for what, secret := range map[string]string{
		"the nonce": "LeakNonce123456789", "a private key": privateMember(ks.Current.Private), "the request body": "receipt_url",
	} {
		if strings.Contains(logged, secret) {
			t.Errorf("the log contains %s:\n%s", what, logged)
		}
	}
}

// Failures are logged at most once a minute per handler, so an outage cannot
// flood the log.
func TestFailureLogsAreRateLimited(t *testing.T) {
	l := newLeakEnv(t, 0)
	l.fs.get = canaryErr
	o := allOps(l.rc.url("/x"))[13] // jwks
	for i := 0; i < 200; i++ {
		l.n.invalidate()
		l.n.HandleRequest(context.Background(), &logical.Request{Operation: o.op, Path: o.path, Storage: l.fs})
	}
	if n := strings.Count(l.logs.String(), "handler=jwt.jwks"); n != 1 {
		t.Fatalf("%d log lines for 200 failures, want 1", n)
	}
	l.env.advance(2 * time.Minute)
	l.n.invalidate()
	l.n.HandleRequest(context.Background(), &logical.Request{Operation: o.op, Path: o.path, Storage: l.fs})
	if n := strings.Count(l.logs.String(), "handler=jwt.jwks"); n != 2 {
		t.Fatalf("%d log lines after a minute, want 2", n)
	}
}

// privateMember returns the value of the private exponent or scalar ("d") of a
// JWK, to look for it in logs.
func privateMember(jwk []byte) string {
	s := string(jwk)
	i := strings.Index(s, `"d":"`)
	if i < 0 {
		return ""
	}
	s = s[i+5:]
	return s[:strings.Index(s, `"`)]
}
