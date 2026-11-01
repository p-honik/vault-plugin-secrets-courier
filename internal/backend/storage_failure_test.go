package backend

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// failingStorage lets a test fail chosen reads and counts writes.
type failingStorage struct {
	*logical.InmemStorage
	failGet atomic.Pointer[func(key string) error]
	writes  atomic.Int64
}

func (f *failingStorage) setFail(fn func(key string) error) {
	if fn == nil {
		f.failGet.Store(nil)
		return
	}
	f.failGet.Store(&fn)
}

func (f *failingStorage) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	if fn := f.failGet.Load(); fn != nil {
		if err := (*fn)(key); err != nil {
			return nil, err
		}
	}
	return f.InmemStorage.Get(ctx, key)
}

func (f *failingStorage) Put(ctx context.Context, e *logical.StorageEntry) error {
	f.writes.Add(1)
	return f.InmemStorage.Put(ctx, e)
}

func (f *failingStorage) Delete(ctx context.Context, key string) error {
	f.writes.Add(1)
	return f.InmemStorage.Delete(ctx, key)
}

var errStorageDown = errors.New("storage is down: secret-internal-detail")

// A storage failure, corrupt data or a signing failure must never reach the
// unauthenticated caller as anything but the usual empty 204: the plugin answers
// only 204 and 400, and tells nobody the mount is failing. The
// request is not delivered, the handler writes nothing, the reservation is
// released so the requester is not locked out, and the failure is not cached.
func TestStorageFailuresNeverReachTheCaller(t *testing.T) {
	failKeys := func(keys ...string) func(string) error {
		return func(k string) error {
			for _, w := range keys {
				if k == w {
					return errStorageDown
				}
			}
			return nil
		}
	}
	corrupt := func(key string, value string) func(*testing.T, *failingStorage) {
		return func(t *testing.T, fs *failingStorage) {
			if err := fs.InmemStorage.Put(context.Background(), &logical.StorageEntry{Key: key, Value: []byte(value)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []struct {
		name    string
		failGet func(string) error                // fail these reads
		corrupt func(*testing.T, *failingStorage) // or damage stored data
	}{
		{"reading the role fails", failKeys("roles/r"), nil},
		{"reading the mount config fails", failKeys("config"), nil},
		{"reading the config fails", failKeys("config"), nil},
		{"reading the key set fails", failKeys("keys/set"), nil},
		{"every read fails", func(string) error { return errStorageDown }, nil},
		{"the role is not valid JSON", nil, corrupt("roles/r", "{not json")},
		{"the mount config is not valid JSON", nil, corrupt("config", "][")},
		{"config is not valid JSON", nil, corrupt("config", "nope")},
		{"the key set is not valid JSON", nil, corrupt("keys/set", "nope")},
		{"the private key is damaged, so signing fails", nil, corrupt("keys/set",
			`{"next":{"kid":"n","private":"e30=","public":"e30=","not_before":"2030-01-01T00:00:00Z"},`+
				`"current":{"kid":"c","private":"e30=","public":"e30=","rotated_at":"2030-01-01T00:00:00Z","longest_ttl":1800000000000},`+
				`"previous":null,"next_rotation":"2030-01-02T00:00:00Z"}`)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			fs := &failingStorage{InmemStorage: &logical.InmemStorage{}}
			e.s = fs
			rc := newReceiver(t)
			e.configureJWT(nil)
			// A long interval proves the reservation is released: if a failed
			// request kept its timer, the good request below would be dropped.
			e.createRole("r", map[string]interface{}{"allowed_receipt_urls": []string{rc.url("/x")}, "receipt_ca_pem": rc.caPEM, "min_request_interval": 3600})
			req := map[string]interface{}{"receipt_url": rc.url("/x"), "nonce": "k3Jx9wQ2mZpL7vTa"}

			// Remember the good data, then break it.
			keys := []string{"roles/r", "config", "keys/set"}
			saved := map[string]*logical.StorageEntry{} // absent keys map to nil
			for _, k := range keys {
				ent, _ := fs.InmemStorage.Get(context.Background(), k)
				saved[k] = ent
			}
			e.b.invalidate()
			fs.setFail(c.failGet)
			if c.corrupt != nil {
				c.corrupt(t, fs)
			}
			writesBefore := fs.writes.Load()

			resp, err := e.b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation, Path: "request/r", Data: req, Storage: fs,
			})
			e.b.wg.Wait()
			if err != nil {
				t.Fatalf("the caller got an error: %v", err)
			}
			if resp != nil {
				t.Fatalf("the caller got a response (an empty 204 is required): %+v", resp)
			}
			if len(rc.received()) != 0 {
				t.Fatal("a request that failed was delivered")
			}
			if e.b.state.inflightCount() != 0 {
				t.Fatal("the in-flight reservation was not released")
			}
			if _, locked := e.b.state.lastAccepted[roleURL{"r", rc.url("/x")}]; locked {
				t.Fatal("a failed request left its rate-limit timer behind")
			}
			if fs.writes.Load() != writesBefore {
				t.Fatal("the request handler wrote to storage")
			}

			// Recover: restore the data, and the same request now works. Nothing
			// was cached from the failure.
			fs.setFail(nil)
			for k, ent := range saved {
				if ent == nil { // the key did not exist before: remove what the test wrote
					_ = fs.InmemStorage.Delete(context.Background(), k)
					continue
				}
				if err := fs.InmemStorage.Put(context.Background(), ent); err != nil {
					t.Fatal(err)
				}
			}
			e.b.invalidate() // the damaged data was changed behind the backend's back
			e.request("r", req)
			if len(rc.received()) != 1 {
				t.Fatal("the request did not work after storage recovered: a failure was cached or the requester stayed locked out")
			}
		})
	}
}

// The public endpoints answer a storage failure or corrupt data with the same
// raw 503: a fixed body that never holds error text, no-store,
// and a retry hint.
func TestWellKnownStorageFailureIs503(t *testing.T) {
	for name, damage := range map[string]func(*failingStorage){
		"storage read fails": func(fs *failingStorage) { fs.setFail(func(string) error { return errStorageDown }) },
		"corrupt key set": func(fs *failingStorage) {
			_ = fs.InmemStorage.Put(context.Background(), &logical.StorageEntry{Key: storageKeySet, Value: []byte("{nope")})
		},
		"corrupt config": func(fs *failingStorage) {
			_ = fs.InmemStorage.Put(context.Background(), &logical.StorageEntry{Key: storageConfig, Value: []byte("{nope")})
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			fs := &failingStorage{InmemStorage: &logical.InmemStorage{}}
			e.s = fs
			e.configureJWT(nil)
			e.b.invalidate()
			damage(fs)
			for _, p := range []string{".well-known/jwks.json", ".well-known/openid-configuration"} {
				resp, err := e.do(logical.ReadOperation, p, nil)
				if err != nil || resp == nil {
					t.Fatalf("%s: %v %v, want a raw 503 response and no error", p, resp, err)
				}
				if resp.Data[logical.HTTPStatusCode] != 503 || resp.Data[logical.HTTPContentType] != "application/json" ||
					string(resp.Data[logical.HTTPRawBody].([]byte)) != `{"error":"temporarily_unavailable"}` ||
					resp.Data[logical.HTTPCacheControlHeader] != "no-store" ||
					len(resp.Headers["Retry-After"]) != 1 || resp.Headers["Retry-After"][0] != "30" {
					t.Fatalf("%s: wrong 503: data %v headers %v", p, resp.Data, resp.Headers)
				}
			}
		})
	}
}

// An absent config stays a 404, not a 503.
func TestWellKnown404IsNotA503(t *testing.T) {
	e := newEnv(t)
	resp, err := e.do(logical.ReadOperation, ".well-known/jwks.json", nil)
	if err != nil || resp.Data[logical.HTTPStatusCode] != 404 {
		t.Fatalf("%v %v", resp, err)
	}
}
