package backend

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

type env struct {
	t     testing.TB
	b     *backend
	s     logical.Storage
	clock time.Time
}

func newEnv(t testing.TB) *env {
	t.Helper()
	e := &env{t: t, b: testBackend(t), s: &logical.InmemStorage{}, clock: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}
	e.b.now = func() time.Time { return e.clock }
	return e
}

func (e *env) advance(d time.Duration) { e.clock = e.clock.Add(d) }

// do runs a request and returns the response and error.
func (e *env) do(op logical.Operation, path string, data map[string]interface{}) (*logical.Response, error) {
	e.t.Helper()
	return e.b.HandleRequest(context.Background(), &logical.Request{Operation: op, Path: path, Data: data, Storage: e.s})
}

// ok runs a request that must succeed without an error response.
func (e *env) ok(op logical.Operation, path string, data map[string]interface{}) *logical.Response {
	e.t.Helper()
	resp, err := e.do(op, path, data)
	if err != nil {
		e.t.Fatalf("%s %s: %v", op, path, err)
	}
	if resp.IsError() {
		e.t.Fatalf("%s %s: error response: %v", op, path, resp.Error())
	}
	return resp
}

// fails runs a request that must be rejected with an error response.
func (e *env) fails(op logical.Operation, path string, data map[string]interface{}) string {
	e.t.Helper()
	resp, err := e.do(op, path, data)
	if err != nil {
		e.t.Fatalf("%s %s: unexpected error %v", op, path, err)
	}
	if resp == nil || !resp.IsError() {
		e.t.Fatalf("%s %s: expected an error response, got %v", op, path, resp)
	}
	return resp.Error().Error()
}

func (e *env) configureJWT(extra map[string]interface{}) {
	e.t.Helper()
	data := map[string]interface{}{"issuer": "https://vault.example.com/v1/courier"}
	for k, v := range extra {
		data[k] = v
	}
	e.ok(logical.CreateOperation, "config", data)
}

func (e *env) createRole(name string, extra map[string]interface{}) {
	e.t.Helper()
	data := map[string]interface{}{
		"allowed_receipt_urls": []string{"https://billing.internal/courier/receive"},
		"aud":                  "payments-api",
	}
	for k, v := range extra {
		data[k] = v
	}
	e.ok(logical.CreateOperation, "roles/"+name, data)
}

func (e *env) keySet() *keySet {
	e.t.Helper()
	ks, err := loadKeySet(context.Background(), e.s)
	if err != nil || ks == nil {
		e.t.Fatalf("loadKeySet = %v, %v", ks, err)
	}
	return ks
}

func (e *env) tick() {
	e.t.Helper()
	if err := e.b.periodic(context.Background(), &logical.Request{Storage: e.s}); err != nil {
		e.t.Fatal(err)
	}
}

// raw decodes the body of a raw response and returns it with its status.
func rawBody(t *testing.T, resp *logical.Response, out interface{}) int {
	t.Helper()
	status := resp.Data[logical.HTTPStatusCode].(int)
	if out != nil {
		if err := json.Unmarshal(resp.Data[logical.HTTPRawBody].([]byte), out); err != nil {
			t.Fatal(err)
		}
	}
	return status
}
