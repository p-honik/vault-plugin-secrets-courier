package backend

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// No internal detail in any response: no body, header,
// warning or error message from any Courier path may carry storage-layer or gRPC
// error text, storage key paths, key material, file paths, stack traces, internal
// addresses, a receiver's response body or the text of a library error.
//
// Handlers still return raw errors internally, but every handler is wrapped by
// guard, which logs the cause server-side (rate-limited, never the token, private
// keys, nonces or request bodies) and hands the caller a fixed answer:
//
//	authenticated paths   a fixed internal-error message (validation failures keep
//	                      their own 400 message, which names only the rule)
//	request/<role>        the empty 204
//	public .well-known    503 with a fixed body, no-store and Retry-After
//
// The only error passed through untouched is logical.ErrReadOnly, which is the
// signal Vault uses to forward a request to the active node.

type handlerKind int

const (
	kindAuthenticated handlerKind = iota
	kindRequest
	kindPublic
)

// internalErrorMessage is the whole message an authenticated caller sees when a
// handler fails for a reason that is not theirs.
const internalErrorMessage = "internal error"

// logEvery bounds the log lines for one failing handler, so an outage cannot
// flood the log.
const logEvery = time.Minute

// failure is what a caller gets when a handler of the given kind fails.
func failure(kind handlerKind) (*logical.Response, error) {
	switch kind {
	case kindRequest:
		return nil, nil
	case kindPublic:
		return unavailable(), nil
	default:
		return nil, logical.CodedError(http.StatusInternalServerError, internalErrorMessage)
	}
}

// typeMismatchMessage is what an authenticated caller sees when the mount's type
// option differs from the type recorded with the stored config: the
// backend refuses to serve rather than read data written for another type.
const typeMismatchMessage = "mount type does not match stored configuration"

// typeMismatch reports whether the stored config was written for another type
// than this mount's, with both type names for the log.
func (b *backend) typeMismatch(ctx context.Context, s logical.Storage) (stored string, mismatch bool) {
	if b.unsupported != "" {
		return b.unsupported, true // the option names a type this build cannot serve
	}
	cfg, err := b.cachedConfig(ctx, s)
	if err != nil || cfg.Type == "" || cfg.Type == b.ctype.name() {
		return "", false
	}
	return cfg.Type, true
}

// mismatchCause describes the mismatch for the server log.
func (b *backend) mismatchCause(stored string) error {
	if b.unsupported != "" {
		return fmt.Errorf("mount option type=%q is not supported by this build", b.unsupported)
	}
	return fmt.Errorf("mount option type=%q but the stored configuration is for %q", b.ctype.name(), stored)
}

// mismatchFailure is the answer for a mount whose type does not match: the same
// fixed answers as any other failure, except that an authenticated caller is told
// the one thing it needs to fix it.
func mismatchFailure(kind handlerKind) (*logical.Response, error) {
	if kind == kindAuthenticated {
		return nil, logical.CodedError(http.StatusInternalServerError, typeMismatchMessage)
	}
	return failure(kind)
}

// unavailable is the 503 for the public endpoints: a fixed body that never holds
// error text, no-store, and a retry hint. The storage failure and corrupt data
// look the same, because the plugin cannot tell a transient error from permanent
// corruption.
func unavailable() *logical.Response {
	r := rawResponse(http.StatusServiceUnavailable, "application/json", []byte(`{"error":"temporarily_unavailable"}`), "no-store")
	r.Headers = map[string][]string{"Retry-After": {"30"}}
	return r
}

// logCause logs why a handler failed: one error-level line per key at most once
// a minute. The key is a fixed handler name, so the set of keys is bounded.
func (b *backend) logCause(key, what string, err error, extra ...interface{}) {
	now := b.now()
	b.logMu.Lock()
	if last, ok := b.lastLog[key]; ok && now.Sub(last) < logEvery {
		b.logMu.Unlock()
		return
	}
	if b.lastLog == nil {
		b.lastLog = make(map[string]time.Time)
	}
	b.lastLog[key] = now
	b.logMu.Unlock()
	args := append([]interface{}{"handler", key, "error", err}, extra...)
	b.Logger().Error(what, args...)
}

// guard wraps a handler: it recovers a panic, and replaces any error other than
// the forwarding signal with the fixed answer for the handler's kind, logging
// the cause.
func (b *backend) guard(kind handlerKind, name string, cb framework.OperationFunc) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (resp *logical.Response, err error) {
		defer func() {
			if p := recover(); p != nil {
				b.logCause(name, "handler panicked", fmt.Errorf("%v", p), "stack", string(debug.Stack()))
				resp, err = failure(kind)
			}
		}()
		if stored, bad := b.typeMismatch(ctx, req.Storage); bad {
			b.logCause(name+".type", typeMismatchMessage, b.mismatchCause(stored))
			return mismatchFailure(kind)
		}
		resp, err = cb(ctx, req, d)
		if err != nil && !errors.Is(err, logical.ErrReadOnly) {
			b.logCause(name, "handler failed", err)
			return failure(kind)
		}
		return resp, err
	}
}

// guardExistence does the same for an existence check, whose error would
// otherwise reach the caller.
func (b *backend) guardExistence(name string, fn framework.ExistenceFunc) framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (exists bool, err error) {
		defer func() {
			if p := recover(); p != nil {
				b.logCause(name, "existence check panicked", fmt.Errorf("%v", p))
				exists, err = false, logical.CodedError(http.StatusInternalServerError, internalErrorMessage)
			}
		}()
		if stored, bad := b.typeMismatch(ctx, req.Storage); bad {
			b.logCause(name+".type", typeMismatchMessage, b.mismatchCause(stored))
			return false, logical.CodedError(http.StatusInternalServerError, typeMismatchMessage)
		}
		exists, err = fn(ctx, req, d)
		if err != nil && !errors.Is(err, logical.ErrReadOnly) {
			b.logCause(name, "existence check failed", err)
			return false, logical.CodedError(http.StatusInternalServerError, internalErrorMessage)
		}
		return exists, err
	}
}
