package backend

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	hclog "github.com/hashicorp/go-hclog"
)

// Failure classes logged when a delivery gives up.
const (
	failureConnection     = "connection"
	failureTimeout        = "timeout"
	failureServerError    = "5xx"
	failureClientError    = "4xx"             // final, not retried
	failureRedirect       = "3xx"             // final, not retried; redirects are never followed
	failureBlockedAddress = "blocked_address" // final: the network policy forbids every address
	failureOther          = "other"           // final: request could not be built or an unexpected status
)

var errBlockedAddress = errors.New("address blocked by network policy")

// maxResponseDrain bounds how much of a receiver's response body is read.
const maxResponseDrain = 64 << 10

// delivery is one in-flight multipart POST. The goroutine needs no storage
// access and no key: the token is signed before it starts and lives only in
// memory.
type delivery struct {
	roleName   string
	credential string // type, e.g. "jwt"
	token      string
	receiptURL string
	nonce      string // empty means the request supplied none

	// Snapshot of the delivery options taken when the request arrived.
	retry           bool
	retryDelay      time.Duration
	deliveryTimeout time.Duration

	caPEM string // role's receipt_ca_pem; empty means system roots

	// policy is read at each connection attempt, so tightening the network
	// policy takes effect at once, including for a retry.
	policy func() *networkPolicy
	logger hclog.Logger
}

// run performs the attempt(s). ctx is the backend's long-lived context, not the
// request context, which ends when the handler returns. It returns the failure
// class ("" when delivered) and the number of attempts made.
func (d *delivery) run(ctx context.Context) (class string, attempts int) {
	maxAttempts := 1
	if d.retry {
		maxAttempts = 2
	}
	for attempts < maxAttempts {
		if attempts > 0 {
			select {
			case <-time.After(d.retryDelay):
			case <-ctx.Done():
				return d.giveUp(failureOther, attempts)
			}
		}
		attempts++
		class = d.attempt(ctx)
		if class == "" {
			return "", attempts
		}
		if !retryable(class) {
			break
		}
	}
	return d.giveUp(class, attempts)
}

// retryable: only a connection error, a timeout or an HTTP 5xx is retried.
func retryable(class string) bool {
	return class == failureConnection || class == failureTimeout || class == failureServerError
}

// giveUp logs the give-up line: role, receipt URL (allowlisted, so it has no
// userinfo or query), attempt count and failure class. Never the token or the
// nonce.
func (d *delivery) giveUp(class string, attempts int) (string, int) {
	if d.logger != nil {
		d.logger.Warn("delivery failed", "role", d.roleName, "receipt_url", d.receiptURL,
			"attempts", attempts, "failure", class)
	}
	return class, attempts
}

// attempt makes one POST and returns "" on success or a failure class.
func (d *delivery) attempt(ctx context.Context) string {
	body, contentType, err := d.multipartBody()
	if err != nil {
		return failureOther
	}
	ctx, cancel := context.WithTimeout(ctx, d.deliveryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.receiptURL, body)
	if err != nil {
		return failureOther
	}
	req.Header.Set("Content-Type", contentType)

	client, err := d.client()
	if err != nil {
		return failureOther
	}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return classifyError(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseDrain))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return ""
	case resp.StatusCode >= 500:
		return failureServerError
	case resp.StatusCode >= 400:
		return failureClientError
	case resp.StatusCode >= 300:
		return failureRedirect
	}
	return failureOther
}

func classifyError(err error) string {
	switch {
	case errors.Is(err, errBlockedAddress):
		return failureBlockedAddress
	case errors.Is(err, context.DeadlineExceeded):
		return failureTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return failureTimeout
	}
	return failureConnection
}

// multipartBody builds the delivery payload: token, name, type, and nonce only
// if the request supplied one.
func (d *delivery) multipartBody() (*bytes.Buffer, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fields := [][2]string{{"token", d.token}, {"name", d.roleName}, {"type", d.credential}}
	if d.nonce != "" {
		fields = append(fields, [2]string{"nonce", d.nonce})
	}
	for _, f := range fields {
		if err := w.WriteField(f[0], f[1]); err != nil {
			return nil, "", err
		}
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return &buf, w.FormDataContentType(), nil
}

// client builds a client that connects directly (no proxy, whatever the
// environment says), never follows redirects, verifies TLS against the system
// roots or the role's CA bundle, and checks every dialed address against the
// network policy in the dialer's connection hook.
func (d *delivery) client() (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if d.caPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(d.caPEM)) {
			return nil, errors.New("receipt_ca_pem contains no certificate")
		}
		tlsConfig.RootCAs = pool
	}
	dialer := &net.Dialer{
		Timeout: d.deliveryTimeout,
		Control: func(network, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: %v", errBlockedAddress, err)
			}
			// permits unmaps IPv4-mapped IPv6 addresses itself.
			if !d.policy().permits(ap.Addr()) {
				return errBlockedAddress
			}
			return nil
		},
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil, // never a proxy: the check must see the receiver's address
			DialContext:         dialer.DialContext,
			TLSClientConfig:     tlsConfig,
			TLSHandshakeTimeout: d.deliveryTimeout,
			DisableKeepAlives:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}
