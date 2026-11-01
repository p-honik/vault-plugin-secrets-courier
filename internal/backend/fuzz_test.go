package backend

import (
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

// FuzzValidateReceiptURL checks the invariant behind "there is no normalization":
// every accepted URL is already in the one canonical spelling, so a standard URL
// parser reads it back to exactly the same string and it has no userinfo, query,
// fragment, IP literal, escapes or dot segments.
func FuzzValidateReceiptURL(f *testing.F) {
	for _, s := range []string{
		"https://billing.internal/courier/receive", "https://a.b.example.com:8443/x", "https://xn--bcher-kva.example/x",
		"https://10.0.0.1/x", "https://0x7f.1/x", "https://[::1]/x", "https://h/%41", "https://h:443/x", "https://h/a/../b",
		"https://u@h/x", "https://h/x?q", "https://h/x#f", "HTTPS://h/x", "https://H/x", "https://h./x", "https://h/a b",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if validateReceiptURL(s) != nil {
			return
		}
		u, err := url.Parse(s)
		if err != nil {
			t.Fatalf("accepted %q but url.Parse fails: %v", s, err)
		}
		if u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
			t.Fatalf("accepted %q with scheme %q user %v query %q fragment %q", s, u.Scheme, u.User, u.RawQuery, u.Fragment)
		}
		if u.String() != s {
			t.Fatalf("accepted %q but it is not canonical: parses back to %q", s, u.String())
		}
		if u.Hostname() != strings.ToLower(u.Hostname()) || u.Hostname() == "" {
			t.Fatalf("accepted %q with host %q", s, u.Hostname())
		}
		if _, err := netip.ParseAddr(u.Hostname()); err == nil {
			t.Fatalf("accepted %q whose host is an IP literal", s)
		}
		if u.Port() == "443" {
			t.Fatalf("accepted %q with an explicit default port", s)
		}
		if u.Path != u.EscapedPath() || strings.Contains(s, "%") {
			t.Fatalf("accepted %q containing percent-encoding", s)
		}
		for _, seg := range strings.Split(u.Path, "/") {
			if seg == "." || seg == ".." {
				t.Fatalf("accepted %q with a dot segment", s)
			}
		}
		if len(s) > maxReceiptURL {
			t.Fatalf("accepted %q longer than the cap", s)
		}
	})
}

// FuzzNonceAndRoleName: the validators never panic and never accept what the
// format forbids.
func FuzzNonceAndRoleName(f *testing.F) {
	for _, s := range []string{"", "k3Jx9wQ2mZpL7vTa", "billing-svc", "A", "a.b", strings.Repeat("a", 70)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if validNonce(s) {
			if len(s) < 16 || len(s) > 128 || strings.Trim(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") != "" {
				t.Fatalf("accepted nonce %q", s)
			}
		}
		if validRoleName(s) {
			if len(s) > maxRoleNameLen || s != strings.ToLower(s) || strings.ContainsAny(s, "./ ") || s[0] == '-' || s[0] == '_' || s[len(s)-1] == '-' || s[len(s)-1] == '_' {
				t.Fatalf("accepted role name %q", s)
			}
		}
	})
}
