package backend

import (
	"strings"
	"testing"
)

func TestValidRoleName(t *testing.T) {
	good := []string{"a", "0", "billing-svc", "a_b", "a1", strings.Repeat("a", 64)}
	bad := []string{"", "Billing", "-a", "a-", "_a", "a_", "a.b", ".", "..", "a/b", "a b", strings.Repeat("a", 65)}
	for _, n := range good {
		if !validRoleName(n) {
			t.Errorf("validRoleName(%q) = false, want true", n)
		}
	}
	for _, n := range bad {
		if validRoleName(n) {
			t.Errorf("validRoleName(%q) = true, want false", n)
		}
	}
}

func TestValidNonce(t *testing.T) {
	good := []string{"k3Jx9wQ2mZpL7vTa", strings.Repeat("A", 128), "a_-b_-c_-d_-e_-f"}
	bad := []string{"", "short", strings.Repeat("A", 129), "k3Jx9wQ2mZpL7vT=", "k3Jx9wQ2mZpL7vT+", "k3Jx9wQ2mZpL7vT "}
	for _, n := range good {
		if !validNonce(n) {
			t.Errorf("validNonce(%q) = false, want true", n)
		}
	}
	for _, n := range bad {
		if validNonce(n) {
			t.Errorf("validNonce(%q) = true, want false", n)
		}
	}
}

func TestValidateReceiptURL(t *testing.T) {
	good := []string{
		"https://billing.internal/courier/receive",
		"https://billing.internal/courier/receive/",
		"https://a.b.example.com:8443/x",
		"https://xn--bcher-kva.example/x",
		"https://localhost/x",
		"https://h/a-b_c.d~e",
		"https://example.com/" + strings.Repeat("a", 2048-len("https://example.com/")),
	}
	bad := map[string]string{
		"http://billing.internal/x":                         "http scheme",
		"HTTPS://billing.internal/x":                        "uppercase scheme",
		"https://Billing.internal/x":                        "uppercase host",
		"https://billing.internal":                          "empty path",
		"https://billing.internal:443/x":                    "explicit :443",
		"https://billing.internal:0443/x":                   "leading zero port",
		"https://billing.internal:0/x":                      "port 0",
		"https://billing.internal:65536/x":                  "port too large",
		"https://billing.internal:/x":                       "empty port",
		"https://user@billing.internal/x":                   "userinfo",
		"https://user:pw@billing.internal/x":                "userinfo with password",
		"https://billing.internal/x?a=b":                    "query",
		"https://billing.internal/x#f":                      "fragment",
		"https://billing.internal./x":                       "trailing dot",
		"https://bücher.example/x":                          "unicode host",
		"https://10.0.0.1/x":                                "ipv4 literal",
		"https://010.0.0.1/x":                               "octal ipv4",
		"https://0x7f.1/x":                                  "hex-ish ipv4",
		"https://0x7f/x":                                    "hex ipv4",
		"https://[::1]/x":                                   "ipv6 literal",
		"https://billing.internal/a%20b":                    "percent-encoding",
		"https://billing.internal/a/../b":                   "dot-dot segment",
		"https://billing.internal/./b":                      "dot segment",
		"https://billing.internal/a b":                      "whitespace",
		"https://billing.internal/a\tb":                     "control character",
		"https://-a.example/x":                              "label starts with hyphen",
		"https://a..example/x":                              "empty label",
		"https://" + strings.Repeat("a", 64) + ".example/x": "label too long",
		"https://example.com/" + strings.Repeat("a", 2048):  "too long",
	}
	for _, u := range good {
		if err := validateReceiptURL(u); err != nil {
			t.Errorf("validateReceiptURL(%q) = %v, want nil", u, err)
		}
	}
	for u, why := range bad {
		if err := validateReceiptURL(u); err == nil {
			t.Errorf("validateReceiptURL(%q) accepted (%s), want error", u, why)
		}
	}
}
