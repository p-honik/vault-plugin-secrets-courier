package backend

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	maxRoleNameLen = 64
	maxReceiptURL  = 2048
	maxHostLen     = 253
	maxLabelLen    = 63
)

var (
	// Role names.
	roleNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$`)
	// Nonce: 16-128 base64url characters.
	nonceRE = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	// Host labels of a receipt URL.
	hostLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	pathCharsRE = regexp.MustCompile(`^[A-Za-z0-9._~/-]*$`)
)

// validRoleName reports whether name satisfies the role name rule. There is no
// normalization: a non-conforming name is rejected, never rewritten.
func validRoleName(name string) bool {
	return len(name) > 0 && len(name) <= maxRoleNameLen && roleNameRE.MatchString(name)
}

// validNonce reports whether nonce satisfies the nonce format.
func validNonce(nonce string) bool {
	return nonceRE.MatchString(nonce)
}

// validateReceiptURL checks one allowed_receipt_urls entry against the strict
// strict format. It never rewrites the value; the returned
// error names the broken rule.
func validateReceiptURL(u string) error {
	if len(u) > maxReceiptURL {
		return fmt.Errorf("receipt URL exceeds %d bytes", maxReceiptURL)
	}
	for i := 0; i < len(u); i++ {
		if u[i] <= 0x20 || u[i] == 0x7f {
			return errors.New("receipt URL contains whitespace or a control character")
		}
	}
	if strings.ContainsAny(u, "?#") {
		return errors.New("receipt URL must not contain a query or fragment")
	}
	rest, ok := strings.CutPrefix(u, "https://")
	if !ok {
		return errors.New("receipt URL must start with lowercase https://")
	}
	authority, path, hasPath := strings.Cut(rest, "/")
	if !hasPath {
		return errors.New("receipt URL path must not be empty")
	}
	path = "/" + path

	if strings.Contains(authority, "@") {
		return errors.New("receipt URL must not contain userinfo")
	}
	host, port, hasPort := strings.Cut(authority, ":")
	if hasPort {
		if err := validatePort(port); err != nil {
			return err
		}
	}
	if err := validateHost(host); err != nil {
		return err
	}
	return validatePath(path)
}

func validatePort(port string) error {
	if port == "" || port[0] == '0' || strings.Contains(port, ":") {
		return errors.New("receipt URL port must be 1-65535 without leading zeros")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return errors.New("receipt URL port must be 1-65535 without leading zeros")
	}
	if n == 443 {
		return errors.New("receipt URL must omit the default port 443")
	}
	return nil
}

func validateHost(host string) error {
	if host == "" || len(host) > maxHostLen {
		return errors.New("receipt URL host must be 1-253 characters")
	}
	if strings.HasSuffix(host, ".") {
		return errors.New("receipt URL host must not have a trailing dot")
	}
	labels := strings.Split(host, ".")
	for _, l := range labels {
		if len(l) == 0 || len(l) > maxLabelLen || !hostLabelRE.MatchString(l) {
			return errors.New("receipt URL host must be a lowercase ASCII DNS name (use xn-- punycode for international names)")
		}
	}
	// IP literals are rejected. IPv6 literals and zone IDs already fail the
	// label rule. For IPv4 in any spelling (decimal, octal, hex), a host whose
	// last label is numeric or hex-prefixed is treated as an address, as URL
	// parsers do; no real DNS top-level domain looks like that.
	last := labels[len(labels)-1]
	if isNumericLabel(last) || strings.HasPrefix(last, "0x") {
		return errors.New("receipt URL host must not be an IP literal")
	}
	return nil
}

func isNumericLabel(l string) bool {
	for i := 0; i < len(l); i++ {
		if l[i] < '0' || l[i] > '9' {
			return false
		}
	}
	return len(l) > 0
}

func validatePath(path string) error {
	if !pathCharsRE.MatchString(path) {
		return errors.New("receipt URL path may only use A-Z a-z 0-9 - . _ ~ / (no percent-encoding)")
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return errors.New("receipt URL path must not contain . or .. segments")
		}
	}
	return nil
}
