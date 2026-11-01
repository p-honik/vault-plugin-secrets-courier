package backend

import (
	"fmt"
	"net/netip"
)

// networkPolicy is the mount-level egress policy. The
// lists are mutually exclusive; both empty means no restriction beyond the
// receipt URL allowlist and verified TLS.
type networkPolicy struct {
	allowed []netip.Prefix
	denied  []netip.Prefix
	// denyAll makes the policy fail closed; used only if a stored policy cannot
	// be parsed.
	denyAll bool
}

// newNetworkPolicy parses and validates the two CIDR lists for a courier/config
// write: valid CIDRs with host bits clear, at most maxNetworkEntries each, and
// not both non-empty.
func newNetworkPolicy(allowed, denied []string) (*networkPolicy, error) {
	if len(allowed) > 0 && len(denied) > 0 {
		return nil, fmt.Errorf("allowed_networks and denied_networks are mutually exclusive")
	}
	a, err := parseCIDRs("allowed_networks", allowed)
	if err != nil {
		return nil, err
	}
	d, err := parseCIDRs("denied_networks", denied)
	if err != nil {
		return nil, err
	}
	return &networkPolicy{allowed: a, denied: d}, nil
}

func parseCIDRs(field string, in []string) ([]netip.Prefix, error) {
	if len(in) > maxNetworkEntries {
		return nil, fmt.Errorf("%s has more than %d entries", field, maxNetworkEntries)
	}
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a valid CIDR", field, s)
		}
		if p != p.Masked() {
			return nil, fmt.Errorf("%s: %q has host bits set", field, s)
		}
		out = append(out, p)
	}
	return out, nil
}

// permits reports whether a delivery may connect to addr. IPv4-mapped IPv6
// addresses are unmapped first. It is meant to run in the dialer's connection
// hook on the address actually dialed.
func (p *networkPolicy) permits(addr netip.Addr) bool {
	if p.denyAll {
		return false
	}
	addr = addr.Unmap()
	if len(p.allowed) > 0 {
		for _, n := range p.allowed {
			if n.Contains(addr) {
				return true
			}
		}
		return false
	}
	for _, n := range p.denied {
		if n.Contains(addr) {
			return false
		}
	}
	return true
}

// policyFor builds the policy from a validated mount config. A config that
// cannot be parsed fails closed.
func policyFor(mc *mountConfig) *networkPolicy {
	p, err := newNetworkPolicy(mc.AllowedNetworks, mc.DeniedNetworks)
	if err != nil {
		return &networkPolicy{denyAll: true}
	}
	return p
}
