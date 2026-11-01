package backend

import (
	"net/netip"
	"testing"
)

func TestNetworkPolicyValidation(t *testing.T) {
	if _, err := newNetworkPolicy([]string{"10.0.0.0/8"}, []string{"192.168.0.0/16"}); err == nil {
		t.Error("both lists non-empty accepted")
	}
	if _, err := newNetworkPolicy([]string{"10.0.0.5/8"}, nil); err == nil {
		t.Error("host bits set accepted")
	}
	if _, err := newNetworkPolicy([]string{"not-a-cidr"}, nil); err == nil {
		t.Error("invalid CIDR accepted")
	}
	many := make([]string, maxNetworkEntries+1)
	for i := range many {
		many[i] = "10.0.0.0/8"
	}
	if _, err := newNetworkPolicy(many, nil); err == nil {
		t.Error("more than 64 entries accepted")
	}
	if _, err := newNetworkPolicy(nil, nil); err != nil {
		t.Errorf("empty policy rejected: %v", err)
	}
}

func TestNetworkPolicyPermits(t *testing.T) {
	addr := netip.MustParseAddr
	open, _ := newNetworkPolicy(nil, nil)
	if !open.permits(addr("8.8.8.8")) {
		t.Error("empty policy must permit everything")
	}
	allow, _ := newNetworkPolicy([]string{"10.0.0.0/8"}, nil)
	if !allow.permits(addr("10.1.2.3")) || allow.permits(addr("8.8.8.8")) {
		t.Error("allowed_networks misbehaves")
	}
	if !allow.permits(addr("::ffff:10.1.2.3")) {
		t.Error("IPv4-mapped IPv6 must be unmapped before the check")
	}
	deny, _ := newNetworkPolicy(nil, []string{"169.254.0.0/16"})
	if deny.permits(addr("169.254.169.254")) || !deny.permits(addr("8.8.8.8")) {
		t.Error("denied_networks misbehaves")
	}
}
