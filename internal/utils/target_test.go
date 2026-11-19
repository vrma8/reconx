package utils

import (
	"net/netip"
	"testing"

	"github.com/vrma8/reconx/internal/model"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		input string
		kind  model.TargetKind
	}{
		{"192.0.2.10", model.TargetIP}, {"192.0.2.0/24", model.TargetCIDR}, {"example.com", model.TargetDomain}, {"https://app.example.com/path", model.TargetURL},
	}
	for _, test := range cases {
		value, err := ParseTarget(test.input)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", test.input, err)
		}
		if value.Profile.Kind != test.kind {
			t.Fatalf("ParseTarget(%q) kind = %q, want %q", test.input, value.Profile.Kind, test.kind)
		}
	}
}

func TestRejectBroadOrUnsafeTargets(t *testing.T) {
	for _, input := range []string{"10.0.0.0/8", "ftp://example.com", "https://user:password@example.com", "not a domain"} {
		if _, err := ParseTarget(input); err == nil {
			t.Fatalf("ParseTarget(%q) unexpectedly succeeded", input)
		}
	}
}

func TestCloudProvider(t *testing.T) {
	if got := CloudProvider([]string{"ec2-203-0-113-1.compute.amazonaws.com"}); got != "AWS" {
		t.Fatalf("provider = %q", got)
	}
	if got := CloudProvider([]string{"example.com"}); got != "" {
		t.Fatalf("provider = %q", got)
	}
}

func TestCIDRAddressesHonorsBudget(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/30")
	addresses, err := CIDRAddresses(prefix, 4)
	if err != nil || len(addresses) != 4 {
		t.Fatalf("CIDRAddresses = %v, %v", addresses, err)
	}
	if _, err = CIDRAddresses(prefix, 3); err == nil {
		t.Fatal("expected budget error")
	}
}
