// Package utils holds validated target and collection helpers.
package utils

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/vrma8/reconx/internal/model"
)

var domainPattern = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$`)

type ParsedTarget struct {
	Profile model.TargetProfile
	Prefix  netip.Prefix
}

func ParseTarget(input string) (ParsedTarget, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return ParsedTarget{}, fmt.Errorf("target is required")
	}
	if prefix, err := netip.ParsePrefix(input); err == nil {
		if !prefix.Addr().Is4() {
			return ParsedTarget{}, fmt.Errorf("only IPv4 CIDRs are currently supported")
		}
		if prefix.Bits() < 16 {
			return ParsedTarget{}, fmt.Errorf("CIDRs broader than /16 are not accepted")
		}
		return ParsedTarget{Profile: model.TargetProfile{Input: input, Kind: model.TargetCIDR, CIDR: prefix.Masked().String()}, Prefix: prefix.Masked()}, nil
	}
	if address, err := netip.ParseAddr(input); err == nil {
		return ParsedTarget{Profile: model.TargetProfile{Input: input, Kind: model.TargetIP, IPs: []string{address.String()}}, Prefix: netip.PrefixFrom(address, address.BitLen())}, nil
	}
	if strings.Contains(input, "://") {
		parsed, err := url.Parse(input)
		if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
			return ParsedTarget{}, fmt.Errorf("invalid URL target %q", input)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return ParsedTarget{}, fmt.Errorf("target URL must use http or https")
		}
		if parsed.User != nil {
			return ParsedTarget{}, fmt.Errorf("target URL must not contain credentials")
		}
		host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
		if !isHost(host) {
			return ParsedTarget{}, fmt.Errorf("invalid URL hostname %q", host)
		}
		parsed.Fragment = ""
		return ParsedTarget{Profile: model.TargetProfile{Input: input, Kind: model.TargetURL, Hostname: host, URL: parsed.String()}}, nil
	}
	host := strings.TrimSuffix(strings.ToLower(input), ".")
	if !domainPattern.MatchString(host) {
		return ParsedTarget{}, fmt.Errorf("target must be an IP, IPv4 CIDR, domain, or http(s) URL")
	}
	return ParsedTarget{Profile: model.TargetProfile{Input: input, Kind: model.TargetDomain, Hostname: host}}, nil
}

func ResolveTarget(ctx context.Context, target ParsedTarget) (model.TargetProfile, error) {
	profile := target.Profile
	if profile.Kind == model.TargetCIDR {
		profile.ResolvedAt = time.Now().UTC()
		return profile, nil
	}
	if profile.Kind != model.TargetIP {
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", profile.Hostname)
		if err != nil {
			return profile, fmt.Errorf("resolve %s: %w", profile.Hostname, err)
		}
		for _, address := range addresses {
			profile.IPs = append(profile.IPs, address.String())
		}
		profile.IPs = normalized(profile.IPs)
	}
	for _, ip := range profile.IPs {
		if names, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil {
			profile.ReverseNames = append(profile.ReverseNames, names...)
		}
	}
	profile.ReverseNames = normalized(profile.ReverseNames)
	profile.CloudProvider = CloudProvider(append([]string{profile.Hostname}, profile.ReverseNames...))
	profile.ResolvedAt = time.Now().UTC()
	return profile, nil
}

// CloudProvider uses provider-owned DNS suffixes as an attribution hint. It
// intentionally returns an empty value for a plain IP: an address alone is not
// proof of tenant ownership or cloud provider assignment.
func CloudProvider(names []string) string {
	for _, name := range names {
		value := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		switch {
		case strings.HasSuffix(value, ".amazonaws.com") || strings.HasSuffix(value, ".aws.amazon.com"):
			return "AWS"
		case strings.HasSuffix(value, ".cloudapp.azure.com") || strings.HasSuffix(value, ".azurewebsites.net") || strings.HasSuffix(value, ".windows.net"):
			return "Azure"
		case strings.HasSuffix(value, ".googleusercontent.com") || strings.HasSuffix(value, ".googleapis.com") || strings.HasSuffix(value, ".appspot.com"):
			return "GCP"
		case strings.HasSuffix(value, ".digitaloceanspaces.com") || strings.HasSuffix(value, ".ondigitalocean.app"):
			return "DigitalOcean"
		case strings.HasSuffix(value, ".ovh.net"):
			return "OVH"
		}
	}
	return ""
}

func CIDRAddresses(prefix netip.Prefix, max int) ([]netip.Addr, error) {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return nil, fmt.Errorf("invalid IPv4 CIDR")
	}
	size := 1 << (32 - prefix.Bits())
	if size > max {
		return nil, fmt.Errorf("CIDR has %d addresses, exceeding configured maximum of %d", size, max)
	}
	start := prefix.Masked().Addr()
	addresses := make([]netip.Addr, 0, size)
	for address := start; prefix.Contains(address); address = address.Next() {
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func IsSubdomainOrEqual(host, root string) bool {
	host, root = strings.TrimSuffix(strings.ToLower(host), "."), strings.TrimSuffix(strings.ToLower(root), ".")
	return host == root || strings.HasSuffix(host, "."+root)
}

func normalized(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(value)), ".")
		if value != "" {
			set[value] = struct{}{}
		}
	}
	output := make([]string, 0, len(set))
	for value := range set {
		output = append(output, value)
	}
	sort.Strings(output)
	return output
}

func isHost(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	return domainPattern.MatchString(host)
}

func Strings(values []string) []string { return normalized(values) }
