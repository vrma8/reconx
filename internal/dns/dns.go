// Package dns provides bounded DNS collection and name resolution.
package dns

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vrma8/reconx/internal/model"
)

func Records(ctx context.Context, name string) model.DNSRecord {
	record := model.DNSRecord{Name: strings.TrimSuffix(strings.ToLower(name), ".")}
	resolver := net.DefaultResolver
	var group sync.WaitGroup
	var lock sync.Mutex
	failure := func(err error) { if err != nil { lock.Lock(); record.Lookup = append(record.Lookup, err.Error()); lock.Unlock() } }
	group.Add(6)
	go func() { defer group.Done(); value, err := resolver.LookupNetIP(ctx, "ip4", name); if err == nil { for _, address := range value { record.A = append(record.A, address.String()) } } else { failure(err) } }()
	go func() { defer group.Done(); value, err := resolver.LookupNetIP(ctx, "ip6", name); if err == nil { for _, address := range value { record.AAAA = append(record.AAAA, address.String()) } } else { failure(err) } }()
	go func() { defer group.Done(); value, err := resolver.LookupCNAME(ctx, name); if err == nil { record.CNAME = strings.TrimSuffix(strings.ToLower(value), ".") } else { failure(err) } }()
	go func() { defer group.Done(); value, err := resolver.LookupMX(ctx, name); if err == nil { for _, mx := range value { record.MX = append(record.MX, strings.TrimSuffix(mx.Host, ".")) } } else { failure(err) } }()
	go func() { defer group.Done(); value, err := resolver.LookupNS(ctx, name); if err == nil { for _, ns := range value { record.NS = append(record.NS, strings.TrimSuffix(ns.Host, ".")) } } else { failure(err) } }()
	go func() { defer group.Done(); value, err := resolver.LookupTXT(ctx, name); if err == nil { record.TXT = append(record.TXT, value...) } else { failure(err) } }()
	group.Wait()
	record.A, record.AAAA, record.MX, record.NS, record.TXT, record.Lookup = unique(record.A), unique(record.AAAA), unique(record.MX), unique(record.NS), unique(record.TXT), unique(record.Lookup)
	return record
}

// ResolveMany resolves names through a bounded worker pool. It keeps the
// historic no-rate-limit behaviour for callers that are not issuing an active
// brute force. Active enumeration should use ResolveManyRateLimited.
// CNAME returns only an actual alias target. net.Resolver.LookupCNAME returns
// the original name when no alias exists, which is intentionally normalized to
// an empty value here so takeover detection does not generate false candidates.
func CNAME(ctx context.Context, name string) (string, error) {
	input := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	value, err := net.DefaultResolver.LookupCNAME(ctx, input)
	if err != nil { return "", err }
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	if value == input { return "", nil }
	return value, nil
}

// CNAMEManyRateLimited performs the single DNS lookup needed for takeover
// candidate discovery. It deliberately avoids calling Records, which would do
// six unrelated record lookups for every subdomain.
func CNAMEManyRateLimited(ctx context.Context, names []string, workers, rate int) map[string]string {
	if workers < 1 { workers = 1 }
	if workers > 1000 { workers = 1000 }
	jobs := make(chan string, workers*2)
	output := make(map[string]string)
	var lock sync.Mutex
	var group sync.WaitGroup
	var ticks <-chan time.Time
	var ticker *time.Ticker
	if rate > 0 {
		interval := time.Second / time.Duration(rate)
		if interval < time.Microsecond { interval = time.Microsecond }
		ticker = time.NewTicker(interval)
		ticks = ticker.C
		defer ticker.Stop()
	}
	for i := 0; i < workers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for name := range jobs {
				if ticks != nil { select { case <-ticks: case <-ctx.Done(): return } }
				alias, err := CNAME(ctx, name)
				if err != nil || alias == "" { continue }
				lock.Lock(); output[name] = alias; lock.Unlock()
			}
		}()
	}
	go func() { defer close(jobs); for _, name := range unique(names) { select { case jobs <- name: case <-ctx.Done(): return } } }()
	group.Wait()
	return output
}

func ResolveMany(ctx context.Context, names []string, workers int) map[string][]netip.Addr {
	return ResolveManyRateLimited(ctx, names, workers, 0)
}

// ResolveManyRateLimited resolves each distinct candidate at most once and
// spaces DNS starts at rate requests/second when rate is positive. A worker
// pool avoids a goroutine per name, while the shared ticker prevents the
// worker count from accidentally multiplying DNS traffic.
func ResolveManyRateLimited(ctx context.Context, names []string, workers, rate int) map[string][]netip.Addr {
	if workers < 1 { workers = 1 }
	if workers > 1000 { workers = 1000 }
	jobs := make(chan string, workers*2)
	output := make(map[string][]netip.Addr)
	var outputLock sync.Mutex
	var group sync.WaitGroup
	var ticks <-chan time.Time
	var ticker *time.Ticker
	if rate > 0 {
		interval := time.Second / time.Duration(rate)
		if interval < time.Microsecond { interval = time.Microsecond }
		ticker = time.NewTicker(interval)
		ticks = ticker.C
		defer ticker.Stop()
	}
	for i := 0; i < workers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for name := range jobs {
				if ticks != nil { select { case <-ticks: case <-ctx.Done(): return } }
				addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
				if err != nil { continue }
				outputLock.Lock()
				output[name] = addresses
				outputLock.Unlock()
			}
		}()
	}
	go func() { defer close(jobs); for _, name := range unique(names) { select { case jobs <- name: case <-ctx.Done(): return } } }()
	group.Wait()
	return output
}

// BruteRateLimited constructs in-scope FQDN candidates and resolves them with
// the same bounded worker/rate semantics used by Phase 2.
func BruteRateLimited(ctx context.Context, root string, words []string, workers, rate int) []string {
	root = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(root)), ".")
	if root == "" { return nil }
	candidates := make([]string, 0, len(words))
	for _, word := range unique(words) {
		word = strings.ToLower(word)
		if !validPrefix(word) { continue }
		candidates = append(candidates, word+"."+root)
	}
	resolved := ResolveManyRateLimited(ctx, candidates, workers, rate)
	output := make([]string, 0, len(resolved))
	for candidate := range resolved { output = append(output, candidate) }
	sort.Strings(output)
	return output
}

// LoadWords reads a line-oriented wordlist defensively. It imposes a caller
// supplied maximum to keep a large SecLists file from turning into unbounded
// memory and DNS traffic.
func LoadWords(path string, maximum int) ([]string, error) {
	file, err := os.Open(path)
	if err != nil { return nil, err }
	defer file.Close()
	words := make([]string, 0)
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if word == "" || strings.HasPrefix(word, "#") || strings.ContainsAny(word, "/\\ ") { continue }
		if _, found := seen[word]; found { continue }
		seen[word] = struct{}{}
		words = append(words, word)
		if maximum > 0 && len(words) >= maximum { break }
	}
	return words, scanner.Err()
}

func Brute(ctx context.Context, root string, words []string, workers int) []string {
	return BruteRateLimited(ctx, root, words, workers, 0)
}

func validPrefix(value string) bool {
	if value == "" || len(value) > 63 || strings.HasPrefix(value, "-") || strings.HasSuffix(value, "-") { return false }
	for _, character := range value {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') { return false }
	}
	return true
}

func unique(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values { value = strings.TrimSpace(value); if value != "" { set[value] = struct{}{} } }
	output := make([]string, 0, len(set))
	for value := range set { output = append(output, value) }
	sort.Strings(output)
	return output
}
