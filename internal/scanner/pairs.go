package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
)

// ScanTCPPairs verifies a sparse list of host/port pairs, for example results
// from a masscan pre-scan. It uses the same global rate limiter and retry
// semantics as ScanTCP without expanding pairs into a host×port Cartesian set.
func ScanTCPPairs(ctx context.Context, candidates []Result, options Options) ([]Result, error) {
	if len(candidates) == 0 { return nil, nil }
	if options.Workers < 1 || options.Rate < 1 || options.Timeout <= 0 || options.Retries < 0 { return nil, fmt.Errorf("invalid scan options") }
	jobs := make(chan Result, options.Workers*2)
	results := make(chan Result, options.Workers)
	limiter := newLimiter(ctx, options.Rate)
	defer limiter.Stop()
	var group sync.WaitGroup
	for index := 0; index < options.Workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			dialer := net.Dialer{Timeout: options.Timeout}
			for candidate := range jobs {
				open := false
				for attempt := 0; attempt <= options.Retries; attempt++ {
					if limiter.Wait(ctx) != nil { return }
					connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(candidate.Host, fmt.Sprint(candidate.Port)))
					if err == nil { connection.Close(); open = true; break }
					if attempt < options.Retries && !sleepContext(ctx, retryDelay(attempt)) { return }
				}
				if open { select { case results <- candidate: case <-ctx.Done(): return } }
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, candidate := range dedupePairs(candidates) { select { case jobs <- candidate: case <-ctx.Done(): return } }
	}()
	go func() { group.Wait(); close(results) }()
	output := make([]Result, 0)
	for result := range results { output = append(output, result) }
	if err := ctx.Err(); err != nil { return output, err }
	sort.Slice(output, func(i, j int) bool { if output[i].Host == output[j].Host { return output[i].Port < output[j].Port }; return output[i].Host < output[j].Host })
	return output, nil
}

func dedupePairs(values []Result) []Result {
	seen := make(map[string]struct{}, len(values))
	output := make([]Result, 0, len(values))
	for _, value := range values {
		key := fmt.Sprintf("%s:%d", value.Host, value.Port)
		if _, found := seen[key]; !found { seen[key] = struct{}{}; output = append(output, value) }
	}
	return output
}
