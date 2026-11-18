// Package scanner implements bounded, cancellation-aware network probes.
package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vrma8/reconx/internal/model"
)

type Options struct {
	Workers int
	Rate    int
	Timeout time.Duration
	// Retries is the number of attempts after the initial probe. Every retry
	// consumes a rate-limit token, so the configured rate remains a real cap.
	Retries int
}

type Result struct {
	Host string
	Port int
	UDP  bool
}

// ScanTCP uses a bounded worker pool instead of one goroutine per probe. The
// generator, limiter and workers all observe ctx so Ctrl+C leaves no hanging
// network dials.
func ScanTCP(ctx context.Context, hosts []netip.Addr, ports []int, options Options) ([]Result, error) {
	if len(hosts) == 0 || len(ports) == 0 { return nil, nil }
	if options.Workers < 1 || options.Rate < 1 || options.Timeout <= 0 || options.Retries < 0 { return nil, fmt.Errorf("invalid scan options") }
	jobs := make(chan Result, options.Workers*2)
	results := make(chan Result, options.Workers)
	var workers sync.WaitGroup
	limiter := newLimiter(ctx, options.Rate)
	defer limiter.Stop()
	for i := 0; i < options.Workers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			dialer := net.Dialer{Timeout: options.Timeout}
			for job := range jobs {
				open := false
				for attempt := 0; attempt <= options.Retries; attempt++ {
					if err := limiter.Wait(ctx); err != nil { return }
					connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(job.Host, fmt.Sprint(job.Port)))
					if err == nil { connection.Close(); open = true; break }
					if attempt < options.Retries && !sleepContext(ctx, retryDelay(attempt)) { return }
				}
				if open { select { case results <- job: case <-ctx.Done(): return } }
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, host := range hosts {
			for _, port := range ports {
				select { case jobs <- Result{Host: host.String(), Port: port}: case <-ctx.Done(): return }
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()
	output := make([]Result, 0)
	for result := range results { output = append(output, result) }
	if err := ctx.Err(); err != nil { return output, err }
	sort.Slice(output, func(i, j int) bool { if output[i].Host == output[j].Host { return output[i].Port < output[j].Port }; return output[i].Host < output[j].Host })
	return output, nil
}

// ScanUDP reports responsive UDP ports. UDP filtering is intentionally not
// inferred as closed: silence is ambiguous by design.
func ScanUDP(ctx context.Context, hosts []netip.Addr, ports []int, options Options) ([]Result, error) {
	if len(hosts) == 0 || len(ports) == 0 { return nil, nil }
	if options.Workers < 1 || options.Rate < 1 || options.Timeout <= 0 || options.Retries < 0 { return nil, fmt.Errorf("invalid scan options") }
	jobs := make(chan Result, options.Workers*2)
	results := make(chan Result, options.Workers)
	limiter := newLimiter(ctx, options.Rate)
	defer limiter.Stop()
	var workers sync.WaitGroup
	for i := 0; i < options.Workers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			dialer := net.Dialer{Timeout: options.Timeout}
			buffer := make([]byte, 128)
			for job := range jobs {
				responsive := false
				for attempt := 0; attempt <= options.Retries; attempt++ {
					if limiter.Wait(ctx) != nil { return }
					connection, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(job.Host, fmt.Sprint(job.Port)))
					if err == nil {
						_ = connection.SetDeadline(time.Now().Add(options.Timeout))
						_, _ = connection.Write([]byte{0})
						_, err = connection.Read(buffer)
						connection.Close()
						if err == nil { responsive = true; break }
					}
					if attempt < options.Retries && !sleepContext(ctx, retryDelay(attempt)) { return }
				}
				if responsive { select { case results <- Result{Host: job.Host, Port: job.Port, UDP: true}: case <-ctx.Done(): return } }
			}
		}()
	}
	go func() { defer close(jobs); for _, h := range hosts { for _, p := range ports { select { case jobs <- Result{Host:h.String(), Port:p, UDP:true}: case <-ctx.Done(): return } } } }()
	go func() { workers.Wait(); close(results) }()
	output := make([]Result, 0)
	for result := range results { output = append(output, result) }
	if err := ctx.Err(); err != nil { return output, err }
	sort.Slice(output, func(i, j int) bool { if output[i].Host == output[j].Host { return output[i].Port < output[j].Port }; return output[i].Host < output[j].Host })
	return output, nil
}

func ProbeService(ctx context.Context, host string, port int, timeout time.Duration, serverName string) model.Service {
	service := model.Service{Host: host, Port: port, Transport: "tcp", Name: PortName(port)}
	address := net.JoinHostPort(host, fmt.Sprint(port))
	dialer := net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil { return service }
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	if isTLSPort(port) {
		name := serverName
		if name == "" { name = host }
		tlsConnection := tls.Client(connection, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}) // #nosec G402 -- reconnaissance records certificates before trust validation.
		if err := tlsConnection.HandshakeContext(ctx); err == nil {
			service.TLS = true
			service.Name = "https"
			state := tlsConnection.ConnectionState()
			service.TLSVersion = tlsVersion(state.Version)
			service.TLSCipher = tls.CipherSuiteName(state.CipherSuite)
			if len(state.PeerCertificates) > 0 { service.Version = state.PeerCertificates[0].Subject.CommonName }
			_ = tlsConnection.Close()
			return service
		}
	}
	buffer := make([]byte, 1024)
	count, _ := connection.Read(buffer)
	service.Banner = sanitizeBanner(string(buffer[:count]))
	if strings.HasPrefix(service.Banner, "SSH-") { service.Name = "ssh" }
	return service
}

func tlsVersion(version uint16) string {
	switch version { case tls.VersionTLS13: return "TLS 1.3"; case tls.VersionTLS12: return "TLS 1.2"; case tls.VersionTLS11: return "TLS 1.1"; case tls.VersionTLS10: return "TLS 1.0"; default: return fmt.Sprintf("0x%x", version) }
}

func PortName(port int) string {
	switch port {
	case 21: return "ftp"
	case 22: return "ssh"
	case 23: return "telnet"
	case 25, 465, 587: return "smtp"
	case 53: return "dns"
	case 80, 8080, 8000, 8008, 8888: return "http"
	case 110, 995: return "pop3"
	case 111: return "rpcbind"
	case 135: return "msrpc"
	case 139, 445: return "smb"
	case 143, 993: return "imap"
	case 161: return "snmp"
	case 389, 636: return "ldap"
	case 443, 8443, 9443: return "https"
	case 1433: return "mssql"
	case 1521: return "oracle"
	case 2049: return "nfs"
	case 3306: return "mysql"
	case 3389: return "rdp"
	case 5432: return "postgresql"
	case 5900: return "vnc"
	case 6379: return "redis"
	case 27017: return "mongodb"
	default: return "unknown"
	}
}

func isTLSPort(port int) bool { return port == 443 || port == 465 || port == 636 || port == 993 || port == 995 || port == 8443 || port == 9443 }
func sanitizeBanner(value string) string { value = strings.Map(func(r rune) rune { if r < 32 && r != '\n' && r != '\r' && r != '\t' { return -1 }; return r }, value); if len(value) > 500 { return value[:500] }; return strings.TrimSpace(value) }

type limiter struct { ticker *time.Ticker; immediate chan struct{} }
func newLimiter(ctx context.Context, rate int) *limiter {
	interval := time.Second / time.Duration(rate)
	if interval < time.Microsecond { interval = time.Microsecond }
	return &limiter{ticker: time.NewTicker(interval)}
}
func (l *limiter) Wait(ctx context.Context) error { select { case <-ctx.Done(): return ctx.Err(); case <-l.ticker.C: return nil } }
func (l *limiter) Stop() { l.ticker.Stop() }

func retryDelay(attempt int) time.Duration {
	return time.Duration(1<<attempt) * 25 * time.Millisecond
}

func sleepContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select { case <-ctx.Done(): return false; case <-timer.C: return true }
}
