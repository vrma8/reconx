//go:build linux

package scanner

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"syscall"
	"time"
)

// ErrRawUnavailable indicates that the process lacks CAP_NET_RAW or the host
// does not permit raw IP sockets. Callers should fall back to TCP connect.
var ErrRawUnavailable = errors.New("raw SYN socket unavailable")

const synBatchSize = 1024

// ScanSYN sends a bounded number of TCP SYN probes from a raw IP socket and
// records SYN/ACK responses. It never completes a TCP handshake and does not
// send data. Each batch uses a unique source port and expires after Timeout.
func ScanSYN(ctx context.Context, hosts []netip.Addr, ports []int, options Options) ([]Result, error) {
	if options.Workers < 1 || options.Rate < 1 || options.Timeout <= 0 {
		return nil, fmt.Errorf("invalid scan options")
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRawUnavailable, err)
	}
	defer syscall.Close(fd)
	timeout := syscall.NsecToTimeval(options.Timeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRawUnavailable, err)
	}

	jobs := make([]Result, 0, len(hosts)*len(ports))
	for _, host := range hosts {
		if !host.Unmap().Is4() {
			continue // AF_INET raw sockets cannot probe IPv6 targets.
		}
		for _, port := range ports {
			jobs = append(jobs, Result{Host: host.String(), Port: port})
		}
	}
	limiter := newLimiter(ctx, options.Rate)
	defer limiter.Stop()
	results := make([]Result, 0)
	for start := 0; start < len(jobs); start += synBatchSize {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
		end := start + synBatchSize
		if end > len(jobs) {
			end = len(jobs)
		}
		batch := jobs[start:end]
		seen := map[string]struct{}{}
		responses := make(chan Result, len(batch))
		var reader sync.WaitGroup
		reader.Add(1)
		go func() {
			defer reader.Done()
			readSYNResponses(ctx, fd, batch, responses)
		}()
		for index, job := range batch {
			if limiter.Wait(ctx) != nil {
				break
			}
			packet, sourcePort, err := synPacket(job.Host, job.Port, 49152+(index%16384))
			if err != nil {
				continue
			}
			address := netip.MustParseAddr(job.Host).Unmap().As4()
			var destination [4]byte
			copy(destination[:], address[:])
			if err := syscall.Sendto(fd, packet, 0, &syscall.SockaddrInet4{Port: 0, Addr: destination}); err != nil {
				continue
			}
			seen[fmt.Sprintf("%s:%d", job.Host, sourcePort)] = struct{}{}
			_ = seen
		}
		deadline := time.NewTimer(options.Timeout)
	collect:
		for {
			select {
			case result := <-responses:
				results = append(results, result)
			case <-deadline.C:
				break collect
			case <-ctx.Done():
				deadline.Stop()
				reader.Wait()
				return results, ctx.Err()
			}
		}
		deadline.Stop()
		reader.Wait()
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Host == results[j].Host {
			return results[i].Port < results[j].Port
		}
		return results[i].Host < results[j].Host
	})
	return results, nil
}

func readSYNResponses(ctx context.Context, fd int, batch []Result, output chan<- Result) {
	want := map[uint16]Result{}
	for _, job := range batch {
		want[uint16(49152+(len(want)%16384))] = job
	}
	buffer := make([]byte, 4096)
	for {
		if ctx.Err() != nil {
			return
		}
		count, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil || count < 20 {
			continue
		}
		ihl := int(buffer[0]&0x0f) * 4
		if buffer[9] != syscall.IPPROTO_TCP || ihl < 20 || count < ihl+20 {
			continue
		}
		tcp := buffer[ihl : ihl+20]
		if tcp[13]&0x12 != 0x12 { // SYN and ACK
			continue
		}
		sourcePort := binary.BigEndian.Uint16(tcp[0:2])
		if job, found := want[sourcePort]; found {
			select {
			case output <- job:
			case <-ctx.Done():
				return
			}
			delete(want, sourcePort)
		}
		if len(want) == 0 {
			return
		}
	}
}

// synPacket builds an IPv4 TCP SYN packet. Only addresses derived from the
// authorized target are used; the source port is a deterministic bounded value.
func synPacket(host string, port, sourcePort int) ([]byte, uint16, error) {
	address, err := netip.ParseAddr(host)
	if err != nil {
		return nil, 0, err
	}
	unmapped := address.Unmap()
	if !unmapped.Is4() {
		return nil, 0, fmt.Errorf("SYN scan requires IPv4 targets")
	}
	localIP, err := localIPv4(unmapped.String())
	if err != nil {
		return nil, 0, err
	}
	return buildSYNPacket(localIP, unmapped.As4(), port, sourcePort), uint16(sourcePort), nil
}

// buildSYNPacket is the pure packet builder used by synPacket; keeping it free
// of socket state makes checksum construction unit-testable.
func buildSYNPacket(localIP []byte, destination [4]byte, port, sourcePort int) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], uint16(sourcePort))
	binary.BigEndian.PutUint16(tcp[2:4], uint16(port))
	binary.BigEndian.PutUint32(tcp[4:8], 0x5a5a5a5a)
	tcp[12] = 5 << 4
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:16], 8192)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(localIP, destination[:], tcp))
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	binary.BigEndian.PutUint16(ip[4:6], 0x1234)
	ip[8] = 64
	ip[9] = syscall.IPPROTO_TCP
	copy(ip[12:16], localIP)
	copy(ip[16:20], destination[:])
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))
	return append(ip, tcp...)
}

func localIPv4(remote string) ([]byte, error) {
	connection, err := net.Dial("udp", net.JoinHostPort(remote, "9"))
	if err != nil {
		return nil, fmt.Errorf("determine local IP: %w", err)
	}
	defer connection.Close()
	address, ok := connection.LocalAddr().(*net.UDPAddr)
	if !ok || address.IP.To4() == nil {
		return nil, fmt.Errorf("determine local IPv4 address")
	}
	return address.IP.To4(), nil
}

func tcpChecksum(source, destination net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], source.To4())
	copy(pseudo[4:8], destination.To4())
	pseudo[9] = syscall.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	return checksum(pseudo)
}

func checksum(data []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(data); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[index : index+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
