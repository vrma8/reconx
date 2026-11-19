//go:build linux

package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"syscall"
	"time"
)

const icmpBatchSize = 512

// ICMPSweep performs a bounded raw-socket echo sweep. The kernel builds the IP
// header; only the ICMP echo request is supplied by reconx. No payload beyond
// a short fixed marker is sent.
func ICMPSweep(ctx context.Context, hosts []netip.Addr, options Options) ([]netip.Addr, error) {
	if options.Workers < 1 || options.Rate < 1 || options.Timeout <= 0 {
		return nil, fmt.Errorf("invalid scan options")
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRawUnavailable, err)
	}
	defer syscall.Close(fd)
	timeout := syscall.NsecToTimeval(options.Timeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRawUnavailable, err)
	}
	targets := make([]netip.Addr, 0, len(hosts))
	for _, host := range hosts {
		if host.Unmap().Is4() {
			targets = append(targets, host.Unmap())
		}
	}
	limiter := newLimiter(ctx, options.Rate)
	defer limiter.Stop()
	results := make([]netip.Addr, 0)
	for start := 0; start < len(targets); start += icmpBatchSize {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
		end := start + icmpBatchSize
		if end > len(targets) {
			end = len(targets)
		}
		batch := targets[start:end]
		responses := make(chan netip.Addr, len(batch))
		var reader sync.WaitGroup
		reader.Add(1)
		go func() {
			defer reader.Done()
			readICMPResponses(ctx, fd, batch, responses)
		}()
		for index, target := range batch {
			if limiter.Wait(ctx) != nil {
				break
			}
			packet := buildICMPEcho(index)
			bytes := target.As4()
			if err := syscall.Sendto(fd, packet, 0, &syscall.SockaddrInet4{Port: 0, Addr: bytes}); err != nil {
				continue
			}
		}
		deadline := time.NewTimer(options.Timeout)
	collect:
		for {
			select {
			case target := <-responses:
				results = append(results, target)
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
	sort.Slice(results, func(i, j int) bool { return results[i].Compare(results[j]) < 0 })
	return results, nil
}

func buildICMPEcho(sequence int) []byte {
	packet := make([]byte, 16)
	packet[0] = 8 // echo request
	binary.BigEndian.PutUint16(packet[4:6], 0x5243)
	binary.BigEndian.PutUint16(packet[6:8], uint16(sequence%65536))
	copy(packet[8:], []byte("reconx"))
	binary.BigEndian.PutUint16(packet[2:4], checksum(packet))
	return packet
}

func readICMPResponses(ctx context.Context, fd int, batch []netip.Addr, output chan<- netip.Addr) {
	want := map[uint16]netip.Addr{}
	for index, target := range batch {
		want[uint16(index%65536)] = target
	}
	buffer := make([]byte, 2048)
	for {
		if ctx.Err() != nil || len(want) == 0 {
			return
		}
		count, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil || count < 28 {
			continue
		}
		ihl := int(buffer[0]&0x0f) * 4
		if buffer[9] != syscall.IPPROTO_ICMP || ihl < 20 || count < ihl+8 {
			continue
		}
		icmp := buffer[ihl:]
		if icmp[0] != 0 || binary.BigEndian.Uint16(icmp[4:6]) != 0x5243 {
			continue
		}
		sequence := binary.BigEndian.Uint16(icmp[6:8])
		if target, found := want[sequence]; found {
			select {
			case output <- target:
			case <-ctx.Done():
				return
			}
			delete(want, sequence)
		}
	}
}
