package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// DNSSECResult is a bounded, explainable view of one DNSSEC-aware resolver
// exchange. It records signals; it does not claim to validate the whole chain.
type DNSSECResult struct {
	Name      string   `json:"name"`
	Resolver  string   `json:"resolver,omitempty"`
	AD        bool     `json:"authenticated_data"`
	DNSKEY    int      `json:"dnskey_records"`
	RRSIG     int      `json:"rrsig_records"`
	Signed    bool     `json:"signed"`
	Notes     []string `json:"notes,omitempty"`
	ErrorCode string   `json:"error,omitempty"`
}

// CheckDNSSEC sends one DNSKEY query with the DO bit set to the first resolver
// found in resolv.conf. It is read-only and bounded by ctx/timeout.
func CheckDNSSEC(ctx context.Context, name string, timeout time.Duration) DNSSECResult {
	result := DNSSECResult{Name: strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")}
	if result.Name == "" || timeout <= 0 {
		result.ErrorCode = "invalid input"
		return result
	}
	resolver := firstResolver()
	if resolver == "" {
		result.ErrorCode = "no DNS resolver configured"
		return result
	}
	result.Resolver = resolver
	query, err := dnskeyQuery(result.Name)
	if err != nil {
		result.ErrorCode = err.Error()
		return result
	}
	address, err := net.ResolveUDPAddr("udp", net.JoinHostPort(resolver, "53"))
	if err != nil {
		result.ErrorCode = "resolve resolver: " + err.Error()
		return result
	}
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := net.DialUDP("udp", nil, address)
	if err != nil {
		result.ErrorCode = "dial resolver: " + err.Error()
		return result
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	if _, err := connection.Write(query); err != nil {
		result.ErrorCode = "write query: " + err.Error()
		return result
	}
	response := make([]byte, 4096)
	count, _, err := connection.ReadFromUDP(response)
	if err != nil {
		if deadline.Err() != nil {
			result.ErrorCode = "resolver timeout"
		} else {
			result.ErrorCode = "read response: " + err.Error()
		}
		return result
	}
	result.AD, result.DNSKEY, result.RRSIG, err = parseDNSSECResponse(response[:count])
	if err != nil {
		result.ErrorCode = err.Error()
		return result
	}
	result.Signed = result.AD || result.RRSIG > 0 || result.DNSKEY > 0
	if !result.Signed {
		result.Notes = append(result.Notes, "no DNSSEC records or authenticated-data bit observed")
	}
	return result
}

func firstResolver() string {
	content, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			return strings.TrimSpace(fields[1])
		}
	}
	return ""
}

func dnskeyQuery(name string) ([]byte, error) {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:2], uint16(time.Now().UnixNano()))
	binary.BigEndian.PutUint16(packet[2:4], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[10:12], 1) // OPT record
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS label in %q", name)
		}
		packet = append(packet, byte(len(label)))
		packet = append(packet, []byte(label)...)
	}
	packet = append(packet, 0)
	question := []byte{0, 48, 0, 1} // DNSKEY, IN
	packet = append(packet, question...)
	opt := []byte{0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0} // OPT with DO bit set
	return append(packet, opt...), nil
}

func parseDNSSECResponse(response []byte) (bool, int, int, error) {
	if len(response) < 12 {
		return false, 0, 0, fmt.Errorf("short DNS response")
	}
	ad := binary.BigEndian.Uint16(response[2:4])&0x0020 != 0
	questions := int(binary.BigEndian.Uint16(response[4:6]))
	answers := int(binary.BigEndian.Uint16(response[6:8]))
	offset := 12
	for i := 0; i < questions; i++ {
		var err error
		offset, err = skipDNSName(response, offset)
		if err != nil {
			return false, 0, 0, err
		}
		if offset+4 > len(response) {
			return false, 0, 0, fmt.Errorf("truncated DNS question")
		}
		offset += 4
	}
	dnskeys, rrsigs := 0, 0
	for i := 0; i < answers; i++ {
		var err error
		offset, err = skipDNSName(response, offset)
		if err != nil {
			return false, 0, 0, err
		}
		if offset+10 > len(response) {
			return false, 0, 0, fmt.Errorf("truncated DNS record")
		}
		recordType := binary.BigEndian.Uint16(response[offset : offset+2])
		length := int(binary.BigEndian.Uint16(response[offset+8 : offset+10]))
		offset += 10
		if length < 0 || offset+length > len(response) {
			return false, 0, 0, fmt.Errorf("invalid DNS record length")
		}
		switch recordType {
		case 48:
			dnskeys++
		case 46:
			rrsigs++
		}
		offset += length
	}
	return ad, dnskeys, rrsigs, nil
}

func skipDNSName(response []byte, offset int) (int, error) {
	limit := 0
	for {
		if offset >= len(response) || limit > 128 {
			return 0, fmt.Errorf("invalid DNS name")
		}
		length := int(response[offset])
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(response) {
				return 0, fmt.Errorf("truncated DNS pointer")
			}
			return offset + 2, nil
		}
		offset++
		if length == 0 {
			return offset, nil
		}
		if offset+length > len(response) {
			return 0, fmt.Errorf("truncated DNS label")
		}
		offset += length
		limit++
	}
}
