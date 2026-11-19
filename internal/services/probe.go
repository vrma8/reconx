// Package services performs bounded, read-only protocol probes that enrich the
// basic banner collected by the port scanner. Nothing here authenticates,
// replays credentials, or changes remote state.
package services

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vrma8/reconx/internal/model"
)

var (
	versionPattern = regexp.MustCompile(`(?i)(\d+(?:\.\d+){1,3})`)
	sshPattern     = regexp.MustCompile(`(?i)^SSH-(\d+\.\d+)-(.*)$`)
	rfbPattern     = regexp.MustCompile(`^RFB\s+(\d{3}\.\d{3})`)
)

// Enrich adds protocol-specific metadata and a bounded hex dump to a service
// that was already found open. Failures leave the original service intact and
// record only a short error note.
func Enrich(ctx context.Context, service model.Service, timeout time.Duration) model.Service {
	if service.Transport != "" && service.Transport != "tcp" || timeout <= 0 {
		return service
	}
	if service.Metadata == nil {
		service.Metadata = map[string]string{}
	}
	address := net.JoinHostPort(service.Host, strconv.Itoa(service.Port))
	dialer := net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		service.Metadata["probe_error"] = shortError(err)
		return service
	}
	defer connection.Close()
	deadline := time.Now().Add(timeout)
	_ = connection.SetDeadline(deadline)
	tracked := &recordingConn{Conn: connection}
	switch service.Name {
	case "ssh", "":
		if name, version := sshBanner(tracked); version != "" {
			service.Metadata["ssh_protocol"] = name
			service.Metadata["ssh_software"] = version
			if service.Banner == "" {
				service.Banner = name + " " + version
			}
		}
	case "smtp":
		service.Metadata["ehlo"] = smtpEHLO(tracked)
	case "ftp":
		service.Metadata["features"] = ftpFeatures(tracked)
	case "redis":
		service.Metadata["info"] = redisInfo(tracked)
	case "memcached":
		service.Metadata["stats"] = memcachedStats(tracked)
	case "mysql":
		service.Metadata["server_version"] = mysqlHandshake(tracked)
	case "postgresql":
		service.Metadata["ssl"] = postgresSSL(tracked, service.Host)
	case "mongodb":
		service.Metadata["server_version"] = versionPattern.FindString(readLine(tracked, 512))
	case "vnc":
		service.Metadata["rfb_version"] = rfbPattern.FindString(readLine(tracked, 128))
	case "rdp":
		service.Metadata["tls"] = rdpTLS(ctx, service.Host, service.Port, timeout)
	case "http", "https":
		service.Metadata["http"] = httpHead(tracked, service.Host)
	default:
		service.Metadata["protocol_guess"] = guessProtocol(service.Name, service.Port)
	}
	_ = connection.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	rest := make([]byte, 512)
	if count, err := tracked.Read(rest); err == nil && count > 0 {
		// recordingConn appends the bytes itself; the extra read only drains
		// any immediately available banner tail.
		_ = count
	}
	if len(tracked.data) > 0 {
		service.HexDump = hexLine(tracked.data)
	}
	if version := versionPattern.FindString(service.Banner + " " + strings.Join(values(service.Metadata), " ")); version != "" && service.Version == "" {
		service.Version = version
	}
	return service
}

// recordingConn keeps a bounded prefix of bytes observed on the wire so a hex
// dump is available even when the protocol handler consumed the only response.
type recordingConn struct {
	net.Conn
	data []byte
}

func (connection *recordingConn) Read(buffer []byte) (int, error) {
	count, err := connection.Conn.Read(buffer)
	if count > 0 && len(connection.data) < 512 {
		end := min(count, 512-len(connection.data))
		connection.data = append(connection.data, buffer[:end]...)
	}
	return count, err
}

func values(metadata map[string]string) []string {
	output := make([]string, 0, len(metadata))
	for _, value := range metadata {
		output = append(output, value)
	}
	return output
}

func shortError(err error) string {
	value := err.Error()
	if len(value) > 160 {
		return value[:160]
	}
	return value
}

func readLine(connection net.Conn, limit int) string {
	buffer := make([]byte, 0, limit)
	one := make([]byte, 1)
	for len(buffer) < limit {
		count, err := connection.Read(one)
		if count > 0 {
			if one[0] == '\n' {
				break
			}
			if one[0] != '\r' {
				buffer = append(buffer, one[0])
			}
		}
		if err != nil {
			break
		}
	}
	return strings.TrimSpace(string(buffer))
}

func sshBanner(connection net.Conn) (string, string) {
	line := readLine(connection, 1024)
	match := sshPattern.FindStringSubmatch(line)
	if match == nil {
		return "", ""
	}
	return match[1], match[2]
}

func smtpEHLO(connection net.Conn) string {
	_ = readLine(connection, 1024)
	_, _ = connection.Write([]byte("EHLO reconx.local\r\n"))
	reader := bufio.NewReader(connection)
	lines := make([]string, 0, 16)
	for len(lines) < 20 {
		line, err := reader.ReadString('\n')
		if line == "" && err != nil {
			break
		}
		line = strings.TrimSpace(line)
		lines = append(lines, line)
		if len(line) < 4 || line[3] != '-' {
			break
		}
	}
	return strings.Join(lines, "; ")
}

func ftpFeatures(connection net.Conn) string {
	_ = readLine(connection, 1024)
	_, _ = connection.Write([]byte("FEAT\r\n"))
	reader := bufio.NewReader(connection)
	lines := make([]string, 0, 20)
	for len(lines) < 20 {
		line, err := reader.ReadString('\n')
		if line == "" && err != nil {
			break
		}
		line = strings.TrimSpace(line)
		lines = append(lines, line)
		if strings.HasPrefix(line, "211 ") {
			break
		}
	}
	return strings.Join(lines, "; ")
}

func redisInfo(connection net.Conn) string {
	_, _ = connection.Write([]byte("INFO server\r\n"))
	buffer := make([]byte, 8192)
	count, err := connection.Read(buffer)
	if err != nil {
		return ""
	}
	fields := make([]string, 0, 8)
	for _, line := range strings.Split(string(buffer[:count]), "\r\n") {
		if strings.HasPrefix(line, "redis_version:") || strings.HasPrefix(line, "os:") || strings.HasPrefix(line, "tcp_port:") {
			fields = append(fields, line)
		}
	}
	return strings.Join(fields, "; ")
}

func memcachedStats(connection net.Conn) string {
	_, _ = connection.Write([]byte("stats\r\n"))
	buffer := make([]byte, 8192)
	count, err := connection.Read(buffer)
	if err != nil {
		return ""
	}
	fields := make([]string, 0, 8)
	for _, line := range strings.Split(string(buffer[:count]), "\r\n") {
		if strings.HasPrefix(line, "version ") || strings.HasPrefix(line, "uptime ") || strings.HasPrefix(line, "curr_connections ") {
			fields = append(fields, line)
		}
	}
	return strings.Join(fields, "; ")
}

func mysqlHandshake(connection net.Conn) string {
	header := make([]byte, 4)
	if _, err := readFull(connection, header); err != nil {
		return ""
	}
	payload := make([]byte, 256)
	count, err := readFull(connection, payload)
	if err == nil || count > 0 {
		fields := strings.Split(string(payload[:count]), "\x00")
		if len(fields) > 0 {
			return fields[0]
		}
	}
	return ""
}

func postgresSSL(connection net.Conn, host string) string {
	packet := []byte{0, 0, 0, 8, 4, 210, 22, 47}
	if _, err := connection.Write(packet); err != nil {
		return ""
	}
	answer := make([]byte, 1)
	if _, err := readFull(connection, answer); err != nil {
		return ""
	}
	if answer[0] != 'S' {
		return "ssl_not_supported"
	}
	config := &tls.Config{ServerName: host, InsecureSkipVerify: true} // #nosec G402 -- only certificate metadata is collected.
	tlsConnection := tls.Client(connection, config)
	if err := tlsConnection.Handshake(); err != nil {
		return "ssl_handshake_failed"
	}
	state := tlsConnection.ConnectionState()
	return "supported; " + tlsVersionName(state.Version)
}

func rdpTLS(ctx context.Context, host string, port int, timeout time.Duration) string {
	dialer := net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return ""
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	tlsConnection := tls.Client(connection, &tls.Config{ServerName: host, InsecureSkipVerify: true}) // #nosec G402 -- certificate metadata only.
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return ""
	}
	state := tlsConnection.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return tlsVersionName(state.Version)
	}
	return tlsVersionName(state.Version) + "; " + state.PeerCertificates[0].Subject.CommonName
}

func httpHead(connection net.Conn, host string) string {
	_, _ = fmt.Fprintf(connection, "GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	reader := bufio.NewReader(connection)
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}

func guessProtocol(name string, port int) string {
	switch {
	case name != "unknown" && name != "":
		return name
	case port == 8080 || port == 8000 || port == 8888:
		return "http"
	case port == 8443 || port == 9443:
		return "https"
	default:
		return "unknown"
	}
}

func hexLine(data []byte) string {
	if len(data) > 256 {
		data = data[:256]
	}
	return hex.EncodeToString(data)
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}

func readFull(connection net.Conn, buffer []byte) (int, error) {
	total := 0
	for total < len(buffer) {
		count, err := connection.Read(buffer[total:])
		total += count
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
