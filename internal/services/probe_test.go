package services

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vrma8/reconx/internal/model"
)

func serveOnce(t *testing.T, respond func(net.Conn)) (string, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		respond(connection)
	}()
	return "127.0.0.1", listener.Addr().(*net.TCPAddr).Port
}

func TestEnrichSMTPCapabilities(t *testing.T) {
	host, port := serveOnce(t, func(connection net.Conn) {
		_, _ = connection.Write([]byte("220 mail.local ESMTP ready\r\n"))
		reader := bufio.NewReader(connection)
		_, _ = reader.ReadString('\n')
		_, _ = connection.Write([]byte("250-mail.local\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n"))
	})
	service := Enrich(context.Background(), model.Service{Host: host, Port: port, Transport: "tcp", Name: "smtp"}, 500*time.Millisecond)
	if !strings.Contains(service.Metadata["ehlo"], "STARTTLS") {
		t.Fatalf("EHLO metadata = %#v", service.Metadata)
	}
}

func TestEnrichRedisAndHexDump(t *testing.T) {
	host, port := serveOnce(t, func(connection net.Conn) {
		reader := bufio.NewReader(connection)
		_, _ = reader.ReadString('\n')
		_, _ = connection.Write([]byte("$64\r\nredis_version:7.2.4\r\nos:Linux 6.1\r\ntcp_port:6379\r\n"))
	})
	service := Enrich(context.Background(), model.Service{Host: host, Port: port, Transport: "tcp", Name: "redis"}, 500*time.Millisecond)
	if !strings.Contains(service.Metadata["info"], "redis_version:7.2.4") {
		t.Fatalf("Redis metadata = %#v", service.Metadata)
	}
	if service.HexDump == "" || service.Version != "7.2.4" {
		t.Fatalf("hex dump/version = %q/%q", service.HexDump, service.Version)
	}
}

func TestEnrichGenericBanner(t *testing.T) {
	host, port := serveOnce(t, func(connection net.Conn) {
		_, _ = connection.Write([]byte("RFB 003.008\r\n"))
	})
	service := Enrich(context.Background(), model.Service{Host: host, Port: port, Transport: "tcp", Name: "vnc"}, 500*time.Millisecond)
	if service.Metadata["rfb_version"] == "" || strconv.Itoa(service.Port) == "" {
		t.Fatalf("VNC metadata = %#v", service.Metadata)
	}
}
