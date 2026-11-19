package scanner

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestScanTCPLocalListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	accepted := make(chan struct{})
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			close(accepted)
			connection.Close()
		}
	}()
	result, err := ScanTCP(context.Background(), []netip.Addr{netip.MustParseAddr("127.0.0.1")}, []int{port}, Options{Workers: 2, Rate: 10000, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].Port != port {
		t.Fatalf("results = %#v, want open port %d", result, port)
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("listener did not receive connection")
	}
}

func TestRetryDelayIsExponential(t *testing.T) {
	if retryDelay(0) != 25*time.Millisecond || retryDelay(2) != 100*time.Millisecond {
		t.Fatalf("unexpected retry delays")
	}
}

func TestPorts(t *testing.T) {
	if got := len(Ports(true, false)); got != 65535 {
		t.Fatalf("full port count = %d", got)
	}
	if got := len(Ports(false, false)); got != 1000 {
		t.Fatalf("default port count = %d", got)
	}
	if got := len(Ports(false, true)); got == 0 || got > 100 {
		t.Fatalf("fast port count = %d", got)
	}
	if got := len(TopUDPPorts); got != 100 {
		t.Fatalf("UDP port count = %d", got)
	}
}
