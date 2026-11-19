package scanner

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestScanTCPPairs(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			connection.Close()
		}
	}()
	values, err := ScanTCPPairs(context.Background(), []Result{{Host: "127.0.0.1", Port: port}, {Host: "127.0.0.1", Port: port}}, Options{Workers: 2, Rate: 1000, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].Port != port {
		t.Fatalf("values = %#v", values)
	}
}
