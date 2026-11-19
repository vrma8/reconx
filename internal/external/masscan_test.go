package external

import (
	"strings"
	"testing"
)

func TestParseMasscanList(t *testing.T) {
	input := "# masscan\nopen tcp 443 192.0.2.1 0\nopen tcp 80 192.0.2.1 0\nopen udp 53 192.0.2.1 0\nopen tcp 80 192.0.2.1 0\n"
	values, err := ParseMasscanList(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 || values[0].Port != 80 || values[1].Port != 443 {
		t.Fatalf("values = %#v", values)
	}
}
