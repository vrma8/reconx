package enrich

import (
	"strings"
	"testing"
)

func TestParseNmapXML(t *testing.T) {
	document := `<?xml version="1.0"?><nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port portid="22" protocol="tcp"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2" method="probed"/></port><port portid="80" protocol="tcp"><state state="closed"/><service name="http"/></port></ports><os><osclass vendor="Linux" family="Linux" osgen="5.X" accuracy="98"><cpe>cpe:/o:linux:linux_kernel:5</cpe></osclass></os></host></nmaprun>`
	services, systems, err := ParseNmapXML(strings.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 1 || services[0].Port != 22 || services[0].Version != "9.2" || services[0].Metadata["product"] != "OpenSSH" {
		t.Fatalf("services = %#v", services)
	}
	if !strings.Contains(systems["192.0.2.10"], "Linux") {
		t.Fatalf("OS map = %#v", systems)
	}
}
