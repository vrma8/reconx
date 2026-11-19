package orchestrator

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/vrma8/reconx/internal/model"
)

func TestMergeOSINTPreservesExtendedDNSAndArtifactMetadata(t *testing.T) {
	merged := mergeOSINT(osintOutput{Target: "example.test", DNS: model.DNSRecord{Name: "example.test", A: []string{"192.0.2.1"}}}, osintOutput{
		DNS:   model.DNSRecord{Name: "example.test", SOA: []string{"ns1.example.test hostmaster.example.test 1 2 3 4 5"}, CAA: []string{"0 issue letsencrypt.org"}},
		Dorks: []string{"site:example.test inurl:admin"}, Employees: []osintEmployee{{Name: "Ada", URL: "https://linkedin.example/ada", Source: "public_search_result"}}, TechStack: []string{"WordPress"}, Screenshots: []string{"https://urlscan.io/screenshots/abc.png"},
		SecretIndicators: []osintSecretIndicator{{Source: "github_code_search", Repository: "example/repo", Path: "config.yml", Indicator: "credential-like assignment"}},
	})
	if len(merged.DNS.SOA) != 1 || len(merged.DNS.CAA) != 1 {
		t.Fatalf("extended DNS = %#v", merged.DNS)
	}
	if len(merged.Dorks) != 1 || len(merged.Employees) != 1 || len(merged.TechStack) != 1 || len(merged.Screenshots) != 1 {
		t.Fatalf("artifacts = %#v", merged)
	}
	lines := osintSecretLines(merged.SecretIndicators)
	if len(lines) != 1 || lines[0] != "github_code_search:credential-like assignment:example/repo:config.yml [REDACTED]" {
		t.Fatalf("secret lines = %#v", lines)
	}
}

func TestPhaseSelection(t *testing.T) {
	selected, err := phaseSelection("0-2,4,10", "1,10")
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []int{0, 2, 4} {
		if !selected[phase] {
			t.Fatalf("phase %d should be selected", phase)
		}
	}
	for _, phase := range []int{1, 3, 10} {
		if selected[phase] {
			t.Fatalf("phase %d should not be selected", phase)
		}
	}
}

func TestSubdomainPermutationsAreBounded(t *testing.T) {
	values := subdomainPermutations([]string{"api"}, 5)
	if len(values) != 5 || values[0] != "api-dev" {
		t.Fatalf("values = %#v", values)
	}
}

func TestSubdomainPermutationsCoverPlanAffixesAndNumbers(t *testing.T) {
	values := subdomainPermutations([]string{"portal"}, 1000)
	for _, expected := range []string{"dev-portal", "portal-admin", "portal0", "portal-99", "99-portal"} {
		if !contains(values, expected) {
			t.Fatalf("missing %q from %#v", expected, values)
		}
	}
	labels := subdomainLabels("example.com", []string{"api.example.com", "v2.api.example.com", "example.com"})
	if !contains(labels, "api") || !contains(labels, "v2") {
		t.Fatalf("labels = %#v", labels)
	}
}

func TestMergeSubdomainWordSourcesCombinesStandardAndCustomWords(t *testing.T) {
	directory := t.TempDir()
	standard := filepath.Join(directory, "seclists.txt")
	custom := filepath.Join(directory, "custom.txt")
	if err := os.WriteFile(standard, []byte("www\napi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(custom, []byte("api\nportal\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	words, failures := mergeSubdomainWordSources([]string{custom, standard}, 5)
	if len(failures) != 0 || !contains(words, "www") || !contains(words, "api") || !contains(words, "portal") {
		t.Fatalf("words=%#v failures=%#v", words, failures)
	}
}

func TestPassiveWebAnalysis(t *testing.T) {
	web := []model.WebResult{{FinalURL: "https://api.example.test/openapi.json", Headers: map[string]string{"Server": "cloudflare"}, Body: `{"openapi":"3.0.0","paths":{"/users":{},"/health":{}}}`}}
	if waf := detectWAF(web); len(waf[web[0].FinalURL]) != 1 || waf[web[0].FinalURL][0] != "Cloudflare" {
		t.Fatalf("waf = %#v", waf)
	}
	openAPI := extractOpenAPI(web)
	if len(openAPI) != 1 || len(openAPI[0].Paths) != 2 {
		t.Fatalf("openapi = %#v", openAPI)
	}
}

func TestTakeoverProvider(t *testing.T) {
	for cname, expected := range map[string]string{
		"demo.herokudns.com.": "Heroku", "store.myshopify.com.": "Shopify", "app.fastly.net.": "Fastly",
		"site.github.io.": "GitHub Pages", "demo.azurewebsites.net.": "Azure App Service", "bucket.s3.amazonaws.com.": "Amazon S3 website", "bucket.s3-website.ap-south-1.amazonaws.com.": "Amazon S3 website",
		"name.netlify.app.": "Netlify", "name.bitbucket.io.": "Bitbucket", "repo.travis-ci.org.": "Travis CI",
	} {
		if got := takeoverProvider(cname); got != expected {
			t.Fatalf("provider for %q = %q, want %q", cname, got, expected)
		}
	}
	if got := takeoverProvider("safe.example.com"); got != "" {
		t.Fatalf("provider = %q", got)
	}
	if got := unclaimedMarker("Shopify", "Sorry, this shop is currently unavailable."); got == "" {
		t.Fatal("expected Shopify marker")
	}
}

func TestPhaseSelectionRejectsInvalid(t *testing.T) {
	if _, err := phaseSelection("0-11", ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestEnrichHostsFromOSINTMergesOwnership(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "01_osint"), 0o750); err != nil {
		t.Fatal(err)
	}
	payload := `{"sources":{"network_ownership":{"192.0.2.10":{"ipinfo":{"asn":"AS64496","org":"Example Org","country":"IN"}},"192.0.2.11":{"skipped":"no token"},"192.0.2.12":{"bgp_tools":{"asn":64497}}}}}`
	if err := os.WriteFile(filepath.Join(root, "01_osint", "osint_results.json"), []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	state := model.NewState(model.TargetProfile{})
	engine := &Engine{Workspace: &Workspace{Root: root}, State: state}
	state.AddHost(netip.MustParseAddr("192.0.2.10"), "example.test")
	state.AddHost(netip.MustParseAddr("192.0.2.12"), "example.test")
	engine.enrichHostsFromOSINT()
	hosts := state.HostList()
	if len(hosts) != 2 {
		t.Fatalf("hosts = %#v", hosts)
	}
	byIP := map[string]model.Host{}
	for _, host := range hosts {
		byIP[host.IP] = host
	}
	if byIP["192.0.2.10"].ASN != "AS64496" || byIP["192.0.2.10"].Org != "Example Org" || byIP["192.0.2.10"].Country != "IN" {
		t.Fatalf("enriched host = %#v", byIP["192.0.2.10"])
	}
	if byIP["192.0.2.12"].ASN != "64497" {
		t.Fatalf("bgp fallback = %#v", byIP["192.0.2.12"])
	}
}
