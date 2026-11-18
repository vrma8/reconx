package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "reconx.yaml")
	content := "scanning:\n  rate: 42\n  timeout_ms: 750\n  workers: 8\n  retries: 1\nweb:\n  crawl_depth: 2\n  respect_robots: true\napi_keys:\n  shodan: abc\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil { t.Fatal(err) }
	value, err := LoadFile(path, Default())
	if err != nil { t.Fatal(err) }
	if value.Rate != 42 || value.Timeout != 750*time.Millisecond || value.Workers != 8 || value.Retries != 1 || value.CrawlDepth != 2 || !value.RespectRobots || value.ShodanKey != "abc" { t.Fatalf("unexpected config: %#v", value) }
}

func TestValidateRejectsPhase2Bounds(t *testing.T) {
	value := Default()
	value.SubdomainMaxPermutations = 0
	if err := value.Validate(); err == nil { t.Fatal("expected phase 2 bound validation error") }
	value = Default()
	value.TakeoverMaxChecks = -1
	if err := value.Validate(); err == nil { t.Fatal("expected negative takeover cap validation error") }
}

func TestDefaultRunsPlanPhaseOneAndTwoChecks(t *testing.T) {
	value := Default()
	if value.Rate < 1000 || !value.OSINTAXFR || !value.SocialEnum || !value.SubdomainPermutations || !value.CloudAssets || !value.TakeoverVerify || value.TakeoverMaxChecks != 0 {
		t.Fatalf("phase defaults = %#v", value)
	}
}

func TestLoadFileRejectsUnknown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("nope: true\n"), 0o600); err != nil { t.Fatal(err) }
	if _, err := LoadFile(path, Default()); err == nil { t.Fatal("expected an unknown key error") }
}
