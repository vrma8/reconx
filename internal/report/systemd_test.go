package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSystemdUnitsAreGeneratedForReview(t *testing.T) {
	directory := t.TempDir()
	if err := SystemdUnits(directory, "https://example.test", 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	service, err := os.ReadFile(filepath.Join(directory, "reconx.service"))
	if err != nil {
		t.Fatal(err)
	}
	timer, err := os.ReadFile(filepath.Join(directory, "reconx.timer"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(service), "--i-am-authorized") || !strings.Contains(string(service), "NoNewPrivileges=true") {
		t.Fatalf("service = %s", service)
	}
	if !strings.Contains(string(timer), "OnCalendar=daily") {
		t.Fatalf("timer = %s", timer)
	}
}

func TestSystemdUnitsRejectNewlines(t *testing.T) {
	if err := SystemdUnits(t.TempDir(), "a\nb", time.Hour); err == nil {
		t.Fatal("expected newline target rejection")
	}
}
