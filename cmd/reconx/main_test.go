package main

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeArgumentsAcceptsTargetBeforeFlags(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	var rate int
	var fast bool
	var file string
	flags.IntVar(&rate, "rate", 0, "")
	flags.BoolVar(&fast, "fast", false, "")
	flags.StringVar(&file, "f", "", "")
	arguments := []string{"192.0.2.1", "--rate", "50", "--fast", "-f", "targets.txt", "--json=out.json"}
	want := []string{"--rate", "50", "--fast", "-f", "targets.txt", "--json=out.json", "192.0.2.1"}
	if got := normalizeArguments(flags, arguments); !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeArguments() = %#v, want %#v", got, want)
	}
}

func TestRunRequiresAuthorizationWithTargetFirst(t *testing.T) {
	err := run([]string{"192.0.2.1", "--phases", "0"})
	if err == nil || !strings.Contains(err.Error(), "--i-am-authorized") {
		t.Fatalf("run() error = %v, want authorization error", err)
	}
}

func TestRunExecutesDocumentedTargetFirstInvocation(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "workspace")
	err := run([]string{"127.0.0.1", "--i-am-authorized", "--phases", "0", "--workspace", workspace, "--quiet"})
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(workspace, "target_profile.json")); err != nil {
		t.Fatalf("target profile was not written: %v", err)
	}
}
