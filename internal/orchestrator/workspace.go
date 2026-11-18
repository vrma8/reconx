package orchestrator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Workspace struct { Root string }

var unsafePath = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func NewWorkspace(requested, target string) (*Workspace, error) {
	root := requested
	if root == "" {
		name := unsafePath.ReplaceAllString(strings.Trim(target, "./"), "_")
		if name == "" { name = "target" }
		root = filepath.Join("reconx_workspaces", name+"_"+time.Now().UTC().Format("20060102_150405"))
	}
	workspace := &Workspace{Root: root}
	for _, directory := range []string{"01_osint", "02_subdomains", "03_hosts", "04_ports", "05_services", "06_web", "07_vulns", "08_secrets", "09_report"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o750); err != nil { return nil, err }
	}
	return workspace, nil
}

func (w *Workspace) Path(parts ...string) string { return filepath.Join(append([]string{w.Root}, parts...)...) }

func (w *Workspace) WriteJSON(relative string, value any) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil { return err }
	return w.WriteBytes(relative, append(content, '\n'))
}

func (w *Workspace) WriteText(relative, content string) error { return w.WriteBytes(relative, []byte(content)) }

func (w *Workspace) WriteBytes(relative string, content []byte) error {
	path := w.Path(relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil { return err }
	temporary, err := os.CreateTemp(filepath.Dir(path), ".reconx-*")
	if err != nil { return err }
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if _, err = temporary.Write(content); err != nil { temporary.Close(); return err }
	if err = temporary.Chmod(0o600); err != nil { temporary.Close(); return err }
	if err = temporary.Close(); err != nil { return err }
	if err = os.Rename(temporaryName, path); err != nil { return fmt.Errorf("persist %s: %w", relative, err) }
	return nil
}
