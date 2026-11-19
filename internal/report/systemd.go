package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SystemdUnits writes an optional service/timer pair for scheduled authorized
// scans. Nothing is installed or enabled on the host: the files are artifacts
// for an operator to review, install and enable explicitly.
func SystemdUnits(directory, target string, interval time.Duration) error {
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("systemd unit requires a target")
	}
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		executable = "/usr/local/bin/reconx"
	}
	executable = strings.ReplaceAll(filepath.Clean(executable), "\"", "\\\"")
	safeTarget := strings.ReplaceAll(strings.TrimSpace(target), "\"", "\\\"")
	if strings.ContainsAny(safeTarget, "\r\n") {
		return fmt.Errorf("systemd target must not contain newlines")
	}
	service := fmt.Sprintf(`[Unit]
Description=reconx authorized reconnaissance scan
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=%s "%s" --i-am-authorized
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/
`, executable, safeTarget)
	timer := fmt.Sprintf(`[Unit]
Description=Periodic reconx authorized reconnaissance scan

[Timer]
OnCalendar=%s
Persistent=true
Unit=reconx.service

[Install]
WantedBy=timers.target
`, systemdCalendar(interval))
	if err := write(filepath.Join(directory, "reconx.service"), []byte(service)); err != nil {
		return err
	}
	return write(filepath.Join(directory, "reconx.timer"), []byte(timer))
}

func systemdCalendar(interval time.Duration) string {
	switch {
	case interval <= time.Hour:
		return "hourly"
	case interval <= 24*time.Hour:
		return "daily"
	case interval <= 7*24*time.Hour:
		return "weekly"
	default:
		return "monthly"
	}
}
