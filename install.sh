#!/usr/bin/env sh
# Build reconx. Optional third-party assessment tools are installed only when
# explicitly requested, so normal installation never mutates the OS package set.
set -eu

if ! command -v go >/dev/null 2>&1; then
  echo "Go 1.22+ is required to build reconx." >&2
  exit 1
fi

if [ "${INSTALL_OPTIONAL_TOOLS:-0}" = "1" ]; then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "INSTALL_OPTIONAL_TOOLS=1 requires apt-get on this platform." >&2
    exit 1
  fi
  if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sufficient privilege to install optional tools, or leave INSTALL_OPTIONAL_TOOLS unset." >&2
    exit 1
  fi
  apt-get update
  apt-get install -y nmap masscan nikto sqlmap wpscan smbclient ldap-utils snmp enum4linux
fi

make build
install_dir="${INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$install_dir"
install -m 0755 bin/reconx "$install_dir/reconx"
printf 'Installed reconx to %s/reconx\n' "$install_dir"
printf 'Copy reconx.example.yaml to a private config file if needed.\n'
printf 'Run only with --i-am-authorized against systems you are permitted to assess.\n'
