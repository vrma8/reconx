// Package assets embeds small, safe defaults so the static binary remains
// functional when it is installed outside the source checkout.
package assets

import (
	_ "embed"
	"strings"
)

//go:embed defaults/subdomains.txt
var subdomains string

//go:embed defaults/directories.txt
var directories string

func SubdomainWords() []string { return strings.Fields(subdomains) }
func DirectoryWords() []string { return strings.Fields(directories) }
