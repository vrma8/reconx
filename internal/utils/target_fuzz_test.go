package utils

import "testing"

func FuzzParseTarget(f *testing.F) {
	for _, seed := range []string{"example.com", "https://example.com/a", "192.0.2.1", "192.0.2.0/24", "", "[::1]", "\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = ParseTarget(input)
	})
}
