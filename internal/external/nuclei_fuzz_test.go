package external

import (
	"strings"
	"testing"
)

func FuzzParseNucleiJSONL(f *testing.F) {
	f.Add(`{"template-id":"x","info":{"name":"x","severity":"low"}}`)
	f.Add("not-json")
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = ParseNucleiJSONL(strings.NewReader(input))
	})
}
