package assets

import "testing"

func TestEmbeddedDefaults(t *testing.T) {
	if len(SubdomainWords()) == 0 || len(DirectoryWords()) == 0 {
		t.Fatal("embedded wordlists must not be empty")
	}
}
