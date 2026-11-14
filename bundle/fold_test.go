package bundle

import "testing"

func TestFoldKeyMatchesEncodingJSONFieldAliases(t *testing.T) {
	for _, aliases := range [][2]string{
		{"platform", "Platform"},
		{"SHA256", "sha256"},
		{"K", "K"}, // Kelvin sign is in the Unicode simple-fold cycle for K.
	} {
		if foldKey(aliases[0]) != foldKey(aliases[1]) {
			t.Errorf("foldKey(%q) != foldKey(%q)", aliases[0], aliases[1])
		}
	}
}
