package spf

import "testing"

func TestTokenString(t *testing.T) {
	types := []tokenType{tVersion, tAll, tIP4, tIP6, tMX, tPTR, tInclude,
		tRedirect, tExists, tExp}
	strs := []string{
		"v", "all", "ip4", "ip6", "mx", "ptr", "include", "redirect", "exists",
		"exp",
	}

	if len(types) != len(strs) {
		t.Errorf("Lengths for types and strs unequal - %d and %d",
			len(types), len(strs))
	}

	for idx := 0; idx < len(types); idx++ {
		if types[idx].String() != strs[idx] {
			t.Errorf("Error while running token.String. Got %q, expected %q",
				types[idx].String(), strs[idx])
		}
	}
}
