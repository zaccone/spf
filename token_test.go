package spf

import "testing"

func TestTokenSyntaxValidation(t *testing.T) {
	type TokenTestCase struct {
		token     *token
		delimiter rune
		expected  bool
	}

	tests := []TokenTestCase{
		{nil, rune('='), false},
		{
			&token{
				tInclude, qPlus, "matching.com",
			}, rune(':'), true,
		},
		{
			&token{
				tInclude, qPlus, "",
			}, rune(':'), false,
		},
		{
			&token{
				tErr, qErr, "",
			}, rune('='), true,
		},
		{
			&token{
				tAll, qMinus, "matching.com",
			}, rune(':'), true,
		},
		{
			&token{
				tAll, qMinus, "matching.com",
			}, rune('='), false,
		},
	}

	for _, test := range tests {
		token := test.token
		delimiter := test.delimiter
		expected := test.expected

		if checkTokenSyntax(token, delimiter) != expected {
			t.Errorf(
				"Error: For token %v, delimiter %v got result %v, expected %v\n",
				*token, delimiter, !expected, expected)
		}
	}
}

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
