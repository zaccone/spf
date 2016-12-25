package spf

import "testing"

func TestTokenSyntaxValidation(t *testing.T) {
	type TokenTestCase struct {
		token     *Token
		delimiter rune
		expected  bool
	}

	tests := []TokenTestCase{
		TokenTestCase{nil, rune('='), false},
		TokenTestCase{
			&Token{
				tInclude, qPlus, "matching.com",
			}, rune(':'), true,
		},
		TokenTestCase{
			&Token{
				tInclude, qPlus, "",
			}, rune(':'), false,
		},
		TokenTestCase{
			&Token{
				tErr, qErr, "",
			}, rune('='), true,
		},
		TokenTestCase{
			&Token{
				tAll, qMinus, "matching.com",
			}, rune(':'), true,
		},
		TokenTestCase{
			&Token{
				tAll, qMinus, "matching.com",
			}, rune('='), false,
		},
		TokenTestCase{
			&Token{
				tRedirect, qEmpty, "matching.com",
			}, rune('='), true,
		},
		TokenTestCase{
			&Token{
				tRedirect, qEmpty, "matching.com",
			}, rune(':'), false,
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
