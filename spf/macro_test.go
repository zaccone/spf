package spf

import (
	"net"
	"testing"
)

const (
	domain = "matching.com"
	sender = "sender@domain.com"
)

var (
	ip4   = net.IP{10, 11, 12, 13}
	ip6   = net.ParseIP("2001:68::1")
	token = &Token{Mechanism: tExp, Qualifier: qMinus, Value: ""}
)

type MacroTest struct {
	Input  string
	Output string
}

func TestMacroIteration(t *testing.T) {
	testCases := []*MacroTest{
		&MacroTest{"matching.com", "matching.com"},
		&MacroTest{"%%matching.com", "%matching.com"},
		&MacroTest{"%%matching%_%%.com", "%matching %.com"},
		&MacroTest{"matching%-.com", "matching%20.com"},
		&MacroTest{"%%%%%_%-", "%% %20"},
		&MacroTest{"Please email to %{s} end",
			"Please email to sender@domain.com end"},
		&MacroTest{"Please email to %{l} end",
			"Please email to sender end"},
		&MacroTest{"Please email to %{o} end",
			"Please email to domain.com end"},
		&MacroTest{"Domain %{d} end",
			"Domain matching.com end"},
		&MacroTest{"Address IP %{i} end",
			"Address IP 10.11.12.13 end"},
		&MacroTest{"Address IP %{i1} end",
			"Address IP 13 end"},
		&MacroTest{"Address IP %{i100} end",
			"Address IP 10.11.12.13 end"},
		&MacroTest{"Address IP %{ir} end",
			"Address IP 13.12.11.10 end"},
		&MacroTest{"Address IP %{i2r} end",
			"Address IP 11.10 end"},
		&MacroTest{"Address IP %{i500r} end",
			"Address IP 13.12.11.10 end"},
	}

	parser := NewParser(sender, domain, ip4, stub, config)

	for _, test := range testCases {
		token.Value = test.Input
		result, err := ParseMacroToken(parser, token)
		if err != nil {
			t.Errorf("Macro %s evaluation failed due to returned error: %v\n",
				test.Input, err)
		}
		if result != test.Output {
			t.Errorf("Macro '%s', evaluation failed, got: '%s',\nexpected '%s'\n",
				test.Input, result, test.Output)
		}
	}
}

// TestMacroExpansionRFCExamples will execute examples from RFC 7208, section
// 7.4
func TestMacroExpansionRFCExamples(t *testing.T) {
	testCases := []*MacroTest{
		&MacroTest{"", ""},
		&MacroTest{"%{s}", "strong-bad@email.example.com"},
		&MacroTest{"%{o}", "email.example.com"},
		&MacroTest{"%{d}", "email.example.com"},
		&MacroTest{"%{d4}", "email.example.com"},
		&MacroTest{"%{d3}", "email.example.com"},
		&MacroTest{"%{d2}", "example.com"},
		&MacroTest{"%{d1}", "com"},
		&MacroTest{"%{dr}", "com.example.email"},
		&MacroTest{"%{d2r}", "example.email"},
		&MacroTest{"%{l}", "strong-bad"},
		&MacroTest{"%{l-}", "strong.bad"},
		&MacroTest{"%{lr}", "strong-bad"},
		&MacroTest{"%{lr-}", "bad.strong"},
		&MacroTest{"%{l1r-}", "strong"},
		&MacroTest{"%{ir}.%{v}._spf.%{d2}",
			"3.2.0.192.in-addr._spf.example.com"},
		&MacroTest{"%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com"},
		&MacroTest{"%{lr-}.lp.%{ir}.%{v}._spf.%{d2}",
			"bad.strong.lp.3.2.0.192.in-addr._spf.example.com"},
		&MacroTest{"%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}",
			"3.2.0.192.in-addr.strong.lp._spf.example.com"},
		&MacroTest{"%{d2}.trusted-domains.example.net",
			"example.com.trusted-domains.example.net"},
	}

	parser := NewParser("strong-bad@email.example.com",
		"email.example.com", net.IP{192, 0, 2, 3}, stub, config)

	for _, test := range testCases {

		token.Value = test.Input
		result, err := ParseMacroToken(parser, token)
		if err != nil {
			t.Errorf("Macro %s evaluation failed due to returned error: %v\n",
				test.Input, err)
		}
		if result != test.Output {
			t.Errorf("Macro '%s', evaluation failed, got: '%s',\nexpected '%s'\n",
				test.Input, result, test.Output)
		}
	}
}

// TODO(zaccone): Fill epected error messages and compare with those returned.
func TestParsingErrors(t *testing.T) {
	testcases := []*MacroTest{
		&MacroTest{"%", ""},
		&MacroTest{"%{?", ""},
		&MacroTest{"%}", ""},
		&MacroTest{"%a", ""},
		&MacroTest{"%", ""},
		&MacroTest{"%{}", ""},
		&MacroTest{"%{", ""},
		&MacroTest{"%{234", ""},
		&MacroTest{"%{2a3}", ""},
		&MacroTest{"%{i2", ""},
		&MacroTest{"%{s2a3}", ""},
		&MacroTest{"%{s2i3}", ""},
		&MacroTest{"%{s2ir-3}", ""},
		&MacroTest{"%{l2a3}", ""},
		&MacroTest{"%{i2a3}", ""},
		&MacroTest{"%{o2a3}", ""},
		&MacroTest{"%{d2a3}", ""},
		&MacroTest{"%{i-2}", ""},
	}

	parser := NewParser(sender, domain, ip4, stub, config)

	for _, test := range testcases {

		token.Value = test.Input
		result, err := ParseMacroToken(parser, token)

		if result != "" {
			t.Errorf("For input '%s' expected empty result, got '%s' instead\n",
				test.Input, result)
		}

		if err == nil {
			t.Errorf("For input '%s', expected non-empty err, got nil instead and result '%s'\n",
				test.Input, result)
		}
	}
}
