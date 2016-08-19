package spf

import (
	"net"
	"reflect"
	"testing"
)

var (
	ip   = net.IP{127, 0, 0, 1}
	ipv6 = net.ParseIP("2001:4860:0:2001::68")
)

const stub string = "stub"

func TestNewParserFunction(t *testing.T) {
	p := NewParser(stub, stub, ip, stub)

	if p.Sender != stub {
		t.Error("Sender mismatch, got: ", p.Sender, " expected ", stub)
	}
	if p.Domain != stub {
		t.Error("Domain mismatch, got: ", p.Domain, " expected ", stub)
	}
	if p.Query != stub {
		t.Error("Query mismatch, got: ", p.Query, " expected ", stub)
	}
	if !ip.Equal(p.IP) {
		t.Error("IP mismatch, got: ", p.IP, " expected ", ip)
	}
	if p.Redirect != nil || p.Explanation != nil {
		t.Error("Parser Redirect and Explanation must be nil, ", p)
	}
}

func TestMatchingResult(t *testing.T) {

	type TestCase struct {
		Qualifier tokenType
		Result    SPFResult
	}

	testcases := []TestCase{
		TestCase{qPlus, Pass},
		TestCase{qMinus, Fail},
		TestCase{qQuestionMark, Neutral},
		TestCase{qTilde, Softfail},
	}

	var result SPFResult
	var err error
	for _, testcase := range testcases {
		result, err = matchingResult(testcase.Qualifier)
		if err != nil {
			t.Error("Qualifier ", testcase.Qualifier, " returned error: ",
				err, " (it shouldn't)")
		}
		if result != testcase.Result {
			t.Error("Expected result ", testcase.Result, " got ", result)
		}
	}

	// ensure an error will be returned upon invalid qualifier
	result, err = matchingResult(tAll)
	if err == nil {
		t.Error("matchingResult expected to fail")
	}

	if result != SPFEnd {
		t.Error(`Upon failure matchingResult expected to return result SPFEnd,
                 instead got `, result)
	}
}

func TestTokensSoriting(t *testing.T) {
	//stub := "stub"
	versionToken := &Token{tVersion, qPlus, "spf1"}
	type TestCase struct {
		Tokens      []*Token
		ExpTokens   []*Token
		Redirect    *Token
		Explanation *Token
	}

	testcases := []TestCase{
		TestCase{
			[]*Token{
				versionToken,
				&Token{tAll, qMinus, ""},
			},
			[]*Token{
				versionToken,
				&Token{tAll, qMinus, ""},
			},
			nil,
			nil,
		},
		TestCase{
			[]*Token{
				versionToken,
				&Token{tRedirect, qPlus, "_spf.example.com"},
				&Token{tMX, qTilde, "example.org"},
			},
			[]*Token{
				versionToken,
				&Token{tMX, qTilde, "example.org"},
			},
			&Token{tRedirect, qPlus, "_spf.example.com"},
			nil,
		},
		TestCase{
			[]*Token{
				versionToken,
				&Token{tRedirect, qPlus, "_spf.example.com"},
				&Token{tIP4, qTilde, "192.168.1.2"},
				&Token{tExp, qPlus, "Something went wrong"},
			},
			[]*Token{
				versionToken,
				&Token{tIP4, qTilde, "192.168.1.2"},
			},
			&Token{tRedirect, qPlus, "_spf.example.com"},
			&Token{tExp, qPlus, "Something went wrong"},
		},
		TestCase{
			[]*Token{
				versionToken,
				&Token{tRedirect, qPlus, "_spf.example.com"},
				&Token{tMX, qTilde, "example.org"},
				&Token{tAll, qQuestionMark, ""},
			},
			[]*Token{
				versionToken,
				&Token{tMX, qTilde, "example.org"},
				&Token{tAll, qQuestionMark, ""},
			},
			nil,
			nil,
		},
		TestCase{
			[]*Token{
				versionToken,
				&Token{tRedirect, qPlus, "_spf.example.com"},
				&Token{tMX, qTilde, "example.org"},
				&Token{tAll, qQuestionMark, ""},
				&Token{tExp, qPlus, "You are wrong"},
			},
			[]*Token{
				versionToken,
				&Token{tMX, qTilde, "example.org"},
				&Token{tAll, qQuestionMark, ""},
			},
			nil,
			&Token{tExp, qPlus, "You are wrong"},
		},
	}

	for _, testcase := range testcases {
		p := NewParser(stub, stub, ip, stub)
		p.sortTokens(testcase.Tokens)

		if !reflect.DeepEqual(p.Mechanisms, testcase.ExpTokens) {
			t.Error("Mechanisms mistmatch, got: ", p.Mechanisms,
				" expected: ", testcase.ExpTokens)
		}
		if !reflect.DeepEqual(p.Redirect, testcase.Redirect) {
			t.Error("Expected Redirect to be", testcase.Redirect,
				" got ", p.Redirect)
		}
		if !reflect.DeepEqual(p.Explanation, testcase.Explanation) {
			t.Error("Expected Explanation to be", testcase.Explanation,
				" got ", p.Explanation, " testcase ", p.Explanation, p.Redirect)
		}

	}

}

func TestTokensSoritingHandleErrors(t *testing.T) {
	stub := "stub"
	versionToken := &Token{tVersion, qPlus, "spf1"}
	type TestCase struct {
		Tokens []*Token
	}

	testcases := []TestCase{
		TestCase{
			[]*Token{
				versionToken,
				&Token{tRedirect, qPlus, "_spf.example.com"},
				&Token{tMX, qMinus, "example.org"},
				&Token{tRedirect, qPlus, "_spf.example.com"},
			},
		},
		TestCase{
			[]*Token{
				versionToken,
				&Token{tRedirect, qPlus, "_spf.example.com"},
				&Token{tMX, qMinus, "example.org"},
				&Token{tExp, qPlus, "Explanation"},
				&Token{tExp, qPlus, "Explanation"},
			},
		},
		TestCase{
			[]*Token{
				versionToken,
				&Token{tRedirect, qPlus, "_spf.example.com"},
				&Token{tAll, qMinus, ""},
				&Token{tExp, qPlus, "_spf.example.com"},
				&Token{tRedirect, qPlus, "mydomain.com"},
			},
		},
	}

	for _, testcase := range testcases {
		p := NewParser(stub, stub, ip, stub)
		if err := p.sortTokens(testcase.Tokens); err == nil {
			t.Error("We should have gotten an error, ")
		}
	}
}

/* Test Parse.parse* methods here */

type TokenTestCase struct {
	Input  *Token
	Result SPFResult
	Match  bool
}

// TODO(marek): Add testfunction for tVersion token

func TestParseAll(t *testing.T) {
	p := NewParser(stub, stub, ip, stub)
	testcases := []TokenTestCase{
		TokenTestCase{&Token{tAll, qPlus, ""}, Pass, true},
		TokenTestCase{&Token{tAll, qMinus, ""}, Fail, true},
		TokenTestCase{&Token{tAll, qQuestionMark, ""}, Neutral, true},
		TokenTestCase{&Token{tAll, qTilde, ""}, Softfail, true},
		TokenTestCase{&Token{tAll, tErr, ""}, Permerror, true},
	}

	var match bool
	var result SPFResult

	for _, testcase := range testcases {
		match, result = p.parseAll(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch")
		}
		if testcase.Result != result {
			t.Error("Result mismatch")
		}
	}
}

func TestParseA(t *testing.T) {
	ip := net.IP{172, 18, 0, 2}
	domain := "matching.com"
	p := NewParser(domain, domain, ip, stub)
	testcases := []TokenTestCase{
		TokenTestCase{&Token{tA, qPlus, "positive.matching.com"}, Pass, true},
		TokenTestCase{&Token{tA, qPlus, "positive.matching.com/32"}, Pass, true},
		TokenTestCase{&Token{tA, qPlus, "negative.matching.com"}, Pass, false},
		TokenTestCase{&Token{tA, qPlus, "range.matching.com/16"}, Pass, true},
		TokenTestCase{&Token{tA, qPlus, "range.matching.com/128"}, Permerror, true},
		TokenTestCase{&Token{tA, qPlus, "idontexist"}, None, false},
		TokenTestCase{&Token{tA, qPlus, "#%$%^"}, Permerror, true},
		TokenTestCase{&Token{tA, qPlus, "lb.matching.com"}, Pass, true},
		TokenTestCase{&Token{tA, qMinus, ""}, Fail, true},
		TokenTestCase{&Token{tA, qTilde, ""}, Softfail, true},

		// expect (Permerror, true) results as a result of syntax errors
		TokenTestCase{&Token{tA, qPlus, "range.matching.com/wrongmask"}, Permerror, true},
		TokenTestCase{&Token{tA, qPlus, "range.matching.com/129"}, Permerror, true},
		TokenTestCase{&Token{tA, qPlus, "range.matching.com/-1"}, Permerror, true},

		// expect (Permerror, true) due to wrong netmasks.
		// It's a syntax error to specify a netmask over 32 bits for IPv4 addresses
		TokenTestCase{&Token{tA, qPlus, "negative.matching.com/128"}, Permerror, true},
		TokenTestCase{&Token{tA, qPlus, "positive.matching.com/128"}, Permerror, true},
		TokenTestCase{&Token{tA, qPlus, "positive.matching.com/128"}, Permerror, true},

		// test dual-cidr syntax
		TokenTestCase{&Token{tA, qPlus, "positive.matching.com//128"}, Pass, true},
		TokenTestCase{&Token{tA, qPlus, "positive.matching.com/32/"}, Pass, true},
		TokenTestCase{&Token{tA, qPlus, "positive.matching.com/0/0"}, Pass, true},
		TokenTestCase{&Token{tA, qPlus, "positive.matching.com/33/100"}, Permerror, true},
		TokenTestCase{&Token{tA, qPlus, "positive.matching.com/24/129"}, Permerror, true},
		TokenTestCase{&Token{tA, qPlus, "positive.matching.com/128/32"}, Permerror, true},
	}

	var match bool
	var result SPFResult

	for _, testcase := range testcases {
		match, result = p.parseA(testcase.Input)
		if testcase.Match != match {
			t.Errorf("Match mismatch, expected %s, got %s\n", testcase.Match, match)
		}
		if testcase.Result != result {
			t.Errorf("Result mismatch, expected %s, got %s\n", testcase.Result, result)
		}
	}
}

func TestParseAIpv6(t *testing.T) {

	domain := "matching.com"
	p := NewParser(domain, domain, ipv6, stub)
	testcases := []TokenTestCase{
		TokenTestCase{&Token{tA, qPlus, "positive.matching.com"}, Pass, true},
		TokenTestCase{&Token{tA, qPlus, "positive.matching.com//128"}, Pass, true},
		TokenTestCase{&Token{tA, qPlus, "positive.matching.com//64"}, Pass, true},

		TokenTestCase{&Token{tA, qPlus, "negative.matching.com"}, Pass, false},
		TokenTestCase{&Token{tA, qPlus, "negative.matching.com//64"}, Pass, false},
		TokenTestCase{&Token{tA, qPlus, "positive.matching.com// "}, Permerror, true},
		TokenTestCase{&Token{tA, qPlus, "positive.matching.com/ "}, Permerror, true},
		TokenTestCase{&Token{tA, qPlus, "positive.matching.com/ / "}, Permerror, true},
	}

	var match bool
	var result SPFResult

	for _, testcase := range testcases {
		match, result = p.parseA(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch")
		}
		if testcase.Result != result {
			t.Error("Result mismatch")
		}
	}
}

func TestParseIp4(t *testing.T) {
	p := NewParser(stub, stub, ip, stub)
	testcases := []TokenTestCase{
		TokenTestCase{&Token{tIP4, qPlus, "127.0.0.1"}, Pass, true},
		TokenTestCase{&Token{tIP4, qMinus, "127.0.0.1"}, Fail, true},
		TokenTestCase{&Token{tIP4, qQuestionMark, "127.0.0.1"}, Neutral, true},
		TokenTestCase{&Token{tIP4, qTilde, "127.0.0.1"}, Softfail, true},

		TokenTestCase{&Token{tIP4, qTilde, "127.0.0.0/16"}, Softfail, true},

		TokenTestCase{&Token{tIP4, qTilde, "192.168.1.2"}, Softfail, false},
		TokenTestCase{&Token{tIP4, qMinus, "192.168.1.5/16"}, Fail, false},

		TokenTestCase{&Token{tIP4, qMinus, "random string"}, Permerror, true},
		TokenTestCase{&Token{tIP4, qMinus, "2001:4860:0:2001::68"}, Permerror, true},
		TokenTestCase{&Token{tIP4, qMinus, "2001:4860:0:2001::68/48"}, Permerror, true},
	}

	var match bool
	var result SPFResult

	for _, testcase := range testcases {
		match, result = p.parseIP4(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch")
		}
		if testcase.Result != result {
			t.Error("Result mismatch")
		}
	}
}

func TestParseIp6(t *testing.T) {
	p := NewParser(stub, stub, ipv6, stub)

	testcases := []TokenTestCase{
		TokenTestCase{&Token{tIP6, qPlus, "2001:4860:0:2001::68"}, Pass, true},
		TokenTestCase{&Token{tIP6, qMinus, "2001:4860:0:2001::68"}, Fail, true},
		TokenTestCase{&Token{tIP6, qQuestionMark, "2001:4860:0:2001::68"}, Neutral, true},
		TokenTestCase{&Token{tIP6, qTilde, "2001:4860:0:2001::68"}, Softfail, true},

		TokenTestCase{&Token{tIP6, qTilde, "2001:4860:0:2001::68/64"}, Softfail, true},

		TokenTestCase{&Token{tIP6, qTilde, "::1"}, Softfail, false},
		TokenTestCase{&Token{tIP6, qMinus, "2002::/16"}, Fail, false},

		TokenTestCase{&Token{tIP6, qMinus, "random string"}, Permerror, true},
	}

	var match bool
	var result SPFResult

	for _, testcase := range testcases {
		match, result = p.parseIP6(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch, expected ", testcase.Match, " got ", match)
		}
		if testcase.Result != result {
			t.Error("Result mismatch, expected ", testcase.Result, " got ", result)
		}
	}
}

func TestParseIp6WithIp4(t *testing.T) {
	p := NewParser(stub, stub, ip, stub)

	testcases := []TokenTestCase{
		TokenTestCase{&Token{tIP6, qPlus, "127.0.0.1"}, Permerror, true},
		TokenTestCase{&Token{tIP6, qTilde, "127.0.0.1"}, Permerror, true},
	}

	var match bool
	var result SPFResult

	for _, testcase := range testcases {
		match, result = p.parseIP6(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch, expected ", testcase.Match, " got ", match)
		}
		if testcase.Result != result {
			t.Error("Result mismatch, expected ", testcase.Result, " got ", result)
		}
	}
}

func TestParseMX(t *testing.T) {

	ips := []net.IP{
		net.IP{172, 18, 0, 2},
		net.IP{172, 20, 20, 20},
		net.IP{172, 100, 0, 1},
		net.ParseIP("2001:4860:1:2001::80"),
	}

	domain := "matching.com"
	p := NewParser(domain, domain, net.IP{0, 0, 0, 0}, stub)

	testcases := []TokenTestCase{
		TokenTestCase{&Token{tMX, qPlus, "matching.com"}, Pass, true},
		TokenTestCase{&Token{tMX, qPlus, "matching.com/24"}, Pass, true},
		TokenTestCase{&Token{tMX, qPlus, "matching.com/24/64"}, Pass, true},
		TokenTestCase{&Token{tMX, qPlus, ""}, Pass, true},
		TokenTestCase{&Token{tMX, qMinus, ""}, Fail, true},
		TokenTestCase{&Token{tMX, qPlus, "idontexist"}, None, false},
		// Mind that the domain is matching.NET and we expect Parser
		// to not match results.
		TokenTestCase{&Token{tMX, qPlus, "matching.net"}, Pass, false},
		TokenTestCase{&Token{tMX, qPlus, "matching.net/24"}, Pass, false},
		TokenTestCase{&Token{tMX, qPlus, "matching.net/24/64"}, Pass, false},
	}

	var match bool
	var result SPFResult

	for _, testcase := range testcases {
		for _, ip := range ips {
			p.IP = ip
			match, result = p.parseMX(testcase.Input)
			if testcase.Match != match {
				t.Error("Match mismatch, expected ", testcase.Match, " got ", match)
			}
			if testcase.Result != result {
				t.Error("Result mismatch, expected ", testcase.Result, " got ", result)
			}
		}
	}
}

func TestParseMXNegativeTests(t *testing.T) {

	ip := net.IP{127, 0, 0, 1}
	domain := "matching.com"
	p := NewParser(domain, domain, ip, stub)

	testcases := []TokenTestCase{
		TokenTestCase{&Token{tMX, qPlus, "matching.com"}, Pass, false},
		TokenTestCase{&Token{tMX, qPlus, ""}, Pass, false},
		//TokenTestCase{&Token{tMX, qPlus, "google.com"}, Pass, false},
		TokenTestCase{&Token{tMX, qPlus, "idontexist"}, None, false},
		TokenTestCase{&Token{tMX, qMinus, "matching.com"}, Fail, false},
	}

	var match bool
	var result SPFResult

	for _, testcase := range testcases {
		match, result = p.parseMX(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch, expected ", testcase.Match, " got ", match)
		}
		if testcase.Result != result {
			t.Error("Result mismatch, expected ", testcase.Result, " got ", result)
		}
	}
}

/* parseInclude tests */

func TestParseInclude(t *testing.T) {

	ips := []net.IP{
		net.IP{172, 100, 100, 1},
		net.IP{173, 20, 20, 1},
		net.IP{173, 20, 21, 1},
	}

	domain := "matching.net"
	p := NewParser(domain, domain, net.IP{0, 0, 0, 0}, stub)

	testcases := []TokenTestCase{
		TokenTestCase{&Token{tInclude, qPlus, "_spf.matching.net"}, Pass, true},
		TokenTestCase{&Token{tInclude, qMinus, "_spf.matching.net"}, Fail, true},
		TokenTestCase{&Token{tInclude, qTilde, "_spf.matching.net"}, Softfail, true},
		TokenTestCase{&Token{tInclude, qQuestionMark, "_spf.matching.net"}, Neutral, true},
	}

	var match bool
	var result SPFResult

	for _, testcase := range testcases {
		for _, ip := range ips {
			p.IP = ip
			match, result = p.parseInclude(testcase.Input)
			if testcase.Match != match {
				t.Error("Match mismatch, expected ", testcase.Match, " got ", match)
			}
			if testcase.Result != result {
				t.Error("Result mismatch, expected ", testcase.Result, " got ", result)
			}
		}
	}

}

// TestParseIncludeNegative shows correct behavior of include qualifier.
func TestParseIncludeNegative(t *testing.T) {
	ips := []net.IP{
		// completely random IP addres out of the net segment
		net.IP{80, 81, 82, 83},
		// ip addresses from failing negative.matching.net A records
		net.IP{173, 18, 100, 100},
		net.IP{173, 18, 100, 101},
		net.IP{173, 18, 100, 102},
		net.IP{173, 18, 100, 103},
	}
	domain := "matching.net"
	p := NewParser(domain, domain, ip, stub)

	testcases := []TokenTestCase{
		TokenTestCase{&Token{tInclude, qMinus, "_spf.matching.net"}, None, false},
		TokenTestCase{&Token{tInclude, qPlus, "_spf.matching.net"}, None, false},
		TokenTestCase{&Token{tInclude, qPlus, "_errspf.matching.net"}, None, false},
		TokenTestCase{&Token{tInclude, qPlus, "nospf.matching.net"}, None, false},
		TokenTestCase{&Token{tInclude, qPlus, "idontexist.matching.net"}, None, false},

		// empty input qualifier results in Permerror withour recursive calls
		TokenTestCase{&Token{tInclude, qMinus, ""}, Permerror, true},
	}

	var match bool
	var result SPFResult

	for _, testcase := range testcases {

		for _, ip := range ips {
			p.IP = ip
			match, result = p.parseInclude(testcase.Input)
			if testcase.Match != match {
				t.Error("Match mismatch, expected ", testcase.Match, " got ", match)
			}
			if testcase.Result != result {
				t.Error("Result mismatch, expected ", testcase.Result, " got ", result)
			}
		}

	}

}

// TestParseExists executes tests for exists term.
func TestParseExists(t *testing.T) {

	domain := "matching.com"
	p := NewParser(domain, domain, ip, stub)
	testcases := []TokenTestCase{
		TokenTestCase{&Token{tExists, qPlus, "positive.matching.net"}, Pass, true},
		TokenTestCase{&Token{tExists, qMinus, "positive.matching.net"}, Fail, true},
		TokenTestCase{&Token{tExists, qMinus, "idontexist.matching.net"}, Fail, false},
		TokenTestCase{&Token{tExists, qMinus, "idontexist.%{d}"}, Fail, false},
		TokenTestCase{&Token{tExists, qTilde, "positive.%{d}"}, Softfail, true},
		TokenTestCase{&Token{tExists, qTilde, "positive.%{d}"}, Softfail, true},
		TokenTestCase{&Token{tExists, qTilde, ""}, Permerror, true},
		TokenTestCase{&Token{tExists, qTilde, "invalidsyntax%{}"}, Permerror, true},
	}

	for _, testcase := range testcases {
		match, result := p.parseExists(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch, expected ", testcase.Match, " got ", match)
		}
		if testcase.Result != result {
			t.Error("Result mismatch, expected ", testcase.Result, " got ", result)
		}
	}
}

type ParseTestCase struct {
	Query  string
	IP     net.IP
	Result SPFResult
}

// TestParse tests whole Parser.Parse() method
func TestParse(t *testing.T) {

	domain := "matching.com"

	ParseTestCases := []ParseTestCase{
		ParseTestCase{"v=spf1 -all", net.IP{127, 0, 0, 1}, Fail},
		ParseTestCase{"v=spf1 mx -all", net.IP{172, 20, 20, 20}, Pass},
		ParseTestCase{"v=spf1 ?mx -all", net.IP{172, 20, 20, 20}, Neutral},
		ParseTestCase{"v=spf1 ~mx -all", net.IP{172, 20, 20, 20}, Softfail},
		ParseTestCase{"v=spf1 a -mx -all", net.IP{172, 18, 0, 2}, Pass},
		ParseTestCase{"v=spf1 -mx a -all", net.IP{172, 18, 0, 2}, Fail},
		ParseTestCase{"v=spf1 +mx:matching.net -a -all", net.IP{173, 18, 0, 2}, Pass},
		ParseTestCase{"v=spf1 +mx:matching.net -a -all", net.IP{172, 17, 0, 2}, Fail},
		ParseTestCase{"v=spf1 a:matching.net -all", net.IP{173, 18, 0, 2}, Pass},
		ParseTestCase{"v=spf1 +ip4:128.14.15.16 -all", net.IP{128, 14, 15, 16}, Pass},
		ParseTestCase{"v=spf1 ~ip6:2001:56::2 -all", net.ParseIP("2001:56::2"), Softfail},
		// Test will return SPFResult Fail as 172.20.20.1 does not result
		// positively for domain _spf.matching.net
		ParseTestCase{"v=spf1 ip4:127.0.0.1 +include:_spf.matching.net -all", net.IP{172, 20, 20, 1}, Fail},
		// Test will return SPFResult Pass as 172.100.100.1 is withing
		// positive.matching.net A records, that are marked as +a:
		ParseTestCase{"v=spf1 ip4:127.0.0.1 +include:_spf.matching.net -all", net.IP{172, 100, 100, 1}, Pass},
		// Test for syntax errors (include must have nonempty domain parameter)
		ParseTestCase{"v=spf1 ip4:127.0.0.1 +include -all", net.IP{172, 100, 100, 1}, Permerror},
		ParseTestCase{"v=spf1 ip4:127.0.0.1 ?include -all", net.IP{172, 100, 100, 1}, Permerror},
		// Include didn't match domain:yyz and underneath returned Temperror,
		// however parent Parse() exection path marked the result as not
		// matching and proceeded to next term
		ParseTestCase{"v=spf1 +include:yyz -all", net.IP{172, 100, 100, 1}, Fail},
		ParseTestCase{"v=spf1 ?exists:lb.%{d} -all", ip, Neutral},
		// domain is set to matching.com, macro >>d1r<< will reverse domain to
		// >>com.matching<< and trim to first part counting from right,
		// effectively returning >>matching<<, which we later concatenate with
		// the >>.com<< suffix. This test should give same matching result as
		// the test above, as effectively the host to be queried is identical.
		ParseTestCase{"v=spf1 ?exists:lb.%{d1r}.com -all", ip, Neutral},
	}

	for _, testcase := range ParseTestCases {
		p := NewParser(domain, domain, testcase.IP, testcase.Query)

		result, _, err := p.Parse()
		if err != nil {
			t.Error("Unexpected error while parsing: ", err)
		} else if result != testcase.Result {
			t.Error("Expected ", testcase.Result, " got ", result, " instead.")
		}
	}
}

// TestParseRedirect tests whole parsing behavior with a special testing of
// redirect modifier
func TestHandleRedirect(t *testing.T) {

	const domain = "matching.com"
	ParseTestCases := []ParseTestCase{
		ParseTestCase{"v=spf1 -all redirect=_spf.matching.net", net.IP{172, 100, 100, 1}, Fail},
		ParseTestCase{"v=spf1 redirect=_spf.matching.net -all", net.IP{172, 100, 100, 1}, Fail},
		ParseTestCase{"v=spf1 redirect=_spf.matching.net", net.IP{172, 100, 100, 1}, Pass},
		ParseTestCase{"v=spf1 redirect=malformed", net.IP{172, 100, 100, 1}, Permerror},
		ParseTestCase{"v=spf1 redirect=_spf.matching.net", net.IP{127, 0, 0, 1}, Fail},
		ParseTestCase{"v=spf1 redirect=nospf.matching.net", net.IP{127, 0, 0, 1}, Permerror},
		ParseTestCase{"v=spf1 +ip4:127.0.0.1 redirect=nospf.matching.net", net.IP{127, 0, 0, 1}, Pass},
		ParseTestCase{"v=spf1 -ip4:127.0.0.1 redirect=nospf.matching.net", net.IP{127, 0, 0, 1}, Fail},
		ParseTestCase{"v=spf1 +include:_spf.matching.net redirect=_spf.matching.net", net.IP{127, 0, 0, 1}, Fail},
		ParseTestCase{"v=spf1 ~include:_spf.matching.net redirect=_spf.matching.net", net.IP{172, 100, 100, 1}, Softfail},
		// Ensure recursive redirects work
		ParseTestCase{"v=spf1 redirect=redirect.matching.com", net.IP{172, 18, 0, 2}, Pass},
		ParseTestCase{"v=spf1 redirect=redirect.matching.com", net.IP{127, 0, 0, 1}, Fail},
	}

	for _, testcase := range ParseTestCases {
		p := NewParser(domain, domain, testcase.IP, testcase.Query)
		result, _, err := p.Parse()
		if err != nil {
			t.Error("Unexpected error while parsing: ", err)
		} else if result != testcase.Result {
			t.Error("Expected ", testcase.Result, " got ", result, " instead.")
		}
	}
}
