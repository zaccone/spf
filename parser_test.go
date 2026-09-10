package spf

import (
	"net"
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

const (
	stub string = "stub"
)

var (
	ip   = net.IP{127, 0, 0, 1}
	ipv6 = net.ParseIP("2001:4860:0:2001::68")
)

/* helper functions */

/********************/

func TestNewParserFunction(t *testing.T) {
	_, testResolver := newTestDNS(t)
	p := newParser(stub, stub, ip, stub, testResolver)

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
		Result    Result
	}

	testcases := []TestCase{
		{qPlus, Pass},
		{qMinus, Fail},
		{qQuestionMark, Neutral},
		{qTilde, Softfail},
	}

	var result Result
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

	if result != internalError {
		t.Error(`Upon failure matchingResult expected to return result SPFEnd,
                 instead got `, result)
	}
}

func TestTokensSoriting(t *testing.T) {
	_, testResolver := newTestDNS(t)
	//stub := "stub"
	versionToken := &token{tVersion, qPlus, "spf1"}
	type TestCase struct {
		Tokens      []*token
		ExpTokens   []*token
		Redirect    *token
		Explanation *token
	}

	testcases := []TestCase{
		{
			[]*token{
				versionToken,
				{tAll, qMinus, ""},
			},
			[]*token{
				versionToken,
				{tAll, qMinus, ""},
			},
			nil,
			nil,
		},
		{
			[]*token{
				versionToken,
				{tRedirect, qPlus, "_spf.example.com"},
				{tMX, qTilde, "example.org"},
			},
			[]*token{
				versionToken,
				{tMX, qTilde, "example.org"},
			},
			&token{tRedirect, qPlus, "_spf.example.com"},
			nil,
		},
		{
			[]*token{
				versionToken,
				{tRedirect, qPlus, "_spf.example.com"},
				{tIP4, qTilde, "192.168.1.2"},
				{tExp, qPlus, "Something went wrong"},
			},
			[]*token{
				versionToken,
				{tIP4, qTilde, "192.168.1.2"},
			},
			&token{tRedirect, qPlus, "_spf.example.com"},
			&token{tExp, qPlus, "Something went wrong"},
		},
		{
			[]*token{
				versionToken,
				{tRedirect, qPlus, "_spf.example.com"},
				{tMX, qTilde, "example.org"},
				{tAll, qQuestionMark, ""},
			},
			[]*token{
				versionToken,
				{tMX, qTilde, "example.org"},
				{tAll, qQuestionMark, ""},
			},
			nil,
			nil,
		},
		{
			[]*token{
				versionToken,
				{tRedirect, qPlus, "_spf.example.com"},
				{tMX, qTilde, "example.org"},
				{tAll, qQuestionMark, ""},
				{tExp, qPlus, "You are wrong"},
			},
			[]*token{
				versionToken,
				{tMX, qTilde, "example.org"},
				{tAll, qQuestionMark, ""},
			},
			nil,
			&token{tExp, qPlus, "You are wrong"},
		},
	}

	for _, testcase := range testcases {
		p := newParser(stub, stub, ip, stub, testResolver)
		_ = p.sortTokens(testcase.Tokens)

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
	_, testResolver := newTestDNS(t)
	versionToken := &token{tVersion, qPlus, "spf1"}
	type TestCase struct {
		Tokens []*token
	}

	testcases := []TestCase{
		{
			[]*token{
				versionToken,
				{tRedirect, qPlus, "_spf.example.com"},
				{tMX, qMinus, "example.org"},
				{tRedirect, qPlus, "_spf.example.com"},
			},
		},
		{
			[]*token{
				versionToken,
				{tRedirect, qPlus, "_spf.example.com"},
				{tMX, qMinus, "example.org"},
				{tExp, qPlus, "Explanation"},
				{tExp, qPlus, "Explanation"},
			},
		},
		{
			[]*token{
				versionToken,
				{tRedirect, qPlus, "_spf.example.com"},
				{tAll, qMinus, ""},
				{tExp, qPlus, "_spf.example.com"},
				{tRedirect, qPlus, "mydomain.com"},
			},
		},
	}

	for _, testcase := range testcases {
		p := newParser(stub, stub, ip, stub, testResolver)
		if err := p.sortTokens(testcase.Tokens); err == nil {
			t.Error("We should have gotten an error, ")
		}
	}
}

/* Test Parse.parse* methods here */

type TokenTestCase struct {
	Input  *token
	Result Result
	Match  bool
}

// TODO(marek): Add testfunction for tVersion token

func TestParseAll(t *testing.T) {
	_, testResolver := newTestDNS(t)
	p := newParser(stub, stub, ip, stub, testResolver)
	testcases := []TokenTestCase{
		{&token{tAll, qPlus, ""}, Pass, true},
		{&token{tAll, qMinus, ""}, Fail, true},
		{&token{tAll, qQuestionMark, ""}, Neutral, true},
		{&token{tAll, qTilde, ""}, Softfail, true},
		{&token{tAll, tErr, ""}, Permerror, true},
	}

	var match bool
	var result Result

	for _, testcase := range testcases {
		match, result, _ = p.parseAll(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch")
		}
		if testcase.Result != result {
			t.Error("Result mismatch")
		}
	}
}

func TestParseA(t *testing.T) {
	mux, testResolver := newTestDNS(t)
	mux.HandleFunc("matching.com.", zone(t, map[uint16][]string{
		dns.TypeA: {
			"matching.com. 0 IN A 172.20.21.1",
			"matching.com. 0 IN A 172.18.0.2",
			"matching.com. 0 IN A 172.20.20.1",
		},
		dns.TypeAAAA: {
			"matching.com. 0 IN AAAA 2001:4860:0:2001::68",
		},
	}))

	mux.HandleFunc("positive.matching.com.", zone(t, map[uint16][]string{
		dns.TypeA: {
			"positive.matching.com. 0 IN A 172.20.21.1",
			"positive.matching.com. 0 IN A 172.18.0.2",
			"positive.matching.com. 0 IN A 172.20.20.1",
		},
		dns.TypeAAAA: {
			"positive.matching.com. 0 IN AAAA 2001:4860:0:2001::68",
		},
	}))

	mux.HandleFunc("negative.matching.com.", zone(t, map[uint16][]string{
		dns.TypeA: {
			"negative.matching.com. 0 IN A 172.20.21.1",
		},
	}))

	mux.HandleFunc("range.matching.com.", zone(t, map[uint16][]string{
		dns.TypeA: {
			"range.matching.com. 0 IN A 172.18.0.2",
		},
	}))

	mux.HandleFunc("lb.matching.com.", zone(t, map[uint16][]string{
		dns.TypeA: {
			"lb.matching.com. 0 IN A 172.18.0.2",
		},
	}))

	p := newParser(domain, "matching.com", net.IP{172, 18, 0, 2}, stub, testResolver)
	testcases := []TokenTestCase{
		{&token{tA, qPlus, "positive.matching.com"}, Pass, true},
		{&token{tA, qPlus, "positive.matching.com/32"}, Pass, true},
		{&token{tA, qPlus, "negative.matching.com"}, Pass, false},
		{&token{tA, qPlus, "range.matching.com/16"}, Pass, true},
		{&token{tA, qPlus, "range.matching.com/128"}, Permerror, true},
		{&token{tA, qPlus, "idontexist"}, Pass, false},
		{&token{tA, qPlus, "#%$%^"}, Permerror, true},
		{&token{tA, qPlus, "lb.matching.com"}, Pass, true},
		{&token{tA, qMinus, ""}, Fail, true},
		{&token{tA, qTilde, ""}, Softfail, true},

		// expect (Permerror, true) results as a result of syntax errors
		{&token{tA, qPlus, "range.matching.com/wrongmask"}, Permerror, true},
		{&token{tA, qPlus, "range.matching.com/129"}, Permerror, true},
		{&token{tA, qPlus, "range.matching.com/-1"}, Permerror, true},

		// expect (Permerror, true) due to wrong netmasks.
		// It's a syntax error to specify a netmask over 32 bits for IPv4 addresses
		{&token{tA, qPlus, "negative.matching.com/128"}, Permerror, true},
		{&token{tA, qPlus, "positive.matching.com/128"}, Permerror, true},
		{&token{tA, qPlus, "positive.matching.com/128"}, Permerror, true},

		// test dual-cidr syntax
		{&token{tA, qPlus, "positive.matching.com//128"}, Pass, true},
		{&token{tA, qPlus, "positive.matching.com/32/"}, Pass, true},
		{&token{tA, qPlus, "positive.matching.com/0/0"}, Pass, true},
		{&token{tA, qPlus, "positive.matching.com/24/24"}, Pass, true},
		{&token{tA, qPlus, "positive.matching.com/33/100"}, Permerror, true},
		{&token{tA, qPlus, "positive.matching.com/24/129"}, Permerror, true},
		{&token{tA, qPlus, "positive.matching.com/128/32"}, Permerror, true},
	}

	var match bool
	var result Result

	for i, testcase := range testcases {
		match, result, _ = p.parseA(testcase.Input)
		if testcase.Match != match {
			t.Errorf("#%d Match mismatch, expected %v, got %v\n", i, testcase.Match, match)
		}
		if testcase.Result != result {
			t.Errorf("#%d Result mismatch, expected %s, got %s\n", i, testcase.Result, result)
		}
	}
}

func TestParseAIpv6(t *testing.T) {
	mux, testResolver := newTestDNS(t)

	hosts := make(map[uint16][]string)

	hosts[dns.TypeA] = []string{
		"positive.matching.com. 0 IN A 172.20.21.1",
		"positive.matching.com. 0 IN A 172.18.0.2",
		"positive.matching.com. 0 IN A 172.20.20.1",
	}
	hosts[dns.TypeAAAA] = []string{
		"positive.matching.com. 0 IN AAAA 2001:4860:0:2001::68",
	}

	positiveMatchingCom := zone(t, hosts)
	mux.HandleFunc("positive.matching.com.", positiveMatchingCom)
	mux.HandleFunc("matching.com.", positiveMatchingCom)

	hosts = make(map[uint16][]string)

	hosts[dns.TypeA] = []string{
		"negative.matching.com. 0 IN A 172.20.21.1",
	}
	negativeMatchingCom := zone(t, hosts)
	mux.HandleFunc("negative.matching.com.", negativeMatchingCom)

	p := newParser(domain, "matching.com", ipv6, stub, testResolver)
	testcases := []TokenTestCase{
		{&token{tA, qPlus, "positive.matching.com"}, Pass, true},
		{&token{tA, qPlus, "positive.matching.com//128"}, Pass, true},
		{&token{tA, qPlus, "positive.matching.com//64"}, Pass, true},

		{&token{tA, qPlus, "negative.matching.com"}, Pass, false},
		{&token{tA, qPlus, "negative.matching.com//64"}, Pass, false},
		{&token{tA, qPlus, "positive.matching.com// "}, Permerror, true},
		{&token{tA, qPlus, "positive.matching.com/ "}, Permerror, true},
		{&token{tA, qPlus, "positive.matching.com/ / "}, Permerror, true},
	}

	var match bool
	var result Result

	for _, testcase := range testcases {
		match, result, _ = p.parseA(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch")
		}
		if testcase.Result != result {
			t.Error("Result mismatch")
		}
	}
}

func TestParseIp4(t *testing.T) {
	_, testResolver := newTestDNS(t)
	p := newParser(stub, stub, ip, stub, testResolver)
	testcases := []TokenTestCase{
		{&token{tIP4, qPlus, "127.0.0.1"}, Pass, true},
		{&token{tIP4, qMinus, "127.0.0.1"}, Fail, true},
		{&token{tIP4, qQuestionMark, "127.0.0.1"}, Neutral, true},
		{&token{tIP4, qTilde, "127.0.0.1"}, Softfail, true},

		{&token{tIP4, qTilde, "127.0.0.0/16"}, Softfail, true},

		{&token{tIP4, qTilde, "192.168.1.2"}, Softfail, false},
		{&token{tIP4, qMinus, "192.168.1.5/16"}, Fail, false},

		{&token{tIP4, qMinus, "random string"}, Permerror, true},
		{&token{tIP4, qMinus, "2001:4860:0:2001::68"}, Permerror, true},
		{&token{tIP4, qMinus, "2001:4860:0:2001::68/48"}, Permerror, true},
	}

	var match bool
	var result Result

	for _, testcase := range testcases {
		match, result, _ = p.parseIP4(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch")
		}
		if testcase.Result != result {
			t.Error("Result mismatch")
		}
	}
}

func TestParseIp6(t *testing.T) {
	_, testResolver := newTestDNS(t)
	p := newParser(stub, stub, ipv6, stub, testResolver)

	testcases := []TokenTestCase{
		{&token{tIP6, qPlus, "2001:4860:0:2001::68"}, Pass, true},
		{&token{tIP6, qMinus, "2001:4860:0:2001::68"}, Fail, true},
		{&token{tIP6, qQuestionMark, "2001:4860:0:2001::68"}, Neutral, true},
		{&token{tIP6, qTilde, "2001:4860:0:2001::68"}, Softfail, true},

		{&token{tIP6, qTilde, "2001:4860:0:2001::68/64"}, Softfail, true},

		{&token{tIP6, qTilde, "::1"}, Softfail, false},
		{&token{tIP6, qMinus, "2002::/16"}, Fail, false},

		{&token{tIP6, qMinus, "random string"}, Permerror, true},
	}

	var match bool
	var result Result

	for _, testcase := range testcases {
		match, result, _ = p.parseIP6(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch, expected ", testcase.Match, " got ", match)
		}
		if testcase.Result != result {
			t.Error("Result mismatch, expected ", testcase.Result, " got ", result)
		}
	}
}

func TestParseIp6WithIp4(t *testing.T) {
	_, testResolver := newTestDNS(t)
	p := newParser(stub, stub, ip, stub, testResolver)

	testcases := []TokenTestCase{
		{&token{tIP6, qPlus, "127.0.0.1"}, Permerror, true},
		{&token{tIP6, qTilde, "127.0.0.1"}, Permerror, true},
	}

	var match bool
	var result Result

	for _, testcase := range testcases {
		match, result, _ = p.parseIP6(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch, expected ", testcase.Match, " got ", match)
		}
		if testcase.Result != result {
			t.Error("Result mismatch, expected ", testcase.Result, " got ", result)
		}
	}
}

func TestParseMX(t *testing.T) {
	mux, testResolver := newTestDNS(t)

	ips := []net.IP{
		{172, 18, 0, 2},
		{172, 20, 20, 20},
		{172, 100, 0, 1},
		net.ParseIP("2001:4860:1:2001::80"),
	}

	/* helper functions */

	mux.HandleFunc("matching.com.", zone(t, map[uint16][]string{
		dns.TypeMX: {
			"matching.com. 0 IN MX 5 mail.matching.com.",
			"matching.com. 0 IN MX 10 mail2.matching.com.",
			"matching.com. 0 IN MX 15 mail3.matching.com.",
		},
		dns.TypeAAAA: {
			"mail.matching.com. 0 IN AAAA 2001:4860:1:2001::80",
		},
		dns.TypeA: {
			"mail.matching.com. 0 IN A 172.18.0.2",
			"mail2.matching.com. 0 IN A 172.20.20.20",
			"mail3.matching.com. 0 IN A 172.100.0.1",
		},
	}))

	/* ***************** */

	p := newParser(domain, "matching.com", net.IP{0, 0, 0, 0}, stub, testResolver)

	testcases := []TokenTestCase{
		{&token{tMX, qPlus, "matching.com"}, Pass, true},
		{&token{tMX, qPlus, "matching.com/24"}, Pass, true},
		{&token{tMX, qPlus, "matching.com/24/64"}, Pass, true},
		{&token{tMX, qPlus, ""}, Pass, true},
		{&token{tMX, qMinus, ""}, Fail, true},
		{&token{tMX, qPlus, "idontexist"}, Pass, false},
		// Mind that the domain is matching.NET and we expect Parser
		// to not match results.
		{&token{tMX, qPlus, "matching.net"}, Pass, false},
		{&token{tMX, qPlus, "matching.net/24"}, Pass, false},
		{&token{tMX, qPlus, "matching.net/24/64"}, Pass, false},
	}

	var match bool
	var result Result

	for i, testcase := range testcases {
		for _, ip := range ips {
			p.IP = ip
			match, result, _ = p.parseMX(testcase.Input)
			if testcase.Match != match {
				t.Errorf("#%d Match mismatch, expected %v, got %v", i, testcase.Match, match)
			}
			if testcase.Result != result {
				t.Errorf("#%d Result mismatch, expected %v, got %v", i, testcase.Result, result)
			}
		}
	}
}

func TestParseMXNegativeTests(t *testing.T) {
	mux, testResolver := newTestDNS(t)

	/* helper functions */

	hosts := make(map[uint16][]string)

	hosts[dns.TypeMX] = []string{
		"mail.matching.com. 0 IN MX 5 mail.matching.com.",
		"mail.matching.com. 0 IN MX 10 mail2.matching.com.",
		"mail.matching.com. 0 IN MX 15 mail3.matching.com.",
	}
	hosts[dns.TypeAAAA] = []string{
		"mail.matching.com. 0 IN AAAA 2001:4860:1:2001::80",
	}

	hosts[dns.TypeA] = []string{
		"mail.matching.com. 0 IN A 172.18.0.2",
		"mail2.matching.com. 0 IN A 172.20.20.20",
		"mail3.matching.com. 0 IN A 172.100.0.1",
	}
	mxMatchingCom := zone(t, hosts)
	mux.HandleFunc("matching.com.", mxMatchingCom)

	p := newParser("matching.com", "matching.com", net.IP{127, 0, 0, 1}, stub, testResolver)

	testcases := []TokenTestCase{
		{&token{tMX, qPlus, "matching.com"}, Pass, false},
		{&token{tMX, qPlus, ""}, Pass, false},
		//TokenTestCase{&Token{tMX, qPlus, "google.com"}, Pass, false},
		{&token{tMX, qPlus, "idontexist"}, Pass, false},
		{&token{tMX, qMinus, "matching.com"}, Fail, false},
	}

	var match bool
	var result Result

	for _, testcase := range testcases {
		match, result, _ = p.parseMX(testcase.Input)
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
	mux, testResolver := newTestDNS(t)

	/* helper functions */

	mux.HandleFunc("matching.net.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			`_spf.matching.net. 0 IN TXT "v=spf1 a:positive.matching.net -a:negative.matching.net ~mx -all"`,
		},
		dns.TypeMX: {
			"mail.matching.net. 0 IN MX 5 mail.matching.net.",
			"mail.matching.net. 0 IN MX 10 mail2.matching.net.",
		},
		dns.TypeA: {
			"positive.matching.net. 0 IN A 172.100.100.1",
			"positive.matching.net. 0 IN A 173.18.0.2",
			"positive.matching.net. 0 IN A 173.20.20.1",
			"positive.matching.net. 0 IN A 173.20.21.1",
			"negative.matching.net. 0 IN A 172.18.100.100",
			"negative.matching.net. 0 IN A 172.18.100.101",
			"negative.matching.net. 0 IN A 172.18.100.102",
			"negative.matching.net. 0 IN A 172.18.100.103",
			"mail.matching.net.	0 IN A 173.18.0.2",
			"mail2.matching.net. 0 IN A 173.20.20.20",
		},
	}))

	/*******************************/
	ips := []net.IP{
		{172, 100, 100, 1},
		{173, 20, 20, 1},
		{173, 20, 21, 1},
	}

	p := newParser("matching.net", "matching.net", net.IP{0, 0, 0, 0}, stub, testResolver)
	testcases := []TokenTestCase{
		{&token{tInclude, qPlus, "_spf.matching.net"}, Pass, true},
		{&token{tInclude, qMinus, "_spf.matching.net"}, Fail, true},
		{&token{tInclude, qTilde, "_spf.matching.net"}, Softfail, true},
		{&token{tInclude, qQuestionMark, "_spf.matching.net"}, Neutral, true},
	}

	for i, testcase := range testcases {
		for j, ip := range ips {
			p.IP = ip
			match, result, _ := p.parseInclude(testcase.Input)
			if testcase.Match != match {
				t.Errorf("#%d.%d Match mismatch, expected %v, got %v", i, j, testcase.Match, match)
			}
			if testcase.Result != result {
				t.Errorf("#%d.%d Result mismatch, expected %v, got %v", i, j, testcase.Result, result)
			}
		}
	}
}

// TestParseIncludeNegative shows correct behavior of include qualifier.
// We expect all the IP addressess to fail (for tests that domain/record
// exists).  Please note that all tested IP address will match
// negative.matching.net domain, or last term (-all), hence the recursive call
// will always return (match, Fail). As per recursive calls for include term we
// are supposed to not mach top-level include term.  On the other hands, for
// include term, that refer to non existing domains we are supposed to return
// (match, Permerror)
func TestParseIncludeNegative(t *testing.T) {
	mux, testResolver := newTestDNS(t)

	/* helper functions */

	hosts := make(map[uint16][]string)
	hosts[dns.TypeTXT] = []string{
		"_spf.matching.net. 0 IN TXT \"v=spf1 a:positive.matching.net -a:negative.matching.net ~mx -all\"",
	}
	hosts[dns.TypeMX] = []string{
		"mail.matching.net. 0 IN MX 5 mail.matching.net.",
		"mail.matching.net. 0 IN MX 10 mail2.matching.net.",
	}
	hosts[dns.TypeA] = []string{
		"postivie.matching.net. 0 IN A 172.100.100.1",
		"positive.matching.net. 0 IN A 173.18.0.2",
		"positive.matching.net. 0 IN A 173.20.20.1",
		"positive.matching.net. 0 IN A 173.20.21.1",
		"negative.matching.net. 0 IN A 172.18.100.100",
		"negative.matching.net. 0 IN A 172.18.100.101",
		"negative.matching.net. 0 IN A 172.18.100.102",
		"negative.matching.net. 0 IN A 172.18.100.103",
		"mail.matching.net.	0 IN A 173.18.0.2",
		"mail2.matching.net. 0 IN A 173.20.20.20",
	}
	includeMatchingCom := zone(t, hosts)
	mux.HandleFunc("matching.net.", includeMatchingCom)

	/*******************************/
	ips := []net.IP{
		// completely random IP address out of the net segment
		{80, 81, 82, 83},
		// ip addresses from failing negative.matching.net A records
		{173, 18, 100, 100},
		{173, 18, 100, 101},
		{173, 18, 100, 102},
		{173, 18, 100, 103},
	}
	p := newParser("matching.net", "matching.net", ip, stub, testResolver)

	testcases := []TokenTestCase{
		{&token{tInclude, qMinus, "_spf.matching.net"}, None, false},
		{&token{tInclude, qPlus, "_spf.matching.net"}, None, false},
		// TODO(zaccone): Following 3 tests are practically identitcal
		{&token{tInclude, qPlus, "_errspf.matching.net"}, Permerror, true},
		{&token{tInclude, qPlus, "nospf.matching.net"}, Permerror, true},
		{&token{tInclude, qPlus, "idontexist.matching.net"}, Permerror, true},

		// empty input qualifier results in Permerror withour recursive calls
		{&token{tInclude, qMinus, ""}, Permerror, true},
	}

	var match bool
	var result Result

	for _, testcase := range testcases {
		for _, ip := range ips {
			p.IP = ip
			match, result, _ = p.parseInclude(testcase.Input)
			if testcase.Match != match {
				t.Error("IP:", ip, ":", testcase.Input.value, ": Match mismatch, expected ", testcase.Match, " got ", match)
			}
			if testcase.Result != result {
				t.Error("IP:", ip, ":", testcase.Input.value, ": Result mismatch, expected ", testcase.Result, " got ", result)
			}
		}
	}

}

// TestParseExists executes tests for exists term.
func TestParseExists(t *testing.T) {
	mux, testResolver := newTestDNS(t)

	hosts := make(map[uint16][]string)
	hosts[dns.TypeA] = []string{
		"positive.matching.net. 0 IN A 172.20.20.20",
		"positive.matching.net. 0 IN A 172.18.0.1",
		"positive.matching.net. 0 IN A 172.18.0.2",
	}
	mux.HandleFunc("positive.matching.net.", zone(t, hosts))

	hosts = make(map[uint16][]string)
	hosts[dns.TypeA] = []string{
		"positive.matching.com. 0 IN A 172.20.20.20",
		"positive.matching.com. 0 IN A 172.18.0.1",
		"positive.matching.com. 0 IN A 172.18.0.2",
	}
	mux.HandleFunc("positive.matching.com.", zone(t, hosts))

	p := newParser("matching.com", "matching.com", ip, stub, testResolver)
	testcases := []TokenTestCase{
		{&token{tExists, qPlus, "positive.matching.net"}, Pass, true},
		{&token{tExists, qMinus, "positive.matching.net"}, Fail, true},
		{&token{tExists, qMinus, "idontexist.matching.net"}, Fail, false},
		{&token{tExists, qMinus, "idontexist.%{d}"}, Fail, false},
		{&token{tExists, qTilde, "positive.%{d}"}, Softfail, true},
		{&token{tExists, qTilde, "positive.%{d}"}, Softfail, true},
		{&token{tExists, qTilde, ""}, Permerror, true},
		{&token{tExists, qTilde, "invalidsyntax%{}"}, Permerror, true},
	}

	for _, testcase := range testcases {
		match, result, _ := p.parseExists(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch, expected ", testcase.Match, " got ", match)
		}
		if testcase.Result != result {
			t.Error("Result mismatch, expected ", testcase.Result, " got ", result)
		}
	}
}

type parseTestCase struct {
	Query  string
	IP     net.IP
	Result Result
}

// TestParse tests whole Parser.Parse() method
func TestParse(t *testing.T) {
	mux, testResolver := newTestDNS(t)

	mux.HandleFunc("matching.com.", zone(t, map[uint16][]string{
		dns.TypeMX: {
			"matching.com. 0 in MX 5 matching.com.",
		},
		dns.TypeA: {
			"matching.com. 0 IN A 172.20.20.20",
			"matching.com. 0 IN A 172.18.0.1",
			"matching.com. 0 IN A 172.18.0.2",
		},
	}))

	mux.HandleFunc("matching.net.", zone(t, map[uint16][]string{
		dns.TypeMX: {
			"matching.net. 0 IN MX 5 matching.net.",
		},
		dns.TypeA: {
			"matching.net. 0 IN A 173.18.0.2",
			"matching.net. 0 IN A 173.20.20.20",
		},
	}))

	mux.HandleFunc("_spf.matching.net.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			"_spf.matching.net. 0 IN TXT \"v=spf1 a:positive.matching.net -a:negative.matching.net ~mx -all\"",
		},
	}))

	mux.HandleFunc("positive.matching.net.", zone(t, map[uint16][]string{
		dns.TypeA: {
			"positive.matching.net. 0 IN A 172.100.100.1",
			"positive.matching.net. 0 IN A 173.18.0.2",
			"positive.matching.net. 0 IN A 173.20.20.1",
			"positive.matching.net. 0 IN A 173.20.21.1",
		},
	}))

	mux.HandleFunc("negative.matching.net.", zone(t, map[uint16][]string{
		dns.TypeA: {
			"negative.matching.net. 0 IN A 172.100.100.1",
			"negative.matching.net. 0 IN A 173.18.0.2",
			"negative.matching.net. 0 IN A 173.20.20.1",
			"negative.matching.net. 0 IN A 173.20.21.1",
		},
	}))

	mux.HandleFunc("lb.matching.com.", zone(t, map[uint16][]string{
		dns.TypeA: {
			"lb.matching.com. 0 IN A 172.101.101.1",
		},
	}))

	mux.HandleFunc("loop.matching.net.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			`loop.matching.net. 0 IN TXT "v=spf1 include:loop.matching.com -all"`,
		},
	}))

	mux.HandleFunc("loop.matching.com.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			`loop.matching.com. 0 IN TXT "v=spf1 include:loop.matching.net -all"`,
		},
	}))

	mux.HandleFunc("loop2.matching.net.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			`loop2.matching.net. 0 IN TXT "v=spf1 redirect:loop2.matching.com -all"`,
		},
	}))

	mux.HandleFunc("loop2.matching.com.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			`loop2.matching.com. 0 IN TXT "v=spf1 redirect:loop2.matching.net -all"`,
		},
	}))

	parseTestCases := []parseTestCase{
		{"v=spf1 -all", net.IP{127, 0, 0, 1}, Fail},
		{"v=spf1 mx -all", net.IP{172, 20, 20, 20}, Pass},
		{"v=spf1 ?mx -all", net.IP{172, 20, 20, 20}, Neutral},
		{"v=spf1 ~mx -all", net.IP{172, 20, 20, 20}, Softfail},
		{"v=spf1 a -mx -all", net.IP{172, 18, 0, 2}, Pass},
		{"v=spf1 -mx a -all", net.IP{172, 18, 0, 2}, Fail},
		{"v=spf1 +mx:matching.net -a -all", net.IP{173, 18, 0, 2}, Pass},
		{"v=spf1 +mx:matching.net -a -all", net.IP{172, 17, 0, 2}, Fail},
		{"v=spf1 a:matching.net -all", net.IP{173, 18, 0, 2}, Pass},
		{"v=spf1 +ip4:128.14.15.16 -all", net.IP{128, 14, 15, 16}, Pass},
		{"v=spf1 ~ip6:2001:56::2 -all", net.ParseIP("2001:56::2"), Softfail},
		// Test ensures that once no term was matched and there is no
		// redirect: mechanism, we should return Neutral result.
		{"v=spf1 -ip4:8.8.8.8", net.IP{9, 9, 9, 9}, Neutral},
		// Test will return SPFResult Fail as 172.20.20.1 does not result
		// positively for domain _spf.matching.net
		{"v=spf1 ip4:127.0.0.1 +include:_spf.matching.net -all", net.IP{172, 20, 20, 1}, Fail},
		// Test will return SPFResult Pass as 172.100.100.1 is within
		// positive.matching.net A records, that are marked as +a:
		{"v=spf1 ip4:127.0.0.1 +include:_spf.matching.net -all", net.IP{172, 100, 100, 1}, Pass},
		// Test for syntax errors (include must have nonempty domain parameter)
		{"v=spf1 ip4:127.0.0.1 +include -all", net.IP{172, 100, 100, 1}, Permerror},
		{"v=spf1 ip4:127.0.0.1 ?include -all", net.IP{172, 100, 100, 1}, Permerror},
		// Include didn't match domain unexistent.com and underneath returned
		// Permerror, hence top level result is (match, Permerror) as per
		// recursive table in section 5.2 of RFC7208
		{"v=spf1 +include:unexistent.com -all", net.IP{172, 100, 100, 1}, Permerror},
		{"v=spf1 ?exists:lb.%{d} -all", ip, Neutral},
		// domain is set to matching.com, macro >>d1r<< will reverse domain to
		// >>com.matching<< and trim to first part counting from right,
		// effectively returning >>matching<<, which we later concatenate with
		// the >>.com<< suffix. This test should give same matching result as
		// the test above, as effectively the host to be queried is identical.
		{"v=spf1 ?exists:lb.%{d1r}.com -all", ip, Neutral},
		// 4.6.4 DNS Lookup Limits
		// Some mechanisms and modifiers (collectively, "terms") cause DNS
		// queries at the time of evaluation, and some do not.  The following
		// terms cause DNS queries: the "include", "a", "mx", "ptr", and
		// "exists" mechanisms, and the "redirect" modifier.  SPF
		// implementations MUST limit the total number of those terms to 10
		// during SPF evaluation, to avoid unreasonable load on the DNS.  If
		// this limit is exceeded, the implementation MUST return "permerror".
		// The other terms -- the "all", "ip4", and "ip6" mechanisms, and the
		// "exp" modifier -- do not cause DNS queries at the time of SPF
		// evaluation (the "exp" modifier only causes a lookup
		// https://tools.ietf.org/html/rfc7208#section-2.6
		{"v=spf1 include:loop.matching.com -all", net.IP{10, 0, 0, 1}, Permerror},
		{"v=spf1 redirect:loop2.matching.com -all", net.IP{10, 0, 0, 1}, Permerror},
	}

	for _, testcase := range parseTestCases {
		result, _, err := newParser("matching.com", "matching.com", testcase.IP, testcase.Query, NewLimitedResolver(testResolver, 4, 4)).parse()
		if result != Permerror && result != Temperror && err != nil {
			t.Errorf("%q Unexpected error while parsing: %s", testcase.Query, err)
		}
		if result != testcase.Result {
			t.Errorf("%q Expected %v, got %v", testcase.Query, testcase.Result, result)
		}
	}
}

// TestParseRedirect tests whole parsing behavior with a special testing of
// redirect modifier
func TestHandleRedirect(t *testing.T) {
	mux, testResolver := newTestDNS(t)

	mux.HandleFunc("matching.net.", zone(t, map[uint16][]string{
		dns.TypeMX: {
			"matching.net. 0 IN MX 5 matching.net.",
		},
		dns.TypeA: {
			"matching.net. 0 IN A 173.18.0.2",
			"matching.net. 0 IN A 173.20.20.20",
		},
	}))

	mux.HandleFunc("_spf.matching.net.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			"_spf.matching.net. 0 IN TXT \"v=spf1 a:positive.matching.net -a:negative.matching.net ~mx -all\"",
		},
	}))

	mux.HandleFunc("nospf.matching.net.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			"nospf.matching.net. 0 IN TXT \"no spf here\"",
		},
	}))

	mux.HandleFunc("positive.matching.net.", zone(t, map[uint16][]string{
		dns.TypeA: {
			"positive.matching.net. 0 IN A 172.100.100.1",
			"positive.matching.net. 0 IN A 173.18.0.2",
			"positive.matching.net. 0 IN A 173.20.20.1",
			"positive.matching.net. 0 IN A 173.20.21.1",
		},
	}))

	mux.HandleFunc("negative.matching.net.", zone(t, map[uint16][]string{
		dns.TypeA: {
			"negative.matching.net. 0 IN A 172.100.100.1",
			"negative.matching.net. 0 IN A 173.18.0.2",
			"negative.matching.net. 0 IN A 173.20.20.1",
			"negative.matching.net. 0 IN A 173.20.21.1",
		},
	}))

	mux.HandleFunc("redirect.matching.net.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			"redirect.matching.net. 0 IN TXT \"v=spf1 redirect=matching.com\"",
		},
	}))

	mux.HandleFunc("redirect.matching.com.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			"redirect.matching.com. 0 IN TXT \"v=spf1 redirect=redirect.matching.net\"",
		},
	}))

	mux.HandleFunc("matching.com.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			"matching.com. 0 IN TXT \"v=spf1 mx:matching.com -all\"",
		},
		dns.TypeMX: {
			"matching.com.	0 IN MX 5 mail.matching.com",
		},
		dns.TypeA: {
			"mail.matching.com.	0 IN A 172.18.0.2",
		},
	}))

	ParseTestCases := []parseTestCase{
		{"v=spf1 -all redirect=_spf.matching.net", net.IP{172, 100, 100, 1}, Fail},
		{"v=spf1 redirect=_spf.matching.net -all", net.IP{172, 100, 100, 1}, Fail},
		{"v=spf1 redirect=_spf.matching.net", net.IP{172, 100, 100, 1}, Pass},
		{"v=spf1 redirect=malformed", net.IP{172, 100, 100, 1}, Permerror},
		{"v=spf1 redirect=_spf.matching.net", net.IP{127, 0, 0, 1}, Fail},
		{"v=spf1 redirect=nospf.matching.net", net.IP{127, 0, 0, 1}, Permerror},
		{"v=spf1 +ip4:127.0.0.1 redirect=nospf.matching.net", net.IP{127, 0, 0, 1}, Pass},
		{"v=spf1 -ip4:127.0.0.1 redirect=nospf.matching.net", net.IP{127, 0, 0, 1}, Fail},
		{"v=spf1 +include:_spf.matching.net redirect=_spf.matching.net", net.IP{127, 0, 0, 1}, Fail},
		{"v=spf1 ~include:_spf.matching.net redirect=_spf.matching.net", net.IP{172, 100, 100, 1}, Softfail},
		// Ensure recursive redirects work
		{"v=spf1 redirect=redirect.matching.com", net.IP{172, 18, 0, 2}, Pass},
		{"v=spf1 redirect=redirect.matching.com", net.IP{127, 0, 0, 1}, Fail},
	}

	for _, testcase := range ParseTestCases {
		p := newParser("matching.com", "matching.com", testcase.IP, testcase.Query, testResolver)
		result, _, _ := p.parse()
		if result != testcase.Result {
			t.Errorf("%q Expected %v, got %v", testcase.Query, testcase.Result, result)
		}
	}
}

type ExpTestCase struct {
	Query       string
	Explanation string
}

func TestHandleExplanation(t *testing.T) {
	mux, testResolver := newTestDNS(t)
	// static.exp.matching.com.        IN      TXT "Invalid SPF record"
	// ip.exp.matching.com.            IN      TXT "%{i} is not one of %{d}'s designated mail servers."
	// redirect.exp.matching.com.      IN      TXT "See http://%{d}/why.html?s=%{s}&i=%{i}"

	mux.HandleFunc("static.exp.matching.com.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			"static.exp.matching.com. 0 IN TXT \"Invalid SPF record\"",
		},
	}))

	mux.HandleFunc("ip.exp.matching.com.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			"ip.exp.matching.com. 0 in TXT \"%{i} is not one of %{d}'s designated mail servers.\"",
		},
	}))

	mux.HandleFunc("redirect.exp.matching.com.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			"redirect.exp.matching.com. 0 in TXT \"See http://%{d}/why.html?s=%{s}&i=%{i}\"",
		},
	}))

	expTestCases := []ExpTestCase{
		{"v=spf1 -all exp=static.exp.matching.com",
			"Invalid SPF record"},
		{"v=spf1 -all exp=ip.exp.matching.com",
			"127.0.0.1 is not one of matching.com's designated mail servers."},
		{"v=spf1 -all exp=redirect.exp.matching.com",
			"See http://matching.com/why.html?s=matching.com&i=127.0.0.1"},
		{"v=spf1 -all exp=idontexist", ""},
	}

	for _, testcase := range expTestCases {
		p := newParser("matching.com", "matching.com", ip, testcase.Query, testResolver)
		_, exp, err := p.parse()
		if err != nil {
			t.Errorf("%q unexpected error while parsing: %s", testcase.Query, err)
		}
		if exp != testcase.Explanation {
			t.Errorf("%q explanation mismatch, expected %q, got %q", testcase.Query,
				testcase.Explanation, exp)
		}
	}
}

func TestHandleExplanationNegative(t *testing.T) {
	mux, testResolver := newTestDNS(t)

	mux.HandleFunc("1.exp.matching.com.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			"1.exp.matching.com. 0 IN TXT \"%{\"",
		},
	}))

	expTestCases := []ExpTestCase{
		// While evaluating exp domain we never encounter closing '}', hence we
		// should raise appropriate error and return ""
		{"v=spf1 -all exp=%{randomstuff", "unexpected char (97), expected '}'"},
		// We cut the domain name, and eventually what we get is empty string.
		// We cannot find any explanation's domain, so we return "" AND
		// a SyntaxError{} error as an indication for operators.
		{"v=spf1 -all exp=%{d0}", "empty domain"},
		// TXT record for 1.exp.matching.com. is invalid, hence we also return
		// an error indicating what's wrong.
		{"v=spf1 -all exp=1.exp.matching.com", "unexpected eof for macro (%{)"},
	}
	for _, testcase := range expTestCases {
		p := newParser("matching.com", "matching.com", ip, testcase.Query, testResolver)
		r, e, err := p.parse()
		if err == nil {
			t.Errorf("Expected error for query: %q", testcase.Query)
		}

		if r != Fail {
			t.Errorf("Expected Result set to Fail for query: %q", testcase.Query)
		}

		if e != "" {
			t.Errorf("Expected explanation returned to be empty string for query: %q",
				testcase.Query)
		}

		// if the err is of type SyntaxErr substract underlying err variable,
		// we don't care about associated *token attribute.
		var serr SyntaxError
		var ok bool
		if serr, ok = err.(SyntaxError); ok {
			if serr.err.Error() != testcase.Explanation {
				t.Errorf("%q expected error %s, got %s\n", testcase.Query,
					testcase.Explanation, serr.err.Error())
			}
		}
	}
}

func TestSelectingRecord(t *testing.T) {
	mux, testResolver := newTestDNS(t)
	mux.HandleFunc("v-spf2.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			`v-spf2. 0 IN TXT "v=spf2"`,
		},
	}))

	mux.HandleFunc("v-spf10.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			`v-spf10. 0 IN TXT "v=spf10"`,
		},
	}))

	mux.HandleFunc("no-record.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			`no-record. 0 IN TXT ""`,
		},
	}))

	mux.HandleFunc("many-records.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			`many-records. 0 IN TXT "v=spf1"`,
			`many-records. 0 IN TXT "v=spf1"`,
			`many-records. 0 IN TXT ""`,
		},
	}))

	mux.HandleFunc("mixed-records.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			`mixed-records. 0 IN TXT "v=spf1 +all"`,
			`mixed-records. 0 IN TXT "v-spf10"`,
			`mixed-records. 0 IN TXT ""`,
		},
	}))

	samples := []struct {
		d string
		r Result
		e error
	}{
		{"notexists", None, ErrDNSPermerror},
		{"v-spf2", None, ErrSPFNotFound},
		{"v-spf10", None, ErrSPFNotFound},
		{"no-record", None, ErrSPFNotFound},
		{"many-records", Permerror, errTooManySPFRecords},
		{"mixed-records", Pass, nil},
	}

	ip := net.ParseIP("10.0.0.1")
	for i, s := range samples {
		r, _, e := CheckHostWithResolver(ip, s.d, s.d, testResolver)
		if r != s.r || e != s.e {
			t.Errorf("#%d `%s` want [`%v` `%v`], got [`%v` `%v`]", i, s.d, s.r, s.e, r, e)
		}
	}
}
