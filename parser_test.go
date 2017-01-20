package spf

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	stub         string = "stub"
	localDNSAddr string = "127.0.0.1:53053"
)

var (
	ip     = net.IP{127, 0, 0, 1}
	ipv6   = net.ParseIP("2001:4860:0:2001::68")
	config = &Config{localDNSAddr}
)

/* helper functions */

func runLocalUDPServer(laddr string) (*dns.Server, string, error) {
	pc, err := net.ListenPacket("udp", laddr)
	if err != nil {
		return nil, "", err
	}
	server := &dns.Server{PacketConn: pc, ReadTimeout: time.Second, WriteTimeout: time.Second}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	go func() {
		server.ActivateAndServe()
		pc.Close()
	}()

	waitLock.Lock()
	return server, pc.LocalAddr().String(), nil
}

func rootZone(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	rr, _ := dns.NewRR(". 0 IN SOA a.root-servers.net. nstld.verisign-grs.com. 2016110600 1800 900 604800 86400")
	m.Ns = []dns.RR{rr}
	w.WriteMsg(m)
}

func zone(zone map[uint16][]string) func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)

		rr, ok := zone[req.Question[0].Qtype]
		if !ok {
			w.WriteMsg(m)
			return
		}
		m.Answer = make([]dns.RR, 0, len(rr))
		for _, r := range rr {
			if !strings.HasPrefix(r, req.Question[0].Name) {
				continue
			}
			a, err := dns.NewRR(r)
			if err != nil {
				fmt.Printf("unable to prepare dns response: %s\n", err)
				continue
			}
			m.Answer = append(m.Answer, a)
		}
		w.WriteMsg(m)
	}
}

/********************/

func TestNewParserFunction(t *testing.T) {
	p := NewParser(stub, stub, ip, stub, config)

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
		{qPlus, Pass},
		{qMinus, Fail},
		{qQuestionMark, Neutral},
		{qTilde, Softfail},
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
		{
			[]*Token{
				versionToken,
				{tAll, qMinus, ""},
			},
			[]*Token{
				versionToken,
				{tAll, qMinus, ""},
			},
			nil,
			nil,
		},
		{
			[]*Token{
				versionToken,
				{tRedirect, qPlus, "_spf.example.com"},
				{tMX, qTilde, "example.org"},
			},
			[]*Token{
				versionToken,
				{tMX, qTilde, "example.org"},
			},
			&Token{tRedirect, qPlus, "_spf.example.com"},
			nil,
		},
		{
			[]*Token{
				versionToken,
				{tRedirect, qPlus, "_spf.example.com"},
				{tIP4, qTilde, "192.168.1.2"},
				{tExp, qPlus, "Something went wrong"},
			},
			[]*Token{
				versionToken,
				{tIP4, qTilde, "192.168.1.2"},
			},
			&Token{tRedirect, qPlus, "_spf.example.com"},
			&Token{tExp, qPlus, "Something went wrong"},
		},
		{
			[]*Token{
				versionToken,
				{tRedirect, qPlus, "_spf.example.com"},
				{tMX, qTilde, "example.org"},
				{tAll, qQuestionMark, ""},
			},
			[]*Token{
				versionToken,
				{tMX, qTilde, "example.org"},
				{tAll, qQuestionMark, ""},
			},
			nil,
			nil,
		},
		{
			[]*Token{
				versionToken,
				{tRedirect, qPlus, "_spf.example.com"},
				{tMX, qTilde, "example.org"},
				{tAll, qQuestionMark, ""},
				{tExp, qPlus, "You are wrong"},
			},
			[]*Token{
				versionToken,
				{tMX, qTilde, "example.org"},
				{tAll, qQuestionMark, ""},
			},
			nil,
			&Token{tExp, qPlus, "You are wrong"},
		},
	}

	for _, testcase := range testcases {
		p := NewParser(stub, stub, ip, stub, config)
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
		{
			[]*Token{
				versionToken,
				{tRedirect, qPlus, "_spf.example.com"},
				{tMX, qMinus, "example.org"},
				{tRedirect, qPlus, "_spf.example.com"},
			},
		},
		{
			[]*Token{
				versionToken,
				{tRedirect, qPlus, "_spf.example.com"},
				{tMX, qMinus, "example.org"},
				{tExp, qPlus, "Explanation"},
				{tExp, qPlus, "Explanation"},
			},
		},
		{
			[]*Token{
				versionToken,
				{tRedirect, qPlus, "_spf.example.com"},
				{tAll, qMinus, ""},
				{tExp, qPlus, "_spf.example.com"},
				{tRedirect, qPlus, "mydomain.com"},
			},
		},
	}

	for _, testcase := range testcases {
		p := NewParser(stub, stub, ip, stub, config)
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
	p := NewParser(stub, stub, ip, stub, config)
	testcases := []TokenTestCase{
		{&Token{tAll, qPlus, ""}, Pass, true},
		{&Token{tAll, qMinus, ""}, Fail, true},
		{&Token{tAll, qQuestionMark, ""}, Neutral, true},
		{&Token{tAll, qTilde, ""}, Softfail, true},
		{&Token{tAll, tErr, ""}, Permerror, true},
	}

	var match bool
	var result SPFResult

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

	ip := net.IP{172, 18, 0, 2}
	domain := "matching.com"

	dns.HandleFunc(".", rootZone)
	defer dns.HandleRemove(".")

	dns.HandleFunc("matching.com.", zone(map[uint16][]string{
		dns.TypeA: {
			"matching.com. 0 IN A 172.20.21.1",
			"matching.com. 0 IN A 172.18.0.2",
			"matching.com. 0 IN A 172.20.20.1",
		},
		dns.TypeAAAA: {
			"matching.com. 0 IN AAAA 2001:4860:0:2001::68",
		},
	}))
	defer dns.HandleRemove("matching.com.")

	dns.HandleFunc("positive.matching.com.", zone(map[uint16][]string{
		dns.TypeA: {
			"positive.matching.com. 0 IN A 172.20.21.1",
			"positive.matching.com. 0 IN A 172.18.0.2",
			"positive.matching.com. 0 IN A 172.20.20.1",
		},
		dns.TypeAAAA: {
			"positive.matching.com. 0 IN AAAA 2001:4860:0:2001::68",
		},
	}))
	defer dns.HandleRemove("positive.matching.com.")

	dns.HandleFunc("negative.matching.com.", zone(map[uint16][]string{
		dns.TypeA: {
			"negative.matching.com. 0 IN A 172.20.21.1",
		},
	}))
	defer dns.HandleRemove("negative.matching.com.")

	dns.HandleFunc("range.matching.com.", zone(map[uint16][]string{
		dns.TypeA: {
			"range.matching.com. 0 IN A 172.18.0.2",
		},
	}))
	defer dns.HandleRemove("range.matching.com.")

	dns.HandleFunc("lb.matching.com.", zone(map[uint16][]string{
		dns.TypeA: {
			"lb.matching.com. 0 IN A 172.18.0.2",
		},
	}))
	defer dns.HandleRemove("lb.matching.com.")

	s, addr, err := runLocalUDPServer(localDNSAddr)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	config.Nameserver = addr
	p := NewParser(domain, domain, ip, stub, config)
	testcases := []TokenTestCase{
		{&Token{tA, qPlus, "positive.matching.com"}, Pass, true},
		{&Token{tA, qPlus, "positive.matching.com/32"}, Pass, true},
		{&Token{tA, qPlus, "negative.matching.com"}, Pass, false},
		{&Token{tA, qPlus, "range.matching.com/16"}, Pass, true},
		{&Token{tA, qPlus, "range.matching.com/128"}, Permerror, true},
		{&Token{tA, qPlus, "idontexist"}, Pass, false},
		{&Token{tA, qPlus, "#%$%^"}, Permerror, true},
		{&Token{tA, qPlus, "lb.matching.com"}, Pass, true},
		{&Token{tA, qMinus, ""}, Fail, true},
		{&Token{tA, qTilde, ""}, Softfail, true},

		// expect (Permerror, true) results as a result of syntax errors
		{&Token{tA, qPlus, "range.matching.com/wrongmask"}, Permerror, true},
		{&Token{tA, qPlus, "range.matching.com/129"}, Permerror, true},
		{&Token{tA, qPlus, "range.matching.com/-1"}, Permerror, true},

		// expect (Permerror, true) due to wrong netmasks.
		// It's a syntax error to specify a netmask over 32 bits for IPv4 addresses
		{&Token{tA, qPlus, "negative.matching.com/128"}, Permerror, true},
		{&Token{tA, qPlus, "positive.matching.com/128"}, Permerror, true},
		{&Token{tA, qPlus, "positive.matching.com/128"}, Permerror, true},

		// test dual-cidr syntax
		{&Token{tA, qPlus, "positive.matching.com//128"}, Pass, true},
		{&Token{tA, qPlus, "positive.matching.com/32/"}, Pass, true},
		{&Token{tA, qPlus, "positive.matching.com/0/0"}, Pass, true},
		{&Token{tA, qPlus, "positive.matching.com/33/100"}, Permerror, true},
		{&Token{tA, qPlus, "positive.matching.com/24/129"}, Permerror, true},
		{&Token{tA, qPlus, "positive.matching.com/128/32"}, Permerror, true},
	}

	var match bool
	var result SPFResult

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

	hosts := make(map[uint16][]string)

	hosts[dns.TypeA] = []string{
		"positive.matching.com. 0 IN A 172.20.21.1",
		"positive.matching.com. 0 IN A 172.18.0.2",
		"positive.matching.com. 0 IN A 172.20.20.1",
	}
	hosts[dns.TypeAAAA] = []string{
		"positive.matching.com. 0 IN AAAA 2001:4860:0:2001::68",
	}

	positiveMatchingCom := zone(hosts)
	dns.HandleFunc("positive.matching.com.", positiveMatchingCom)
	defer dns.HandleRemove("positive.matching.com.")
	dns.HandleFunc("matching.com.", positiveMatchingCom)
	defer dns.HandleRemove("matching.com.")

	hosts = make(map[uint16][]string)

	hosts[dns.TypeA] = []string{
		"negative.matching.com. 0 IN A 172.20.21.1",
	}
	negativeMatchingCom := zone(hosts)
	dns.HandleFunc("negative.matching.com.", negativeMatchingCom)
	defer dns.HandleRemove("negative.matching.com.")

	s, addr, err := runLocalUDPServer(localDNSAddr)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()
	config.Nameserver = addr
	domain := "matching.com"
	p := NewParser(domain, domain, ipv6, stub, config)
	testcases := []TokenTestCase{
		{&Token{tA, qPlus, "positive.matching.com"}, Pass, true},
		{&Token{tA, qPlus, "positive.matching.com//128"}, Pass, true},
		{&Token{tA, qPlus, "positive.matching.com//64"}, Pass, true},

		{&Token{tA, qPlus, "negative.matching.com"}, Pass, false},
		{&Token{tA, qPlus, "negative.matching.com//64"}, Pass, false},
		{&Token{tA, qPlus, "positive.matching.com// "}, Permerror, true},
		{&Token{tA, qPlus, "positive.matching.com/ "}, Permerror, true},
		{&Token{tA, qPlus, "positive.matching.com/ / "}, Permerror, true},
	}

	var match bool
	var result SPFResult

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
	p := NewParser(stub, stub, ip, stub, config)
	testcases := []TokenTestCase{
		{&Token{tIP4, qPlus, "127.0.0.1"}, Pass, true},
		{&Token{tIP4, qMinus, "127.0.0.1"}, Fail, true},
		{&Token{tIP4, qQuestionMark, "127.0.0.1"}, Neutral, true},
		{&Token{tIP4, qTilde, "127.0.0.1"}, Softfail, true},

		{&Token{tIP4, qTilde, "127.0.0.0/16"}, Softfail, true},

		{&Token{tIP4, qTilde, "192.168.1.2"}, Softfail, false},
		{&Token{tIP4, qMinus, "192.168.1.5/16"}, Fail, false},

		{&Token{tIP4, qMinus, "random string"}, Permerror, true},
		{&Token{tIP4, qMinus, "2001:4860:0:2001::68"}, Permerror, true},
		{&Token{tIP4, qMinus, "2001:4860:0:2001::68/48"}, Permerror, true},
	}

	var match bool
	var result SPFResult

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
	p := NewParser(stub, stub, ipv6, stub, config)

	testcases := []TokenTestCase{
		{&Token{tIP6, qPlus, "2001:4860:0:2001::68"}, Pass, true},
		{&Token{tIP6, qMinus, "2001:4860:0:2001::68"}, Fail, true},
		{&Token{tIP6, qQuestionMark, "2001:4860:0:2001::68"}, Neutral, true},
		{&Token{tIP6, qTilde, "2001:4860:0:2001::68"}, Softfail, true},

		{&Token{tIP6, qTilde, "2001:4860:0:2001::68/64"}, Softfail, true},

		{&Token{tIP6, qTilde, "::1"}, Softfail, false},
		{&Token{tIP6, qMinus, "2002::/16"}, Fail, false},

		{&Token{tIP6, qMinus, "random string"}, Permerror, true},
	}

	var match bool
	var result SPFResult

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
	p := NewParser(stub, stub, ip, stub, config)

	testcases := []TokenTestCase{
		{&Token{tIP6, qPlus, "127.0.0.1"}, Permerror, true},
		{&Token{tIP6, qTilde, "127.0.0.1"}, Permerror, true},
	}

	var match bool
	var result SPFResult

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

	ips := []net.IP{
		{172, 18, 0, 2},
		{172, 20, 20, 20},
		{172, 100, 0, 1},
		net.ParseIP("2001:4860:1:2001::80"),
	}

	/* helper functions */

	dns.HandleFunc(".", rootZone)
	defer dns.HandleRemove(".")

	dns.HandleFunc("matching.com.", zone(map[uint16][]string{
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
	defer dns.HandleRemove("matching.com.")

	s, _, err := runLocalUDPServer(localDNSAddr)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	/* ***************** */

	domain := "matching.com"
	p := NewParser(domain, domain, net.IP{0, 0, 0, 0}, stub, config)

	testcases := []TokenTestCase{
		{&Token{tMX, qPlus, "matching.com"}, Pass, true},
		{&Token{tMX, qPlus, "matching.com/24"}, Pass, true},
		{&Token{tMX, qPlus, "matching.com/24/64"}, Pass, true},
		{&Token{tMX, qPlus, ""}, Pass, true},
		{&Token{tMX, qMinus, ""}, Fail, true},
		{&Token{tMX, qPlus, "idontexist"}, Pass, false},
		// Mind that the domain is matching.NET and we expect Parser
		// to not match results.
		{&Token{tMX, qPlus, "matching.net"}, Pass, false},
		{&Token{tMX, qPlus, "matching.net/24"}, Pass, false},
		{&Token{tMX, qPlus, "matching.net/24/64"}, Pass, false},
	}

	var match bool
	var result SPFResult

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

	/* helper functions */

	dns.HandleFunc(".", rootZone)
	defer dns.HandleRemove(".")

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
	mxMatchingCom := zone(hosts)
	dns.HandleFunc("matching.com.", mxMatchingCom)
	defer dns.HandleRemove("matching.com.")

	s, addr, err := runLocalUDPServer(localDNSAddr)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()
	config.Nameserver = addr
	/* ***************** */
	ip := net.IP{127, 0, 0, 1}
	domain := "matching.com"
	p := NewParser(domain, domain, ip, stub, config)

	testcases := []TokenTestCase{
		{&Token{tMX, qPlus, "matching.com"}, Pass, false},
		{&Token{tMX, qPlus, ""}, Pass, false},
		//TokenTestCase{&Token{tMX, qPlus, "google.com"}, Pass, false},
		{&Token{tMX, qPlus, "idontexist"}, Pass, false},
		{&Token{tMX, qMinus, "matching.com"}, Fail, false},
	}

	var match bool
	var result SPFResult

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

	/* helper functions */

	dns.HandleFunc(".", rootZone)
	defer dns.HandleRemove(".")

	dns.HandleFunc("matching.net.", zone(map[uint16][]string{
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
	defer dns.HandleRemove("matching.net.")

	s, addr, err := runLocalUDPServer(localDNSAddr)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()
	config.Nameserver = addr

	/*******************************/
	ips := []net.IP{
		{172, 100, 100, 1},
		{173, 20, 20, 1},
		{173, 20, 21, 1},
	}

	domain := "matching.net"
	p := NewParser(domain, domain, net.IP{0, 0, 0, 0}, stub, config)
	testcases := []TokenTestCase{
		{&Token{tInclude, qPlus, "_spf.matching.net"}, Pass, true},
		{&Token{tInclude, qMinus, "_spf.matching.net"}, Fail, true},
		{&Token{tInclude, qTilde, "_spf.matching.net"}, Softfail, true},
		{&Token{tInclude, qQuestionMark, "_spf.matching.net"}, Neutral, true},
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
func TestParseIncludeNegative(t *testing.T) {

	/* helper functions */

	dns.HandleFunc(".", rootZone)
	defer dns.HandleRemove(".")

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
	includeMatchingCom := zone(hosts)
	dns.HandleFunc("matching.net.", includeMatchingCom)
	defer dns.HandleRemove("matching.net.")

	s, addr, err := runLocalUDPServer(localDNSAddr)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()
	config.Nameserver = addr
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
	domain := "matching.net"
	p := NewParser(domain, domain, ip, stub, config)

	testcases := []TokenTestCase{
		{&Token{tInclude, qMinus, "_spf.matching.net"}, None, false},
		{&Token{tInclude, qPlus, "_spf.matching.net"}, None, false},
		{&Token{tInclude, qPlus, "_errspf.matching.net"}, None, false},
		{&Token{tInclude, qPlus, "nospf.matching.net"}, None, false},
		{&Token{tInclude, qPlus, "idontexist.matching.net"}, None, false},

		// empty input qualifier results in Permerror withour recursive calls
		{&Token{tInclude, qMinus, ""}, Permerror, true},
	}

	var match bool
	var result SPFResult

	for _, testcase := range testcases {

		for _, ip := range ips {
			p.IP = ip
			match, result, _ = p.parseInclude(testcase.Input)
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

	dns.HandleFunc(".", rootZone)
	defer dns.HandleRemove(".")

	hosts := make(map[uint16][]string)
	hosts[dns.TypeA] = []string{
		"positive.matching.net. 0 IN A 172.20.20.20",
		"positive.matching.net. 0 IN A 172.18.0.1",
		"positive.matching.net. 0 IN A 172.18.0.2",
	}
	dns.HandleFunc("positive.matching.net.", zone(hosts))
	defer dns.HandleRemove("positive.matching.net.")

	hosts = make(map[uint16][]string)
	hosts[dns.TypeA] = []string{
		"positive.matching.com. 0 IN A 172.20.20.20",
		"positive.matching.com. 0 IN A 172.18.0.1",
		"positive.matching.com. 0 IN A 172.18.0.2",
	}
	dns.HandleFunc("positive.matching.com.", zone(hosts))
	defer dns.HandleRemove("positive.matching.com.")
	s, addr, err := runLocalUDPServer(localDNSAddr)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()
	config.Nameserver = addr

	domain := "matching.com"
	p := NewParser(domain, domain, ip, stub, config)
	testcases := []TokenTestCase{
		{&Token{tExists, qPlus, "positive.matching.net"}, Pass, true},
		{&Token{tExists, qMinus, "positive.matching.net"}, Fail, true},
		{&Token{tExists, qMinus, "idontexist.matching.net"}, Fail, false},
		{&Token{tExists, qMinus, "idontexist.%{d}"}, Fail, false},
		{&Token{tExists, qTilde, "positive.%{d}"}, Softfail, true},
		{&Token{tExists, qTilde, "positive.%{d}"}, Softfail, true},
		{&Token{tExists, qTilde, ""}, Permerror, true},
		{&Token{tExists, qTilde, "invalidsyntax%{}"}, Permerror, true},
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

type ParseTestCase struct {
	Query  string
	IP     net.IP
	Result SPFResult
}

// TestParse tests whole Parser.Parse() method
func TestParse(t *testing.T) {

	dns.HandleFunc(".", rootZone)
	defer dns.HandleRemove(".")

	dns.HandleFunc("matching.com.", zone(map[uint16][]string{
		dns.TypeMX: {
			"matching.com. 0 in MX 5 matching.com.",
		},
		dns.TypeA: {
			"matching.com. 0 IN A 172.20.20.20",
			"matching.com. 0 IN A 172.18.0.1",
			"matching.com. 0 IN A 172.18.0.2",
		},
	}))
	defer dns.HandleRemove("matching.com.")

	dns.HandleFunc("matching.net.", zone(map[uint16][]string{
		dns.TypeMX: {
			"matching.net. 0 IN MX 5 matching.net.",
		},
		dns.TypeA: {
			"matching.net. 0 IN A 173.18.0.2",
			"matching.net. 0 IN A 173.20.20.20",
		},
	}))
	defer dns.HandleRemove("matching.net.")

	dns.HandleFunc("_spf.matching.net.", zone(map[uint16][]string{
		dns.TypeTXT: {
			"_spf.matching.net. 0 IN TXT \"v=spf1 a:positive.matching.net -a:negative.matching.net ~mx -all\"",
		},
	}))
	defer dns.HandleRemove("_spf.matching.net.")

	dns.HandleFunc("positive.matching.net.", zone(map[uint16][]string{
		dns.TypeA: {
			"positive.matching.net. 0 IN A 172.100.100.1",
			"positive.matching.net. 0 IN A 173.18.0.2",
			"positive.matching.net. 0 IN A 173.20.20.1",
			"positive.matching.net. 0 IN A 173.20.21.1",
		},
	}))
	defer dns.HandleRemove("positive.matching.net.")

	dns.HandleFunc("negative.matching.net.", zone(map[uint16][]string{
		dns.TypeA: {
			"negative.matching.net. 0 IN A 172.100.100.1",
			"negative.matching.net. 0 IN A 173.18.0.2",
			"negative.matching.net. 0 IN A 173.20.20.1",
			"negative.matching.net. 0 IN A 173.20.21.1",
		},
	}))
	defer dns.HandleRemove("negative.matching.net.")

	dns.HandleFunc("lb.matching.com.", zone(map[uint16][]string{
		dns.TypeA: {
			"lb.matching.com. 0 IN A 172.101.101.1",
		},
	}))
	defer dns.HandleRemove("lb.matching.com.")

	dns.HandleFunc("loop.matching.net.", zone(map[uint16][]string{
		dns.TypeTXT: {
			`loop.matching.net. 0 IN TXT "v=spf1 include:loop.matching.com -all"`,
		},
	}))
	defer dns.HandleRemove("loop.matching.net.")

	dns.HandleFunc("loop.matching.com.", zone(map[uint16][]string{
		dns.TypeTXT: {
			`loop.matching.com. 0 IN TXT "v=spf1 include:loop.matching.net -all"`,
		},
	}))
	defer dns.HandleRemove("loop.matching.com.")

	s, addr, err := runLocalUDPServer(localDNSAddr)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()
	config.Nameserver = addr
	domain := "matching.com"
	ParseTestCases := []ParseTestCase{
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
		// Test will return SPFResult Fail as 172.20.20.1 does not result
		// positively for domain _spf.matching.net
		{"v=spf1 ip4:127.0.0.1 +include:_spf.matching.net -all", net.IP{172, 20, 20, 1}, Fail},
		// Test will return SPFResult Pass as 172.100.100.1 is within
		// positive.matching.net A records, that are marked as +a:
		{"v=spf1 ip4:127.0.0.1 +include:_spf.matching.net -all", net.IP{172, 100, 100, 1}, Pass},
		// Test for syntax errors (include must have nonempty domain parameter)
		{"v=spf1 ip4:127.0.0.1 +include -all", net.IP{172, 100, 100, 1}, Permerror},
		{"v=spf1 ip4:127.0.0.1 ?include -all", net.IP{172, 100, 100, 1}, Permerror},
		// Include didn't match domain:yyz and underneath returned Temperror,
		// however parent Parse() execution path marked the result as not
		// matching and proceeded to next term
		{"v=spf1 +include:yyz -all", net.IP{172, 100, 100, 1}, Fail},
		{"v=spf1 ?exists:lb.%{d} -all", ip, Neutral},
		// domain is set to matching.com, macro >>d1r<< will reverse domain to
		// >>com.matching<< and trim to first part counting from right,
		// effectively returning >>matching<<, which we later concatenate with
		// the >>.com<< suffix. This test should give same matching result as
		// the test above, as effectively the host to be queried is identical.
		{"v=spf1 ?exists:lb.%{d1r}.com -all", ip, Neutral},
		// Loop
		{"v=spf1 include:loop.matching.com -all", net.IP{10, 0, 0, 1}, Permerror},
	}

	for _, testcase := range ParseTestCases {
		done := make(chan struct{})
		go func() {
			p := NewParser(domain, domain, testcase.IP, testcase.Query, config)
			result, _, err := p.Parse()
			if result != Permerror && result != Temperror && err != nil {
				t.Errorf("%q Unexpected error while parsing: %s", testcase.Query, err)
			}
			if result != testcase.Result {
				t.Errorf("%q Expected %v, got %v", testcase.Query, testcase.Result, result)
			}
			close(done)
		}()
		select {
		case <-done:
			continue
		case <-time.After(time.Second):
			t.Errorf("%q failed due to timeout", testcase.Query)
		}
	}
}

// TestParseRedirect tests whole parsing behavior with a special testing of
// redirect modifier
func TestHandleRedirect(t *testing.T) {

	dns.HandleFunc(".", rootZone)
	defer dns.HandleRemove(".")

	dns.HandleFunc("matching.net.", zone(map[uint16][]string{
		dns.TypeMX: {
			"matching.net. 0 IN MX 5 matching.net.",
		},
		dns.TypeA: {
			"matching.net. 0 IN A 173.18.0.2",
			"matching.net. 0 IN A 173.20.20.20",
		},
	}))
	defer dns.HandleRemove("matching.net.")

	dns.HandleFunc("_spf.matching.net.", zone(map[uint16][]string{
		dns.TypeTXT: {
			"_spf.matching.net. 0 IN TXT \"v=spf1 a:positive.matching.net -a:negative.matching.net ~mx -all\"",
		},
	}))
	defer dns.HandleRemove("_spf.matching.net.")

	dns.HandleFunc("nospf.matching.net.", zone(map[uint16][]string{
		dns.TypeTXT: {
			"nospf.matching.net. 0 IN TXT \"no spf here\"",
		},
	}))
	defer dns.HandleRemove("nospf.matching.net.")

	dns.HandleFunc("positive.matching.net.", zone(map[uint16][]string{
		dns.TypeA: {
			"positive.matching.net. 0 IN A 172.100.100.1",
			"positive.matching.net. 0 IN A 173.18.0.2",
			"positive.matching.net. 0 IN A 173.20.20.1",
			"positive.matching.net. 0 IN A 173.20.21.1",
		},
	}))
	defer dns.HandleRemove("positive.matching.net.")

	dns.HandleFunc("negative.matching.net.", zone(map[uint16][]string{
		dns.TypeA: {
			"negative.matching.net. 0 IN A 172.100.100.1",
			"negative.matching.net. 0 IN A 173.18.0.2",
			"negative.matching.net. 0 IN A 173.20.20.1",
			"negative.matching.net. 0 IN A 173.20.21.1",
		},
	}))
	defer dns.HandleRemove("negative.matching.net.")

	dns.HandleFunc("redirect.matching.net.", zone(map[uint16][]string{
		dns.TypeTXT: {
			"redirect.matching.net. 0 IN TXT \"v=spf1 redirect=matching.com\"",
		},
	}))
	defer dns.HandleRemove("redirect.matching.net.")

	dns.HandleFunc("redirect.matching.com.", zone(map[uint16][]string{
		dns.TypeTXT: {
			"redirect.matching.com. 0 IN TXT \"v=spf1 redirect=redirect.matching.net\"",
		},
	}))
	defer dns.HandleRemove("redirect.matching.com.")

	dns.HandleFunc("matching.com.", zone(map[uint16][]string{
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
	defer dns.HandleRemove("matching.com.")

	s, addr, err := runLocalUDPServer(localDNSAddr)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()
	config.Nameserver = addr

	const domain = "matching.com"
	ParseTestCases := []ParseTestCase{
		/*
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
		*/
		// Ensure recursive redirects work
		{"v=spf1 redirect=redirect.matching.com", net.IP{172, 18, 0, 2}, Pass},
		//{"v=spf1 redirect=redirect.matching.com", net.IP{127, 0, 0, 1}, Fail},
	}

	for _, testcase := range ParseTestCases {
		p := NewParser(domain, domain, testcase.IP, testcase.Query, config)
		result, _, _ := p.Parse()
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
	const domain = "matching.com"
	// static.exp.matching.com.        IN      TXT "Invalid SPF record"
	// ip.exp.matching.com.            IN      TXT "%{i} is not one of %{d}'s designated mail servers."
	// redirect.exp.matching.com.      IN      TXT "See http://%{d}/why.html?s=%{s}&i=%{i}"

	dns.HandleFunc(".", rootZone)
	defer dns.HandleRemove(".")

	hosts := make(map[uint16][]string)
	hosts[dns.TypeTXT] = []string{
		"static.exp.matching.com. 0 IN TXT \"Invalid SPF record\"",
	}
	dns.HandleFunc("static.exp.matching.com.", zone(hosts))
	defer dns.HandleRemove("static.exp.matching.com.")

	hosts = make(map[uint16][]string)
	hosts[dns.TypeTXT] = []string{
		"ip.exp.matching.com. 0 in TXT \"%{i} is not one of %{d}'s designated mail servers.\"",
	}
	dns.HandleFunc("ip.exp.matching.com.", zone(hosts))
	defer dns.HandleRemove("ip.exp.matching.com.")

	s, addr, err := runLocalUDPServer(localDNSAddr)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()
	config.Nameserver = addr

	ExpTestCases := []ExpTestCase{
		{"v=spf1 -all exp=static.exp.matching.com",
			"Invalid SPF record"},
		{"v=spf1 -all exp=ip.exp.matching.com",
			"127.0.0.1 is not one of matching.com's designated mail servers."},
		// TODO(zaccone): Cover this testcase
		//ExpTestCase{"v=spf1 -all exp=redirect.exp.matching.com",
		//ExpT"See http://matching.com/why.html?s=&i="},
	}

	for _, testcase := range ExpTestCases {

		p := NewParser(domain, domain, ip, testcase.Query, config)
		_, exp, err := p.Parse()
		if err != nil {
			t.Error("Unexpected error while parsing: ", err)
		} else if exp != testcase.Explanation {
			t.Errorf("Explanation mismatch, expected %s, got %s\n",
				testcase.Explanation, exp)
		}
	}
}
