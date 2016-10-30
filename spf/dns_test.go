package spf

import "testing"

type spfTestpair struct {
	query    []string
	expected bool
}

func TestSPFValidator(t *testing.T) {
	queries := []spfTestpair{
		{[]string{"v=spf1"}, true},
		{[]string{"v=spf1 "}, true},
		{[]string{"v=spf10"}, false},
		{[]string{"v=spf11 "}, false},
		{[]string{"v=spf1 mx -all"}, true},
		{[]string{"v=spf1", "mx", "-all"}, true},
		{[]string{"random string"}, false},
	}

	for _, testcase := range queries {
		result := checkSPFVersion(testcase.query)
		if result != testcase.expected {
			t.Error(
				"Query: ", testcase.query, "got",
				result, "instead of", testcase.expected)
		}
	}
}

type SPFTestCase struct {
	Host string
	Txt  []string
}

//TestSPFLookup ensures a TXT records are properly queried and reurned to the called. Function should also work with
// multiple TXT records for a given host.
/*
func TestSPFLookup(t *testing.T) {
	testcases := []SPFTestCase{
		SPFTestCase{"multi.spf.matching.com", []string{"v=spf1 ip6:2001:db8:a0b:12f0::1 -all", "v=spf1 mx -all"}},
		SPFTestCase{"1.spf.matching.com", []string{"v=spf1 a mx -all"}},
		SPFTestCase{"2.spf.matching.com", []string{"v=spf1 ip4:172.100.100.100 -all"}},
		SPFTestCase{"3.spf.matching.com", []string{"v=spf1 ip4:172.100.100.1/24 ?all"}},
	}

	for _, testcase := range testcases {
		lookup, err := LookupSPF(testcase.Host)
		// There is no guarantee in which order TXT records will be returned for a given host, so we need to sort here
		// in order to ensure the expected ordering will be provided (expected is sorted here)
		sort.Strings(lookup)
		if err != nil {
			t.Error("Caught error: ", err)
		} else if reflect.DeepEqual(testcase.Txt, lookup) == false {
			t.Error("Host: ", testcase.Host, " expected: ", testcase.Txt, " got: ", lookup)
		}
	}
}

func TestSPFLookupNegative(t *testing.T) {
	testcase := SPFTestCase{"incorrect.spf.matching.com", nil}

	spfPrefix := "Invalid SPF record:"
	_, err := LookupSPF(testcase.Host)
	if strings.HasPrefix(err.Error(), spfPrefix) == false {
		t.Error("Expected error to start with: ", spfPrefix, " got: ", err.Error(), " instead.")
	}
}

func TestHandleNoSuchHostDNSError(t *testing.T) {
	host := "idontexist.matching.com"
	_, err := LookupSPF(host)
	switch err.(type) {
	case *net.DNSError:
		break
	default:
		t.Errorf("Expected 'net.DNSError' error type, instead got:  %T\n", err)
	}
}
*/
// DNS domain name validation.
// This source code is copied from:
//https://github.com/golang/go/blob/master/src/net/dnsclient_test.go

type dnsNameTest struct {
	name   string
	result bool
}

var dnsNameTests = []dnsNameTest{
	// RFC 2181, section 11.
	{"_xmpp-server._tcp.google.com", true},
	{"foo.com", true},
	{"1foo.com", true},
	{"26.0.0.73.com", true},
	{"fo-o.com", true},
	{"fo1o.com", true},
	{"foo1.com", true},
	{"a.b..com", false},
	{"a.b-.com", false},
	{"a.b.com-", false},
	{"a.b..", false},
	{"b.com.", true},
}

func emitDNSNameTest(ch chan<- dnsNameTest) {
	defer close(ch)
	var char59 = ""
	var char63 = ""
	var char64 = ""
	for i := 0; i < 59; i++ {
		char59 += "a"
	}
	char63 = char59 + "aaaa"
	char64 = char63 + "a"

	for _, tc := range dnsNameTests {
		ch <- tc
	}

	ch <- dnsNameTest{char63 + ".com", true}
	ch <- dnsNameTest{char64 + ".com", false}
	// 255 char name is fine:
	ch <- dnsNameTest{char59 + "." + char63 + "." + char63 + "." +
		char63 + ".com",
		true}
	// 256 char name is bad:
	ch <- dnsNameTest{char59 + "a." + char63 + "." + char63 + "." +
		char63 + ".com",
		false}
}

func TestDNSName(t *testing.T) {
	ch := make(chan dnsNameTest)
	go emitDNSNameTest(ch)
	for tc := range ch {
		if IsDomainName(tc.name) != tc.result {
			t.Errorf("IsDomainName(%q) = %v; want %v", tc.name, !tc.result, tc.result)
		}
	}
}
