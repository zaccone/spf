package spf

import (
	"net"
	"testing"
)

// An in-memory resolver keeps syntax tests independent of DNS and counts any
// work beyond record selection. Embedded methods panic if unexpectedly used.
type syntaxResolver struct {
	Resolver
	records []string
	calls   int
	host    string
	address net.IP
}

func (r *syntaxResolver) LookupTXTStrict(string) ([]string, error) { return r.records, nil }
func (r *syntaxResolver) MatchIP(host string, match IPMatcherFunc) (bool, error) {
	r.calls++
	r.host = host
	return match(r.address)
}
func (r *syntaxResolver) MatchMX(host string, match IPMatcherFunc) (bool, error) {
	return r.MatchIP(host, match)
}

func TestCompleteRecordSyntax(t *testing.T) {
	invalid := []string{
		"ip4:garbage", "ip6:192.0.2.0/24", "ip4:2001:db8::1/32",
		"ip4:::ffff:192.0.2.1", "ip4:192.000.2.1", "ip4:256.0.0.1",
		"ip4:192.0.2.1/", "ip4:192.0.2.1/00", "ip4:192.0.2.1/033",
		"ip4:192.0.2.1/33", "ip4:192.0.2.1/+1", "ip6:2001:db8::1/129",
		"ip6:2001:db8::1/064", "ip6:2001:db8::1/", "ip6:fe80::1%eth0",
		"a/", "a//", "a/foo.com", "mx//foo.com", "a/24/64", "a/24/", "a/33", "mx//129", "mx//064",
		"a:/24", "mx://64", "a:example.com/00", "a:example.com/24///64",
		"++all", "-+all", "a+", "all:example.com", "include", "exists", "ip4",
		"+redirect=example.com", "~exp=example.com", "?x=value", "redirect:example.com",
		"redirect=", "exp=", "include:", "ptr:", "a:", "mx:", "unknown",
		"include:localhost", "a:example.123", "mx:example.-com", "ptr:example.c_m",
		"exists:%", "exists:%{z}.example.com", "exists:%{c}.example.com",
		"exp=%{randomstuff", "exp=%{d0}", "exp=%{r}", "exp=%{t}", "exists:%{d0}", "exists:%{d00}", "exists:%{d2rr}",
		"exists:%{d", "x=%q", "x=%{unknown}", "1x=value",
		"redirect=example.com REDIRECT=other.example", "exp=example.com EXP=other.example",
	}
	for _, tail := range invalid {
		for _, prefix := range []string{"v=spf1 +all ", "v=spf1 a "} {
			query := prefix + tail
			t.Run(query, func(t *testing.T) {
				r := &syntaxResolver{records: []string{query}, address: net.IP{192, 0, 2, 1}}
				result, explanation, err := CheckHostWithResolver(net.IP{192, 0, 2, 1}, "example.com", "sender@example.com", r)
				if result != Permerror || err == nil || explanation != "" {
					t.Fatalf("got (%v, %q, %v), want permerror", result, explanation, err)
				}
				if r.calls != 0 {
					t.Fatalf("performed %d mechanism lookups before syntax validation", r.calls)
				}
			})
		}
	}
	valid := []string{
		"V=SPF1 +ALL", "v=SpF1 IP4:192.0.2.1 -all", "v=spf1  +all   ",
		"v=spf1 x-test=value +all", "v=spf1 x= x=again +all", "v=spf1 include=anything +all",
		"v=spf1 explanation=ignored +all", "v=spf1 v=anything +all",
		"v=spf1 +all a/0//0 mx/32//128 ip4:0.0.0.0/0 ip6:::/0",
		"v=spf1 +all ip4:255.255.255.255/32 ip6:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
		"v=spf1 +all ip6:::ffff:192.0.2.1/128",
		"v=spf1 +all exists:%{ir}.%{l1r+-}._spf.%{d} ptr:%{p} a:%{D2R/}//64",
		"v=spf1 +all include:%{d} redirect=example.com. exp=explain._spf.%{d}",
		"v=spf1 +all x=%%-%_-%- x=%{s99999999999999999999999999} a:example.a-1",
	}
	for _, query := range valid {
		t.Run(query, func(t *testing.T) {
			r := &syntaxResolver{records: []string{query}}
			result, _, err := CheckHostWithResolver(net.IP{192, 0, 2, 1}, "example.com", "sender@example.com", r)
			if result != Pass || err != nil {
				t.Fatalf("got (%v, %v), want pass", result, err)
			}
		})
	}
}

func TestSPFVersionSelection(t *testing.T) {
	tests := []struct {
		records []string
		want    Result
	}{
		{[]string{"V=SPF1 -ALL"}, Fail},
		{[]string{"v=spf1"}, Neutral},
		{[]string{"v=spf10 +all", "V=SPF1 +all"}, Pass},
		{[]string{"v=spf1\t+all"}, None},
		{[]string{"v=spf1\n+all"}, None},
		{[]string{" v=spf1 +all"}, None},
		{[]string{"v=spf1 +all", "V=SPF1 -all"}, Permerror},
		{[]string{"v=spf1 +all\tip4:192.0.2.1"}, Permerror},
		{[]string{"v=spf1 +all \n"}, Permerror},
		{[]string{"v=spf1 +all \r"}, Permerror},
		{[]string{"v=spf1 +all \u00a0"}, Permerror},
	}
	for _, tt := range tests {
		t.Run(tt.records[0], func(t *testing.T) {
			r := &syntaxResolver{records: tt.records}
			got, _, err := CheckHostWithResolver(net.IP{192, 0, 2, 1}, "example.com", "sender@example.com", r)
			if got != tt.want || (got == Permerror && err == nil) {
				t.Fatalf("got (%v, %v), want %v", got, err, tt.want)
			}
		})
	}
}

func TestBareDualCIDREvaluation(t *testing.T) {
	tests := []struct {
		term, client string
		address      net.IP
		want         Result
	}{
		{"a/24", "192.0.2.1", net.IP{192, 0, 2, 200}, Pass},
		{"a/32", "192.0.2.1", net.IP{192, 0, 2, 200}, Fail},
		{"mx//64", "2001:db8::1", net.ParseIP("2001:db8::2"), Pass},
		{"mx//128", "2001:db8::1", net.ParseIP("2001:db8::2"), Fail},
		{"a/24//64", "2001:db8::1", net.ParseIP("2001:db8::2"), Pass},
	}
	for _, tt := range tests {
		t.Run(tt.term, func(t *testing.T) {
			r := &syntaxResolver{records: []string{"v=spf1 " + tt.term + " -all"}, address: tt.address}
			got, _, err := CheckHostWithResolver(net.ParseIP(tt.client), "example.com", "sender@example.com", r)
			if got != tt.want || err != nil || r.host != "example.com." || r.calls != 1 {
				t.Fatalf("got (%v, %v), host=%q calls=%d", got, err, r.host, r.calls)
			}
		})
	}
}

func TestIPMechanismFamilies(t *testing.T) {
	tests := []struct {
		term, client string
		want         Result
	}{
		{"ip6:::ffff:192.0.2.1", "192.0.2.1", Fail},
		{"ip6:::ffff:192.0.2.1/128", "192.0.2.1", Fail},
		{"ip4:0.0.0.0/0", "2001:db8::1", Fail},
		{"ip6:::/0", "192.0.2.1", Fail},
		{"ip6:::/0", "2001:db8::1", Pass},
		{"ip4:0.0.0.0/0", "192.0.2.1", Pass},
		{"ip6:2001:db8::1/128", "2001:db8::1", Pass},
		{"ip6:2001:db8::1/128", "2001:db8::2", Fail},
	}
	for _, tt := range tests {
		t.Run(tt.term+"/"+tt.client, func(t *testing.T) {
			r := &syntaxResolver{records: []string{"v=spf1 " + tt.term + " -all"}}
			got, _, err := CheckHostWithResolver(net.ParseIP(tt.client), "example.com", "sender@example.com", r)
			if got != tt.want || err != nil {
				t.Fatalf("got (%v, %v), want %v", got, err, tt.want)
			}
		})
	}
}
