package spf

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestLimitedResolver(t *testing.T) {
	dns.HandleFunc(".", rootZone)
	defer dns.HandleRemove(".")

	dns.HandleFunc("domain.", zone(map[uint16][]string{
		dns.TypeMX: {
			"domain. 0 in MX 5 domain.",
		},
		dns.TypeA: {
			"domain. 0 IN A 10.0.0.1",
		},
		dns.TypeTXT: {
			`domain. 0 IN TXT "ok"`,
		},
	}))
	defer dns.HandleRemove("domain.")

	s, err := runLocalUDPServer(localDNSAddr)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	{
		r := NewLimitedResolver(testResolver, 2)
		a, err := r.LookupTXT("domain.")
		if len(a) == 0 || err != nil {
			t.Error("1st LookupTXT")
		}
		a, err = r.LookupTXT("domain.")
		if len(a) != 0 || err != ErrDNSLimitExceeded {
			t.Error("2nd LookupTXT")
		}
	}
	{
		r := NewLimitedResolver(testResolver, 2)
		b, err := r.Exists("domain.")
		if !b || err != nil {
			t.Error("1st Exists")
		}
		b, err = r.Exists("domain.")
		if b || err != ErrDNSLimitExceeded {
			t.Error("2nd Exists")
		}
	}
	matcher := func(ip net.IP) bool {
		return ip.Equal(net.ParseIP("10.0.0.1"))
	}
	{
		r := NewLimitedResolver(testResolver, 2)
		b, err := r.MatchIP("domain.", matcher)
		if !b || err != nil {
			t.Error("1st MatchIP")
		}
		b, err = r.MatchIP("domain.", matcher)
		if b || err != ErrDNSLimitExceeded {
			t.Error("2nd MatchIP")
		}
	}
	{
		r := NewLimitedResolver(testResolver, 2)
		b, err := r.MatchMX("domain.", matcher)
		if !b || err != nil {
			t.Error("1st MatchMX")
		}
		b, err = r.MatchMX("domain.", matcher)
		if b || err != ErrDNSLimitExceeded {
			t.Error("2nd MatchMX")
		}
	}
}
