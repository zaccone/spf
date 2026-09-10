package spf

import (
	"testing"

	"github.com/miekg/dns"
)

func TestMiekgDNSResolver(t *testing.T) {
	_, e := NewMiekgDNSResolver("8.8.8.8") // invalid TCP address, no port specified
	if e == nil {
		t.Errorf(`want "address 8.8.8.8: missing port in address"`)
	}
}

func TestMiekgDNSResolver_LookupTXTStrict_Multiline(t *testing.T) {
	mux, testResolver := newTestDNS(t)
	mux.HandleFunc("multiline.test.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			`multiline.test. 0 IN TXT "v=spf1 ip4:10.0.0.1 ip4:10.0.0" ".2 -all"`,
		},
	}))

	r, e := testResolver.LookupTXTStrict("multiline.test.")

	if e != nil {
		t.Fatal(e)
	}

	if len(r) != 1 {
		t.Errorf("want 1 got %d", len(r))
	}
}

func TestMiekgDNSResolver_LookupTXT_Multiline(t *testing.T) {
	mux, testResolver := newTestDNS(t)
	mux.HandleFunc("multiline.test.", zone(t, map[uint16][]string{
		dns.TypeTXT: {
			`multiline.test. 0 IN TXT "v=spf1 ip4:10.0.0.1 ip4:10.0.0" ".2 -all"`,
		},
	}))

	r, e := testResolver.LookupTXT("multiline.test.")

	if e != nil {
		t.Fatal(e)
	}

	if len(r) != 1 {
		t.Errorf("want 1 got %d", len(r))
	}
}
