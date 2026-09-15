package spf

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestResolverMatcherLifecycle(t *testing.T) {
	stop := errors.New("stop matching")
	for _, backend := range []string{"server", "standard"} {
		t.Run(backend, func(t *testing.T) {
			mux, resolver := newTestDNS(t)
			mux.HandleFunc("example.test.", zone(t, map[uint16][]string{
				dns.TypeMX:   {"example.test. 0 IN MX 10 first.example.test.", "example.test. 0 IN MX 20 second.example.test."},
				dns.TypeA:    {"first.example.test. 0 IN A 192.0.2.1", "second.example.test. 0 IN A 192.0.2.2"},
				dns.TypeAAAA: {"first.example.test. 0 IN AAAA 2001:db8::1", "second.example.test. 0 IN AAAA 2001:db8::2"},
			}))
			if backend == "standard" {
				// These tests are intentionally not parallel: net.Lookup* uses this global.
				addr := resolver.(*ServerResolver).serverAddr
				original := net.DefaultResolver
				net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				}}
				t.Cleanup(func() { net.DefaultResolver = original })
				resolver = &DNSResolver{}
			}
			for _, operation := range []struct {
				name, host string
				lookup     func(string, IPMatcherFunc) (bool, error)
				total      int
			}{
				{"IP", "first.example.test.", resolver.MatchIP, 2},
				{"MX", "example.test.", resolver.MatchMX, 4},
			} {
				for _, outcome := range []struct {
					name  string
					match bool
					err   error
				}{{"no-match", false, nil}, {"match", true, nil}, {"error", false, stop}} {
					t.Run(operation.name+"/"+outcome.name, func(t *testing.T) {
						// Deliberately ordinary caller-owned state: concurrent or late callbacks
						// must fail under the race detector as well as the count assertions.
						calls := 0
						found, err := operation.lookup(operation.host, func(ip net.IP) (bool, error) {
							if ip == nil {
								t.Error("nil address")
							}
							calls++
							return outcome.match, outcome.err
						})
						if found != outcome.match || !errors.Is(err, outcome.err) {
							t.Fatalf("got (%v, %v), want (%v, %v)", found, err, outcome.match, outcome.err)
						}
						want := operation.total
						if outcome.match || outcome.err != nil {
							want = 1
						}
						if calls != want {
							t.Errorf("got %d matcher calls, want %d", calls, want)
						}
					})
				}
			}
		})
	}
}

func TestDNSFixtureQuestionMatching(t *testing.T) {
	mux, resolver := newTestDNS(t)
	mux.HandleFunc("example.test.", zone(t, map[uint16][]string{
		dns.TypeTXT: {`example.test. 0 IN TXT "parent"`, `example.test.child.example.test. 0 IN TXT "child"`},
		dns.TypeA:   {"example.test. 0 IN A 192.0.2.1"},
	}))
	for _, name := range []string{"example.test.", "EXAMPLE.TEST."} {
		records, err := resolver.LookupTXT(name)
		if err != nil || len(records) != 1 || records[0] != "parent" {
			t.Fatalf("%s: %v, %v", name, records, err)
		}
	}
}
