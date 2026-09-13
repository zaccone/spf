package spf

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestRecursiveLiteralDomain(t *testing.T) {
	for _, policy := range []string{"include:%{l}.child.test -all", "redirect=%{l}.child.test"} {
		r := &contextFixture{txt: func(_ context.Context, name string) ([]string, error) {
			switch name {
			case "example.test.":
				return []string{"v=spf1 " + policy}, nil
			case "percent%.child.test.":
				return []string{"v=spf1 a -all"}, nil
			default:
				t.Fatalf("name was expanded twice: %q", name)
				return nil, nil
			}
		}, ip: func(_ context.Context, network, name string) ([]net.IP, error) {
			if network != "ip4" || name != "percent%.child.test." {
				t.Fatalf("unexpected address query %s %q", network, name)
			}
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		}}
		got, _, err := CheckHostWithOptions(context.Background(), net.ParseIP("192.0.2.1"), "example.test", "percent%@example.test", Options{Resolver: r})
		if got != Pass || err != nil {
			t.Fatalf("%s: %v %v", policy, got, err)
		}
	}
}

func TestMiekgLiteralDNSLabels(t *testing.T) {
	for _, name := range []string{"foo:bar/baz.example.test", "macro%percent  space%20url.example.test", `literal\032.example.test`, `semi;quote".example.test`, "-leading.example.test"} {
		t.Run(name, func(t *testing.T) {
			addr := startDualDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
				question := q.Question[0]
				// Examine wire labels independently of the production conversion helper.
				wire := make([]byte, 255)
				end, err := dns.PackDomainName(question.Name, wire, 0, nil, false)
				if err != nil {
					t.Error(err)
					return
				}
				var labels []string
				for pos := 0; pos < end && wire[pos] != 0; {
					n := int(wire[pos])
					pos++
					labels = append(labels, string(wire[pos:pos+n]))
					pos += n
				}
				if strings.Join(labels, ".") != name {
					t.Errorf("changed DNS label: %q", labels)
				}
				reply := new(dns.Msg)
				reply.SetReply(q)
				reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
				if err := w.WriteMsg(reply); err != nil {
					t.Error(err)
				}
			}))
			resolver, err := NewMiekgDNSResolverContext(addr)
			if err != nil {
				t.Fatal(err)
			}
			ips, err := resolver.LookupIPContext(context.Background(), "ip4", name+".")
			if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("192.0.2.1")) {
				t.Fatalf("%v %v", ips, err)
			}
		})
	}
}

func TestSystemResolverUtilityLabelLimit(t *testing.T) {
	// Go's net.Resolver rejects non-hostname labels before dialing. Keep this
	// limitation visible rather than attributing fixture-level corpus coverage
	// to the system backend. miekg supports these labels (tested above).
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{Dial: func(context.Context, string, string) (net.Conn, error) {
		t.Error("unexpected DNS dispatch")
		return nil, errors.New("unexpected dial")
	}}
	t.Cleanup(func() { net.DefaultResolver = original })
	for _, name := range []string{"foo:bar/baz.example.test.", "space label.example.test."} {
		_, err := (&DNSResolver{}).LookupIPContext(context.Background(), "ip4", name)
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
			t.Fatalf("%q: %v", name, err)
		}
	}
}

func TestDNSLiteralNameCannotForgeBoundary(t *testing.T) {
	if _, err := dnsLiteralName(`attacker\.example.test.`); !errors.Is(err, ErrInvalidDomain) {
		t.Fatalf("embedded label dot accepted: %v", err)
	}
	got, err := dnsLiteralName(`literal\\032.example.test.`)
	if err != nil || got != `literal\032.example.test.` {
		t.Fatalf("%q %v", got, err)
	}
}

func FuzzDNSLiteralNames(f *testing.F) {
	for _, name := range []string{"example.test.", "space label.example", `literal\032.example`, `embedded\.dot.example`, "", ".", "bad..test"} {
		f.Add(name)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if len(name) > 4096 {
			return
		}
		_, _ = dnsLiteralName(name)
		if name != "." && !validExpandedDomain(name) {
			return
		}
		presentation, err := dnsPresentationName(name)
		if err != nil {
			t.Fatal(err)
		}
		literal, err := dnsLiteralName(presentation)
		if err != nil || literal != NormalizeFQDN(name) {
			t.Fatalf("round trip %q -> %q -> %q (%v)", name, presentation, literal, err)
		}
	})
}
