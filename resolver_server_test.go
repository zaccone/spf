package spf

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestServerPTRCandidateLimit(t *testing.T) {
	for _, mechanism := range []string{"ptr", "exists:%{p}.check.test"} {
		for _, tc := range []struct {
			name     string
			extra    string
			matching int
			want     Result
		}{
			{"ten candidates", "", 9, Pass},
			{"unrepresentable eleventh candidate", `embedded\.dot.example.test.`, 9, Pass},
			{"matching eleventh candidate", "mail10.example.test.", 10, Fail},
		} {
			t.Run(mechanism+"/"+tc.name, func(t *testing.T) {
				client := net.ParseIP("192.0.2.1")
				matching := fmt.Sprintf("mail%d.example.test.", tc.matching)
				addr := startDualDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
					reply := new(dns.Msg)
					reply.SetReply(q)
					reply.Compress = true
					question := q.Question[0]
					header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET}
					switch question.Qtype {
					case dns.TypeTXT:
						reply.Answer = []dns.RR{&dns.TXT{Hdr: header, Txt: []string{"v=spf1 " + mechanism + " -all"}}}
					case dns.TypePTR:
						for i := 0; i < 10; i++ {
							reply.Answer = append(reply.Answer, &dns.PTR{Hdr: header, Ptr: fmt.Sprintf("mail%d.example.test.", i)})
						}
						if tc.extra != "" {
							reply.Answer = append(reply.Answer, &dns.PTR{Hdr: header, Ptr: tc.extra})
						}
					case dns.TypeA:
						if question.Name == "mail10.example.test." {
							t.Error("queried the eleventh PTR candidate")
						}
						ip := net.ParseIP("192.0.2.2")
						if question.Name == matching || question.Name == matching+"check.test." {
							ip = client
						} else if question.Name == "unknown.check.test." {
							break
						}
						reply.Answer = []dns.RR{&dns.A{Hdr: header, A: ip}}
					}
					if err := w.WriteMsg(reply); err != nil {
						t.Error(err)
					}
				}))
				result, _, err := CheckHostWithOptions(context.Background(), client, "example.test", "", Options{Resolver: contextBackend(t, "server", addr)})
				if result != tc.want || err != nil {
					t.Fatalf("got %v, %v; want %v", result, err, tc.want)
				}
			})
		}
	}
}

func TestServerResolver(t *testing.T) {
	_, e := NewServerResolver("8.8.8.8") // invalid TCP address, no port specified
	if e == nil {
		t.Errorf(`want "address 8.8.8.8: missing port in address"`)
	}
}

func TestServerResolver_LookupTXTStrict_Multiline(t *testing.T) {
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

func TestServerResolver_LookupTXT_Multiline(t *testing.T) {
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
