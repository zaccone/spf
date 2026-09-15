package spf

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func newTestDNS(t *testing.T) (*dns.ServeMux, Resolver) {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		response := new(dns.Msg)
		response.SetRcode(req, dns.RcodeNameError)
		writeDNSResponse(t, w, response)
	})
	addr := startTestDNS(t, mux)
	resolver, err := NewServerResolver(addr)
	if err != nil {
		t.Fatal(err)
	}
	return mux, resolver
}

func startTestDNS(t *testing.T, handler dns.Handler) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	done := make(chan error, 1)
	server := &dns.Server{
		PacketConn:        conn,
		Handler:           handler,
		ReadTimeout:       time.Second,
		WriteTimeout:      time.Second,
		NotifyStartedFunc: func() { close(started) },
	}
	go func() { done <- server.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-done:
		conn.Close()
		t.Fatalf("DNS server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		conn.Close()
		t.Fatal("DNS server startup timed out")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.ShutdownContext(ctx); err != nil {
			t.Errorf("DNS server shutdown: %v", err)
			conn.Close()
		}
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("DNS server: %v", err)
			}
		case <-ctx.Done():
			t.Error("DNS server did not exit")
		}
	})
	return conn.LocalAddr().String()
}

func writeDNSResponse(t *testing.T, w dns.ResponseWriter, response *dns.Msg) {
	t.Helper()
	if err := w.WriteMsg(response); err != nil {
		t.Errorf("writing DNS response: %v", err)
	}
}

func zone(t *testing.T, records map[uint16][]string) dns.HandlerFunc {
	t.Helper()
	var parsed []dns.RR
	for qtype, values := range records {
		for _, value := range values {
			rr, err := dns.NewRR(value)
			if err != nil {
				t.Fatalf("invalid DNS fixture %q: %v", value, err)
			}
			if rr.Header().Rrtype != qtype {
				t.Fatalf("DNS fixture %q has wrong record type", value)
			}
			parsed = append(parsed, rr)
		}
	}
	return func(w dns.ResponseWriter, req *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(req)
		if len(req.Question) != 1 {
			response.Rcode = dns.RcodeFormatError
		} else {
			question := req.Question[0]
			for _, rr := range parsed {
				h := rr.Header()
				if strings.EqualFold(h.Name, question.Name) && h.Rrtype == question.Qtype && h.Class == question.Qclass {
					response.Answer = append(response.Answer, dns.Copy(rr))
				}
			}
		}
		writeDNSResponse(t, w, response)
	}
}
