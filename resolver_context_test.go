package spf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var _ ContextResolver = (*DNSResolver)(nil)
var _ ContextResolver = (*ServerResolver)(nil)

// A free TCP port may already be occupied by UDP. Keep both sockets reserved
// once a pair succeeds, and release the TCP listener before retrying a collision.
func listenDualDNS(listenPacket func(string, string) (net.PacketConn, error)) (net.Listener, net.PacketConn, error) {
	var err error
	for attempt := 0; attempt < 32; attempt++ {
		listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
		if listenErr != nil {
			return nil, nil, listenErr
		}
		var packet net.PacketConn
		packet, err = listenPacket("udp", listener.Addr().String())
		if err == nil {
			return listener, packet, nil
		}
		listener.Close()
		// Windows returns Winsock WSAEADDRINUSE (10048), not the synthetic
		// POSIX EADDRINUSE constant provided by its syscall package.
		addressInUse := errors.Is(err, syscall.EADDRINUSE) ||
			(runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(10048)))
		if !addressInUse {
			return nil, nil, err
		}
	}
	return nil, nil, fmt.Errorf("reserving a TCP/UDP DNS port after 32 attempts: %w", err)
}

func TestListenDualDNSPortCollision(t *testing.T) {
	attempts := 0
	var firstAddress string
	listener, packet, err := listenDualDNS(func(network, address string) (net.PacketConn, error) {
		attempts++
		if attempts == 1 {
			firstAddress = address
			occupied, err := net.ListenPacket(network, address)
			if err != nil {
				return nil, err
			}
			defer occupied.Close()
			return net.ListenPacket(network, address)
		}
		return net.ListenPacket(network, address)
	})
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
	packet.Close()
	if attempts < 2 {
		t.Fatal("did not retry the UDP port collision")
	}
	// The unsuccessful attempt must not leak its TCP listener.
	reopened, err := net.Listen("tcp", firstAddress)
	if err != nil {
		t.Fatalf("first TCP listener was not released: %v", err)
	}
	reopened.Close()
}

func TestListenDualDNSFailure(t *testing.T) {
	for _, test := range []struct {
		name     string
		cause    error
		attempts int
	}{
		{"collision limit", syscall.EADDRINUSE, 32},
		{"other error", errors.New("not a port collision"), 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			attempts := 0
			listener, packet, err := listenDualDNS(func(string, string) (net.PacketConn, error) {
				attempts++
				return nil, &net.OpError{Op: "listen", Net: "udp", Err: test.cause}
			})
			if listener != nil || packet != nil || !errors.Is(err, test.cause) || attempts != test.attempts {
				t.Fatalf("listener=%v packet=%v err=%v attempts=%d", listener, packet, err, attempts)
			}
		})
	}
}

// Both transports share one port so truncated UDP can retry against TCP.
func startDualDNS(t *testing.T, handler dns.Handler) string {
	t.Helper()
	listener, packet, err := listenDualDNS(net.ListenPacket)
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range []*dns.Server{{Listener: listener, Handler: handler}, {PacketConn: packet, Handler: handler}} {
		ready := make(chan struct{})
		done := make(chan error, 1)
		server.NotifyStartedFunc = func() { close(ready) }
		go func() { done <- server.ActivateAndServe() }()
		select {
		case <-ready:
		case err := <-done:
			t.Fatalf("DNS startup: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("DNS startup timeout")
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := server.ShutdownContext(ctx); err != nil {
				t.Error(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-ctx.Done():
				t.Error("DNS shutdown timeout")
			}
		})
	}
	return listener.Addr().String()
}

func contextBackend(t *testing.T, backend, addr string) ContextResolver {
	t.Helper()
	if backend == "server" {
		r, err := NewServerResolver(addr)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// Tests using the global system resolver deliberately do not run in parallel.
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}
	t.Cleanup(func() { net.DefaultResolver = original })
	return &DNSResolver{}
}

func TestContextDNSBackends(t *testing.T) {
	for _, backend := range []string{"server", "standard"} {
		t.Run(backend, func(t *testing.T) {
			var mu sync.Mutex
			queried := []string{}
			handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
				question := q.Question[0]
				name := question.Name
				mu.Lock()
				queried = append(queried, name+" "+dns.TypeToString[question.Qtype])
				mu.Unlock()
				reply := new(dns.Msg)
				reply.SetReply(q)
				reply.Authoritative = true
				var records []string
				switch {
				case name == "nx.test.":
					reply.Rcode = dns.RcodeNameError
				case name == "fail.test.":
					reply.Rcode = dns.RcodeServerFailure
				case name == "txt.test." && question.Qtype == dns.TypeTXT:
					records = []string{`txt.test. 0 IN TXT "v=spf1 " "-all"`, `txt.test. 0 IN TXT "other"`}
				case name == "mx.test." && question.Qtype == dns.TypeMX:
					records = []string{"mx.test. 0 IN MX 10 a.test."}
				case name == "1.2.0.192.in-addr.arpa." && question.Qtype == dns.TypePTR:
					records = []string{"1.2.0.192.in-addr.arpa. 0 IN PTR a.test."}
				case name == "a.test." && question.Qtype == dns.TypeA:
					records = []string{"a.test. 0 IN A 192.0.2.1"}
				case name == "a.test." && question.Qtype == dns.TypeAAAA:
					records = []string{"a.test. 0 IN AAAA 2001:db8::1"}
				case name == "aaaa.test." && question.Qtype == dns.TypeAAAA:
					records = []string{"aaaa.test. 0 IN AAAA 2001:db8::1"}
				case name == "alias.test.":
					records = []string{"alias.test. 0 IN CNAME a.test."}
					if question.Qtype == dns.TypeA {
						records = append(records, "a.test. 0 IN A 192.0.2.1")
					}
				case name == "cname-only.test.":
					records = []string{"cname-only.test. 0 IN CNAME empty.test."}
				}
				for _, text := range records {
					rr, err := dns.NewRR(text)
					if err != nil {
						t.Error(err)
						continue
					}
					reply.Answer = append(reply.Answer, rr)
				}
				writeDNSResponse(t, w, reply)
			})
			r := contextBackend(t, backend, startDualDNS(t, handler))
			ctx := context.Background()
			records, err := r.LookupTXTContext(ctx, "txt.test.")
			if err != nil || !reflect.DeepEqual(records, []string{"v=spf1 -all", "other"}) {
				t.Fatalf("TXT=%v, %v", records, err)
			}
			mxs, err := r.LookupMXContext(ctx, "mx.test.")
			if err != nil || len(mxs) != 1 || mxs[0].Host != "a.test." {
				t.Fatalf("MX=%v, %v", mxs, err)
			}
			ptrs, err := r.LookupAddrContext(ctx, "192.0.2.1")
			if err != nil || !reflect.DeepEqual(ptrs, []string{"a.test."}) {
				t.Fatalf("PTR=%v, %v", ptrs, err)
			}
			for _, family := range []string{"ip4", "ip6"} {
				mu.Lock()
				queried = nil
				mu.Unlock()
				ips, err := r.LookupIPContext(ctx, family, "a.test.")
				if err != nil || len(ips) != 1 {
					t.Fatalf("%s: %v %v", family, ips, err)
				}
				wantType := "A"
				if family == "ip6" {
					wantType = "AAAA"
				}
				mu.Lock()
				calls := append([]string(nil), queried...)
				mu.Unlock()
				if !reflect.DeepEqual(calls, []string{"a.test. " + wantType}) {
					t.Fatalf("same-family lookup: %v", calls)
				}
			}
			ips, err := r.LookupIPContext(ctx, "ip4", "alias.test.")
			if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("192.0.2.1")) {
				t.Fatalf("alias %v %v", ips, err)
			}
			for _, name := range []string{"empty.test.", "aaaa.test.", "cname-only.test.", "nx.test."} {
				ips, err := r.LookupIPContext(ctx, "ip4", name)
				if len(ips) != 0 || (err != nil && !dnsNotFound(err)) {
					t.Fatalf("%s falsely exists: %v %v", name, ips, err)
				}
				found, err := r.(Resolver).Exists(name)
				if found || err != nil {
					t.Fatalf("legacy exists %s: %v %v", name, found, err)
				}
			}
			_, err = r.LookupTXTContext(ctx, "nx.test.")
			var de *net.DNSError
			if !errors.Is(err, ErrDNSPermerror) || !errors.As(err, &de) || !de.IsNotFound {
				t.Fatalf("lost NXDOMAIN cause: %v", err)
			}
			_, err = r.LookupTXTContext(ctx, "fail.test.")
			if !errors.Is(err, ErrDNSTemperror) || !errors.As(err, &de) {
				t.Fatalf("lost server failure cause: %v", err)
			}
		})
	}
}

func TestContextDNSTCPFallback(t *testing.T) {
	for _, backend := range []string{"server", "standard"} {
		t.Run(backend, func(t *testing.T) {
			var mu sync.Mutex
			udp, tcp := 0, 0
			addr := startDualDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
				response := new(dns.Msg)
				response.SetReply(q)
				mu.Lock()
				if strings.HasPrefix(w.RemoteAddr().Network(), "udp") {
					udp++
					response.Truncated = true
				} else {
					tcp++
					rr, _ := dns.NewRR(`fallback.test. 0 IN TXT "v=spf1 " "-all"`)
					response.Answer = []dns.RR{rr}
				}
				mu.Unlock()
				writeDNSResponse(t, w, response)
			}))
			records, err := contextBackend(t, backend, addr).LookupTXTContext(context.Background(), "fallback.test.")
			if err != nil || !reflect.DeepEqual(records, []string{"v=spf1 -all"}) {
				t.Fatalf("%v %v", records, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if udp != 1 || tcp != 1 {
				t.Fatalf("UDP=%d TCP=%d", udp, tcp)
			}
		})
	}
}

func TestContextDNSCancellation(t *testing.T) {
	for _, backend := range []string{"server", "standard"} {
		for _, deadline := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/deadline=%v", backend, deadline), func(t *testing.T) {
				received := make(chan struct{}, 1)
				addr := startDualDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
					select {
					case received <- struct{}{}:
					default:
					}
				}))
				r := contextBackend(t, backend, addr)
				ctx, cancel := context.WithCancel(context.Background())
				if deadline {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
				}
				defer cancel()
				done := make(chan error, 1)
				go func() { _, err := r.LookupTXTContext(ctx, "cancel.test."); done <- err }()
				select {
				case <-received:
				case <-time.After(time.Second):
					t.Fatal("no DNS dispatch")
				}
				if !deadline {
					cancel()
				}
				select {
				case err := <-done:
					cause := context.Canceled
					if deadline {
						cause = context.DeadlineExceeded
					}
					if !errors.Is(err, cause) || !errors.Is(err, ErrDNSTemperror) {
						t.Fatalf("lost cancellation cause: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("cancellation did not interrupt the lookup")
				}
			})
		}
	}
}

func TestServerAliasBounds(t *testing.T) {
	for _, test := range []string{"cycle", "chain10", "chain11", "unrelated", "packet10", "packet11"} {
		t.Run(test, func(t *testing.T) {
			var mu sync.Mutex
			calls := 0
			addr := startDualDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
				mu.Lock()
				calls++
				mu.Unlock()
				response := new(dns.Msg)
				response.SetReply(q)
				add := func(text string) {
					rr, err := dns.NewRR(text)
					if err != nil {
						t.Error(err)
						return
					}
					response.Answer = append(response.Answer, rr)
				}
				name := q.Question[0].Name
				switch test {
				case "cycle":
					add(name + " 0 IN CNAME " + name)
				case "unrelated":
					add("other.test. 0 IN A 192.0.2.1")
				default:
					limit := 10
					if strings.HasSuffix(test, "11") {
						limit = 11
					}
					if strings.HasPrefix(test, "packet") {
						for i := 0; i < limit; i++ {
							add(fmt.Sprintf("hop%d.test. 0 IN CNAME hop%d.test.", i, i+1))
						}
						add(fmt.Sprintf("hop%d.test. 0 IN A 192.0.2.1", limit))
					} else {
						var hop int
						fmt.Sscanf(name, "hop%d.test.", &hop)
						if hop == limit {
							add(name + " 0 IN A 192.0.2.1")
						} else {
							add(fmt.Sprintf("%s 0 IN CNAME hop%d.test.", name, hop+1))
						}
					}
				}
				writeDNSResponse(t, w, response)
			}))
			r := contextBackend(t, "server", addr)
			ips, err := r.LookupIPContext(context.Background(), "ip4", "hop0.test.")
			if test == "chain10" || test == "packet10" {
				if err != nil || len(ips) != 1 {
					t.Fatalf("%v %v", ips, err)
				}
			} else if test == "unrelated" {
				if err != nil || len(ips) != 0 {
					t.Fatalf("unrelated address accepted: %v %v", ips, err)
				}
			} else if !errors.Is(err, ErrDNSTemperror) {
				t.Fatalf("unbounded alias accepted: %v %v", ips, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if calls > 11 {
				t.Fatalf("dispatched %d queries", calls)
			}
		})
	}
}

func TestContextDNSTransportCause(t *testing.T) {
	for _, backend := range []string{"server", "standard"} {
		t.Run(backend, func(t *testing.T) {
			// A local TCP server rejects a DNS stream before sending a response.
			addr := startDualDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
				if strings.HasPrefix(w.RemoteAddr().Network(), "tcp") {
					w.Close()
					return
				}
				response := new(dns.Msg)
				response.SetReply(q)
				response.Truncated = true
				writeDNSResponse(t, w, response)
			}))
			_, err := contextBackend(t, backend, addr).LookupTXTContext(context.Background(), "transport.test.")
			if !errors.Is(err, ErrDNSTemperror) {
				t.Fatalf("%v", err)
			}
			// ServerResolver retains EOF directly; net exposes its structured DNSError wrapper.
			if backend == "standard" {
				var de *net.DNSError
				if !errors.As(err, &de) {
					t.Fatalf("lost DNS cause: %v", err)
				}
			} else if !errors.Is(err, io.EOF) {
				t.Fatalf("lost transport cause: %v", err)
			}
		})
	}
}
