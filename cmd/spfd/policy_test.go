package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	spf "github.com/zaccone/spf"
)

type fixtureResolver struct {
	policy  string
	entered chan string
	release <-chan struct{}
}

func (r fixtureResolver) LookupTXTContext(ctx context.Context, name string) ([]string, error) {
	if r.entered != nil {
		r.entered <- name
	}
	if r.release != nil {
		select {
		case <-r.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return []string{r.policy}, nil
}
func (fixtureResolver) LookupIPContext(context.Context, string, string) ([]net.IP, error) {
	panic("unexpected IP lookup")
}
func (fixtureResolver) LookupMXContext(context.Context, string) ([]*net.MX, error) {
	panic("unexpected MX lookup")
}
func (fixtureResolver) LookupAddrContext(context.Context, string) ([]string, error) {
	panic("unexpected PTR lookup")
}
func testServer(r spf.ContextResolver) *server {
	return &server{resolver: r, timeout: time.Second, ioTimeout: time.Second, grace: 50 * time.Millisecond, maxConnections: 4, slots: make(chan struct{}, 2), enforce: true, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}
func request() map[string]string {
	return map[string]string{"request": "smtpd_access_policy", "protocol_state": "RCPT", "sender": "sender@example.com", "client_address": "192.0.2.1", "helo_name": "helo.example.com"}
}

const wireRequest = "request=smtpd_access_policy\nprotocol_state=RCPT\nsender=sender@example.com\nclient_address=192.0.2.1\nhelo_name=helo.example.com\n\n"

func TestPolicyResults(t *testing.T) {
	for _, tc := range []struct{ policy, action string }{
		{"v=spf1 ip4:192.0.2.0/24 -all", "DUNNO"},
		{"v=spf1 -all", "550 5.7.23 SPF validation failed"},
		{"v=spf1 ~all", "DUNNO"},
		{"v=spf1 ?all", "DUNNO"},
		{"not SPF", "DUNNO"},
		{"v=spf1 invalid", "DUNNO"},
	} {
		t.Run(tc.policy, func(t *testing.T) {
			s := testServer(fixtureResolver{policy: tc.policy})
			if got := s.policy(context.Background(), request()); got != tc.action {
				t.Fatalf("got %q want %q", got, tc.action)
			}
			s.enforce = false
			if got := s.policy(context.Background(), request()); got != "DUNNO" {
				t.Fatalf("monitor mode: %q", got)
			}
		})
	}
}
func TestNullSenderAndInvalidRequests(t *testing.T) {
	for _, sender := range []string{"", "<>"} {
		entered := make(chan string, 1)
		s := testServer(fixtureResolver{policy: "v=spf1 +all", entered: entered})
		a := request()
		a["sender"] = sender
		if got := s.policy(context.Background(), a); got != "DUNNO" {
			t.Fatal(got)
		}
		if name := <-entered; name != "helo.example.com." {
			t.Fatal(name)
		}
	}
	for _, tc := range []struct {
		key, value string
		remove     bool
		want       string
	}{
		{"client_address", "bad", false, unavailable}, {"request", "other", false, unavailable},
		{"sender", "", true, unavailable}, {"sender", "malformed", false, unavailable},
		{"protocol_state", "", true, unavailable}, {"protocol_state", "DATA", false, "DUNNO"},
		{"sasl_username", "authenticated", false, "DUNNO"},
	} {
		entered := make(chan string, 1)
		s := testServer(fixtureResolver{policy: "v=spf1 -all", entered: entered})
		a := request()
		if tc.remove {
			delete(a, tc.key)
		} else {
			a[tc.key] = tc.value
		}
		if got := s.policy(context.Background(), a); got != tc.want {
			t.Fatalf("%s: %q", tc.key, got)
		}
		if len(entered) != 0 {
			t.Fatal("unexpected DNS call")
		}
	}
}
func TestNullSenderInvalidHELO(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		for _, sender := range []string{"", "<>"} {
			for _, helo := range []string{"[192.0.2.1]", "[IPv6:2001:db8::1]", "localhost", "bad..example.com"} {
				t.Run(fmt.Sprintf("enforce=%v/sender=%q/helo=%s", enforce, sender, helo), func(t *testing.T) {
					entered := make(chan string, 1)
					s := testServer(fixtureResolver{policy: "v=spf1 -all", entered: entered})
					s.enforce = enforce
					a := request()
					a["sender"], a["helo_name"] = sender, helo
					if got := s.policy(context.Background(), a); got != "DUNNO" {
						t.Fatalf("got %q, want DUNNO", got)
					}
					if len(entered) != 0 {
						t.Fatal("unexpected DNS call for invalid HELO")
					}
				})
			}
		}
	}
}

func TestConcurrentChecksAndOverload(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan string, 2)
	s := testServer(fixtureResolver{policy: "v=spf1 +all", entered: entered, release: release})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := s.policy(context.Background(), request()); got != "DUNNO" {
				t.Errorf("got %q", got)
			}
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("checks did not overlap")
		}
	}
	if got := s.policy(context.Background(), request()); got != unavailable {
		t.Fatalf("overload: %q", got)
	}
	close(release)
	wg.Wait()
	if len(s.slots) != 0 {
		t.Fatal("leaked evaluation slot")
	}
}
func TestDeadline(t *testing.T) {
	s := testServer(fixtureResolver{release: make(chan struct{})})
	s.timeout = 10 * time.Millisecond
	if got := s.policy(context.Background(), request()); got != "451 4.7.24 SPF evaluation temporarily unavailable" {
		t.Fatal(got)
	}
}
func TestReadRequestBounds(t *testing.T) {
	for _, raw := range []string{
		"\n", "missing-equals\n\n", "a=\x00\n\n",
		"a=" + strings.Repeat("x", 4096) + "\n\n", "request=x\n", strings.Repeat("x", 4096),
	} {
		if _, err := readRequest(bufio.NewReaderSize(strings.NewReader(raw), 4096)); err == nil {
			t.Fatal("accepted invalid request")
		}
	}
	raw := "request=smtpd_access_policy\r\nunknown=future=value\r\n\r\n"
	a, err := readRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil || a["unknown"] != "future=value" {
		t.Fatalf("%v %v", a, err)
	}
}
func startServer(t *testing.T, s *server) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.serve(ctx, ln) }()
	t.Cleanup(cancel)
	return ln.Addr().String(), cancel, done
}
func dial(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { conn.Close() })
	return conn
}
func TestPersistentConnectionAndShutdown(t *testing.T) {
	s := testServer(fixtureResolver{policy: "v=spf1 +all"})
	address, cancel, done := startServer(t, s)
	conn := dial(t, address)
	r := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, wireRequest+wireRequest); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		a, err := readRequest(r)
		if err != nil || a["action"] != "DUNNO" {
			t.Fatalf("%v %v", a, err)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle connection blocked shutdown")
	}
}
func TestShutdownCancelsActiveDNS(t *testing.T) {
	entered := make(chan string, 1)
	s := testServer(fixtureResolver{entered: entered, release: make(chan struct{})})
	s.timeout = 10 * time.Second
	address, cancel, done := startServer(t, s)
	conn := dial(t, address)
	if _, err := io.WriteString(conn, wireRequest); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("DNS not started")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("active DNS was not canceled")
	}
	if len(s.slots) != 0 {
		t.Fatal("leaked evaluation")
	}
}
func TestListenerValidation(t *testing.T) {
	for _, address := range []string{":10023", "0.0.0.0:10023", "[::]:10023", "example.com:10023"} {
		if ln, err := listen("tcp", address); err == nil {
			ln.Close()
			t.Fatalf("accepted %q", address)
		}
	}
}

func TestReadRequestAggregateLimits(t *testing.T) {
	var raw strings.Builder
	for i := 0; i < 257; i++ {
		fmt.Fprintf(&raw, "key%d=value\n", i)
	}
	raw.WriteString("\n")
	if _, err := readRequest(bufio.NewReader(strings.NewReader(raw.String()))); err == nil {
		t.Fatal("accepted too many attributes")
	}
	raw.Reset()
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&raw, "key%d=%s\n", i, strings.Repeat("x", 2000))
	}
	raw.WriteString("\n")
	if _, err := readRequest(bufio.NewReader(strings.NewReader(raw.String()))); err == nil {
		t.Fatal("accepted oversized request")
	}
}

func TestConnectionLimit(t *testing.T) {
	s := testServer(fixtureResolver{policy: "v=spf1 +all"})
	s.maxConnections = 1
	address, cancel, done := startServer(t, s)
	first := dial(t, address)
	if _, err := io.WriteString(first, wireRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := readRequest(bufio.NewReader(first)); err != nil {
		t.Fatal(err)
	}
	second := dial(t, address)
	var b [1]byte
	if _, err := second.Read(b[:]); err == nil {
		t.Fatal("excess connection was not closed")
	} else if n, ok := err.(net.Error); ok && n.Timeout() {
		t.Fatal("excess connection remained open")
	}
	first.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestShutdownDrainsCompletedCheck(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan string, 1)
	s := testServer(fixtureResolver{policy: "v=spf1 +all", release: release, entered: entered})
	s.grace = time.Second
	address, cancel, done := startServer(t, s)
	conn := dial(t, address)
	io.WriteString(conn, wireRequest)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("DNS not started")
	}
	cancel()
	close(release)
	a, err := readRequest(bufio.NewReader(conn))
	if err != nil || a["action"] != "DUNNO" {
		t.Fatalf("active response was lost: %v %v", a, err)
	}
	conn.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not drain")
	}
}

func TestDuplicateAttributesUseLastValue(t *testing.T) {
	raw := "request=old\nrequest=smtpd_access_policy\nunknown=first\nunknown=last\n\n"
	attrs, err := readRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if attrs["request"] != "smtpd_access_policy" || attrs["unknown"] != "last" {
		t.Fatal(attrs)
	}
}

// The reader is already blocked waiting for a request when shutdown starts.
func TestShutdownDoesNotStartAnotherEvaluation(t *testing.T) {
	entered := make(chan string, 1)
	s := testServer(fixtureResolver{policy: "v=spf1 +all", entered: entered})
	client, peer := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	ready := make(chan struct{})
	wrapped := &readNotifyingConn{Conn: peer, ready: ready}
	go func() { defer close(done); defer peer.Close(); s.connection(context.Background(), wrapped) }()
	<-ready
	s.stopping.Store(true)
	client.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(client, wireRequest); err != nil {
		t.Fatal(err)
	}
	attrs, err := readRequest(bufio.NewReader(client))
	if err != nil || attrs["action"] != unavailable {
		t.Fatalf("got %v, %v", attrs, err)
	}
	<-done
	if len(entered) != 0 {
		t.Fatal("started DNS after shutdown")
	}
}

type readNotifyingConn struct {
	net.Conn
	ready chan struct{}
	once  sync.Once
}

func (c *readNotifyingConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.ready) })
	return c.Conn.Read(p)
}
