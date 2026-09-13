package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCheckCommandWithDNS(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	server := &dns.Server{PacketConn: packet, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		answer := new(dns.Msg)
		answer.SetReply(q)
		name := q.Question[0].Name
		if name == "example.com." || name == "helo.example.com." {
			answer.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"v=spf1 ip4:192.0.2.0/24 -all"}}}
		}
		w.WriteMsg(answer)
	})}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("DNS startup")
	}
	t.Cleanup(func() {
		server.Shutdown()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	for _, tc := range []struct{ ip, sender, want string }{
		{"192.0.2.1", "sender@example.com", "pass"},
		{"192.0.2.1", `"a<>b"@example.com`, "pass"},
		{"198.51.100.1", "sender@example.com", "fail"},
		{"192.0.2.1", "", "pass"},
		{"192.0.2.1", "<>", "pass"},
		{"192.0.2.1", "sender@absent.example", "none"},
	} {
		var out bytes.Buffer
		err := run(context.Background(), []string{"check", "-dns", packet.LocalAddr().String(), "-ip", tc.ip, "-sender", tc.sender, "-helo", "helo.example.com"}, &out, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			Result string `json:"result"`
		}
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Result != tc.want {
			t.Fatalf("%s: %s", tc.sender, out.String())
		}
	}
}
func TestUnixSocketDoesNotReplaceExistingListener(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket deployment is Linux/macOS only")
	}
	path := filepath.Join(t.TempDir(), "policy.sock")
	// macOS temporary directories can exceed the Unix socket pathname limit.
	if len(path) > 100 {
		t.Skip("temporary path exceeds portable Unix socket limit")
	}
	ln, err := listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if second, err := listen("unix", path); err == nil {
		second.Close()
		t.Fatal("replaced active socket")
	}
}

func TestResolverConfiguration(t *testing.T) {
	for _, address := range []string{"resolver.example:53", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:dns"} {
		if _, err := makeResolver(address, time.Second); err == nil {
			t.Fatalf("accepted %q", address)
		}
	}
}
