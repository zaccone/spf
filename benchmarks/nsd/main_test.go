package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// Exercise the actual executable's exit status: a harness that merely reports
// errors but exits successfully would silently bless a broken production build.
func TestDriverProcess(t *testing.T) {
	if os.Getenv("SPF_BENCH_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"bench"}, os.Args[i+1:]...)
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet("bench", flag.ExitOnError)
	if err := run(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func driver(t *testing.T, cases []Case, args ...string) (map[string]any, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cases.json")
	data, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, append([]string{"-test.run=^TestDriverProcess$", "--", "-cases", path, "-once"}, args...)...)
	cmd.Env = append(os.Environ(), "SPF_BENCH_HELPER=1")
	output, runErr := cmd.Output()
	var result map[string]any
	if len(output) > 0 {
		if err := json.Unmarshal(output, &result); err != nil {
			t.Fatalf("invalid JSON %q: %v", output, err)
		}
	}
	return result, runErr
}

func TestDriverSPFResultGate(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		policy := "v=spf1 +all"
		if strings.HasPrefix(request.Question[0].Name, "invalid.") {
			policy = "v=spf1 unknown"
		}
		response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{policy}}}
		_ = w.WriteMsg(response)
	})}
	go server.ActivateAndServe()
	defer server.Shutdown()
	cases := []Case{{Name: "pass", Domain: "pass.example.test", IP: "192.0.2.1", Expected: "pass"}, {Name: "invalid", Domain: "invalid.example.test", IP: "192.0.2.1", Expected: "permerror"}}
	result, err := driver(t, cases, "-dns", packet.LocalAddr().String())
	if err != nil || result["n"] != float64(2) || result["errors"] != float64(0) {
		t.Fatalf("valid mixed results: %v %v", result, err)
	}
	cases[0].Expected = "fail"
	result, err = driver(t, cases, "-dns", packet.LocalAddr().String())
	if err == nil || result["errors"] != float64(1) {
		t.Fatalf("wrong SPF result must fail: %v %v", result, err)
	}
}

func TestDriverPolicyGate(t *testing.T) {
	for _, reply := range []string{"action=DUNNO\n\n", "action=550 5.7.23 SPF validation failed\nnot-blank\n"} {
		t.Run(strings.TrimSpace(reply), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, e := listener.Accept()
				if e != nil {
					return
				}
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					line, e := reader.ReadString('\n')
					if e != nil {
						return
					}
					if line == "\n" {
						break
					}
				}
				_, _ = conn.Write([]byte(reply))
			}()
			result, err := driver(t, []Case{{Name: "fail", Domain: "fail.example.test", IP: "192.0.2.1", Expected: "fail"}}, "-mode", "policy", "-policy", listener.Addr().String())
			if err == nil || result["errors"] != float64(1) {
				t.Fatalf("incorrect action/framing must fail: %v %v", result, err)
			}
			<-done
		})
	}
}
