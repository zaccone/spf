// Command smoke_grpc checks a real spfd binary against local deterministic DNS.
// Run on Linux/macOS: go run ./tools/smoke_grpc /absolute/path/to/spfd
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/miekg/dns"
	spfv1 "github.com/zaccone/spf/api/spf/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 2 {
		return errors.New("usage: smoke_grpc /path/to/spfd")
	}
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	ready := make(chan struct{})
	dnsServer := &dns.Server{PacketConn: packet, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(q)
		if len(q.Question) > 0 && q.Question[0].Qtype == dns.TypeTXT {
			name := q.Question[0].Name
			if name == "example.test." || name == "helo.test." {
				response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"v=spf1 ip4:192.0.2.1 -all"}}}
			}
		}
		_ = w.WriteMsg(response)
	})}
	dnsDone := make(chan error, 1)
	go func() { dnsDone <- dnsServer.ActivateAndServe() }()
	select {
	case <-ready:
	case err := <-dnsDone:
		return fmt.Errorf("DNS startup: %w", err)
	case <-time.After(3 * time.Second):
		packet.Close()
		return errors.New("DNS startup timed out")
	}
	defer dnsServer.Shutdown()
	cmd := exec.Command(os.Args[1], "grpc", "-listen", "127.0.0.1:0", "-dns", packet.LocalAddr().String(), "-shutdown-timeout", "1s")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	addresses := make(chan string, 1)
	logsDone := make(chan struct{})
	go func() {
		defer close(logsDone)
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			var entry struct {
				Msg     string `json:"msg"`
				Address string `json:"address"`
			}
			if json.Unmarshal(scanner.Bytes(), &entry) == nil && entry.Msg == "gRPC service listening" {
				addresses <- entry.Address
			}
		}
	}()
	var address string
	select {
	case address = <-addresses:
	case <-logsDone:
		return errors.New("daemon exited before startup")
	case <-time.After(5 * time.Second):
		return errors.New("daemon startup timed out")
	}
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	health, err := healthv1.NewHealthClient(conn).Check(ctx, &healthv1.HealthCheckRequest{Service: spfv1.SPFService_ServiceDesc.ServiceName})
	if err != nil {
		return err
	}
	if health.GetStatus() != healthv1.HealthCheckResponse_SERVING {
		return errors.New("not serving")
	}
	client := spfv1.NewSPFServiceClient(conn)
	for _, tt := range []struct {
		ip, sender, helo string
		want             spfv1.Result
	}{
		{"192.0.2.1", "a@example.test", "", spfv1.Result_RESULT_PASS},
		{"198.51.100.1", "a@example.test", "", spfv1.Result_RESULT_FAIL},
		{"192.0.2.1", "<>", "helo.test", spfv1.Result_RESULT_PASS},
		{"192.0.2.1", "a@absent.test", "", spfv1.Result_RESULT_NONE},
	} {
		got, err := client.Check(ctx, &spfv1.CheckRequest{ClientIp: tt.ip, Sender: tt.sender, Helo: tt.helo})
		if err != nil {
			return err
		}
		if got.GetResult() != tt.want {
			return fmt.Errorf("got %v want %v", got.GetResult(), tt.want)
		}
	}
	if _, err := client.Check(ctx, &spfv1.CheckRequest{ClientIp: "bad"}); status.Code(err) != codes.InvalidArgument {
		return fmt.Errorf("invalid request: %v", err)
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		return err
	}
	// Drain the stderr pipe before Wait closes it.
	select {
	case <-logsDone:
	case <-time.After(3 * time.Second):
		return errors.New("shutdown timed out")
	}
	err = cmd.Wait()
	waited = true
	if err != nil {
		return err
	}
	fmt.Println("gRPC smoke test passed: health, SPF results, null sender, validation, shutdown")
	return nil
}
