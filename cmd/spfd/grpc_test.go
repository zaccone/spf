package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	spf "github.com/zaccone/spf"
	spfv1 "github.com/zaccone/spf/api/spf/v1"
	"github.com/zaccone/spf/internal/grpcapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

func grpcFixture(t *testing.T, resolver spf.ContextResolver, grace time.Duration) (*grpc.ClientConn, context.CancelFunc, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := grpcapi.New(grpcapi.Config{Resolver: resolver, Timeout: time.Second, MaxChecks: 1, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveGRPC(ctx, ln, service, 4, 8, time.Second, grace, logger) }()
	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(); cancel() })
	return conn, cancel, done
}
func rpcRequest() *spfv1.CheckRequest {
	return &spfv1.CheckRequest{ClientIp: "192.0.2.1", Sender: "a@example.test"}
}
func awaitGRPCStop(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("gRPC shutdown stalled")
	}
}
func TestGRPCTransportAndHealth(t *testing.T) {
	conn, cancel, done := grpcFixture(t, fixtureResolver{policy: "v=spf1 +all"}, time.Second)
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	client := spfv1.NewSPFServiceClient(conn)
	for range 2 {
		got, err := client.Check(ctx, rpcRequest())
		if err != nil || got.GetResult() != spfv1.Result_RESULT_PASS {
			t.Fatalf("%v %v", got, err)
		}
	}
	for _, name := range []string{"", spfv1.SPFService_ServiceDesc.ServiceName} {
		got, err := healthv1.NewHealthClient(conn).Check(ctx, &healthv1.HealthCheckRequest{Service: name})
		if err != nil || got.GetStatus() != healthv1.HealthCheckResponse_SERVING {
			t.Fatalf("%v %v", got, err)
		}
	}
	req := rpcRequest()
	req.Helo = strings.Repeat("x", grpcMessageLimit+1)
	if _, err := client.Check(ctx, req); status.Code(err) != codes.ResourceExhausted {
		t.Fatal(err)
	}
	req = rpcRequest()
	req.ClientIp = "bad"
	if _, err := client.Check(ctx, req); status.Code(err) != codes.InvalidArgument {
		t.Fatal(err)
	}
	cancel()
	awaitGRPCStop(t, done)
}
func TestGRPCOverloadAndDeadline(t *testing.T) {
	entered := make(chan string, 2)
	conn, cancel, done := grpcFixture(t, fixtureResolver{policy: "v=spf1 +all", entered: entered, release: make(chan struct{})}, time.Second)
	client := spfv1.NewSPFServiceClient(conn)
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	callctx, stopCall := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() { _, err := client.Check(callctx, rpcRequest()); result <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := client.Check(ctx, rpcRequest()); status.Code(err) != codes.ResourceExhausted {
		t.Fatal(err)
	}
	stopCall()
	if err := <-result; status.Code(err) != codes.Canceled {
		t.Fatal(err)
	}
	cancel()
	awaitGRPCStop(t, done)
}
func TestGRPCShutdown(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(map[bool]string{false: "drain", true: "force"}[force], func(t *testing.T) {
			entered := make(chan string, 1)
			release := make(chan struct{})
			grace := time.Second
			if force {
				grace = 30 * time.Millisecond
			}
			conn, cancel, done := grpcFixture(t, fixtureResolver{policy: "v=spf1 +all", entered: entered, release: release}, grace)
			ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			result := make(chan error, 1)
			go func() { _, err := spfv1.NewSPFServiceClient(conn).Check(ctx, rpcRequest()); result <- err }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			cancel()
			if !force {
				close(release)
			}
			awaitGRPCStop(t, done)
			err := <-result
			if force && err == nil {
				t.Fatal("forced RPC succeeded")
			}
			if !force && err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestGRPCFlags(t *testing.T) {
	for _, args := range [][]string{
		{"-max-checks", "0"}, {"-max-connections", "0"}, {"-timeout", "21s"},
		{"-connection-timeout", "0s"}, {"-shutdown-timeout", "0s"},
		{"-listen", "0.0.0.0:50051"}, {"-listen", "localhost:50051"},
		{"-network", "udp"}, {"extra"},
	} {
		if err := run(context.Background(), append([]string{"grpc"}, args...), io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	if err := run(context.Background(), []string{"grpc", "-h"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
}
func TestBoundedListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	bounded := &boundedListener{Listener: ln, max: 1}
	first, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	accepted, err := bounded.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	next := make(chan net.Conn, 1)
	go func() { conn, _ := bounded.Accept(); next <- conn }()
	excess, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer excess.Close()
	excess.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := excess.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("excess connection not closed: %v", err)
	}
	accepted.Close()
	accepted.Close()
	bounded.mu.Lock()
	active := len(bounded.conns)
	bounded.mu.Unlock()
	if active != 0 {
		t.Fatal("incorrect active count")
	}
	replacement, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	select {
	case conn := <-next:
		if conn == nil {
			t.Fatal("accept failed")
		}
		conn.Close()
	case <-time.After(time.Second):
		t.Fatal("capacity not released")
	}
}

func TestGRPCClientDeadline(t *testing.T) {
	conn, cancel, done := grpcFixture(t, fixtureResolver{release: make(chan struct{})}, time.Second)
	// Establish the transport before measuring an evaluation deadline.
	ready, stopReady := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopReady()
	if _, err := healthv1.NewHealthClient(conn).Check(ready, &healthv1.HealthCheckRequest{}); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	if _, err := spfv1.NewSPFServiceClient(conn).Check(ctx, rpcRequest()); status.Code(err) != codes.DeadlineExceeded {
		t.Fatal(err)
	}
	cancel()
	awaitGRPCStop(t, done)
}

func TestGRPCShutdownDuringHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := grpcapi.New(grpcapi.Config{Resolver: fixtureResolver{policy: "v=spf1 +all"}, Timeout: time.Second, MaxChecks: 1, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	accepted := make(chan struct{})
	observed := &observedListener{Listener: ln, accepted: accepted}
	done := make(chan error, 1)
	go func() { done <- serveGRPC(ctx, observed, service, 4, 8, 10*time.Second, 30*time.Millisecond, logger) }()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("not accepted")
	}
	// Read server SETTINGS: this confirms the server has entered HTTP/2 setup,
	// while deliberately never sending a client preface.
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	cancel()
	awaitGRPCStop(t, done)
}

type observedListener struct {
	net.Listener
	accepted chan struct{}
}

func (l *observedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		close(l.accepted)
	}
	return conn, err
}
