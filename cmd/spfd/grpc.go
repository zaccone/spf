package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	spfv1 "github.com/zaccone/spf/api/spf/v1"
	"github.com/zaccone/spf/internal/grpcapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
)

const grpcMessageLimit = 64 * 1024

func runGRPC(ctx context.Context, args []string, errout io.Writer) error {
	fs := flag.NewFlagSet("grpc", flag.ContinueOnError)
	fs.SetOutput(errout)
	var opts resolverOptions
	opts.registerFlags(fs)
	network := fs.String("network", "tcp", "listener network: tcp (loopback only) or unix")
	address := fs.String("listen", "127.0.0.1:50051", "listener address or Unix socket path")
	connections := fs.Int("max-connections", 256, "maximum open connections")
	checks := fs.Int("max-checks", 64, "maximum concurrent SPF evaluations (no waiting queue)")
	handshake := fs.Duration("connection-timeout", 10*time.Second, "connection handshake deadline")
	grace := fs.Duration("shutdown-timeout", 5*time.Second, "time to drain RPCs before cancellation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *connections < 1 || *checks < 1 || uint64(*checks) > uint64(^uint32(0)) || *handshake <= 0 || *grace <= 0 {
		return errors.New("resource limits and timeouts must be positive; max-checks must fit uint32")
	}
	resolver, err := makeResolver(opts.dns, opts.timeout)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(errout, nil))
	service, err := grpcapi.New(grpcapi.Config{Resolver: resolver, Receiver: opts.receiver, Timeout: opts.timeout, MaxChecks: *checks, Logger: logger})
	if err != nil {
		return err
	}
	ln, err := listen(*network, *address)
	if err != nil {
		return err
	}
	defer ln.Close()
	logger.Info("gRPC service listening", "address", ln.Addr().String(), "max_checks", *checks, "max_connections", *connections)
	return serveGRPC(ctx, ln, service, *connections, uint32(*checks), *handshake, *grace, logger)
}

func serveGRPC(ctx context.Context, ln net.Listener, service *grpcapi.Service, connections int, streams uint32, handshake, grace time.Duration, logger *slog.Logger) error {
	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(grpcMessageLimit), grpc.MaxSendMsgSize(grpcMessageLimit),
		grpc.MaxConcurrentStreams(streams), grpc.ConnectionTimeout(handshake),
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: 30 * time.Second}),
	)
	spfv1.RegisterSPFServiceServer(server, service)
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(spfv1.SPFService_ServiceDesc.ServiceName, healthv1.HealthCheckResponse_SERVING)
	healthv1.RegisterHealthServer(server, healthServer)
	done := make(chan error, 1)
	listener := &boundedListener{Listener: ln, max: connections}
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		listener.closeConnections()
		server.Stop()
		return err
	case <-ctx.Done():
	}
	healthServer.Shutdown()
	drained := make(chan struct{})
	go func() { server.GracefulStop(); close(drained) }()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-drained:
	case <-timer.C:
		logger.Info("gRPC drain deadline reached")
		listener.closeConnections()
		server.Stop()
		<-drained
	}
	err := <-done
	logger.Info("gRPC service stopped")
	if errors.Is(err, grpc.ErrServerStopped) {
		return nil
	}
	return err
}

// HTTP/2 can multiplex requests, so connection and evaluation bounds are separate.
// Reject excess connections rather than maintaining an application accept queue.
type boundedListener struct {
	net.Listener
	max      int
	mu       sync.Mutex
	conns    map[*countedConn]struct{}
	stopping bool
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.mu.Lock()
		if l.stopping || len(l.conns) >= l.max {
			l.mu.Unlock()
			conn.Close()
			continue
		}
		if l.conns == nil {
			l.conns = make(map[*countedConn]struct{})
		}
		counted := &countedConn{Conn: conn}
		counted.release = func() { l.mu.Lock(); delete(l.conns, counted); l.mu.Unlock() }
		l.conns[counted] = struct{}{}
		l.mu.Unlock()
		return counted, nil
	}
}

// gRPC does not register a transport until its handshake finishes. Close raw
// connections too at the drain deadline, so those handshakes cannot delay Stop.
func (l *boundedListener) closeConnections() {
	l.mu.Lock()
	l.stopping = true
	conns := make([]*countedConn, 0, len(l.conns))
	for conn := range l.conns {
		conns = append(conns, conn)
	}
	l.mu.Unlock()
	for _, conn := range conns {
		conn.Close()
	}
}

type countedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *countedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
