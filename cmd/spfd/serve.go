package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"os"
	"time"
)

func runServe(ctx context.Context, args []string, errout io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(errout)
	var opts resolverOptions
	opts.registerFlags(fs)
	network := fs.String("network", "tcp", "listener network: tcp (loopback only) or unix")
	address := fs.String("listen", "127.0.0.1:10023", "listener address or Unix socket path")
	connections := fs.Int("max-connections", 256, "maximum open connections")
	checks := fs.Int("max-checks", 64, "maximum concurrent SPF evaluations (no waiting queue)")
	idle := fs.Duration("io-timeout", 30*time.Second, "deadline for each complete request or response")
	grace := fs.Duration("shutdown-timeout", 5*time.Second, "time to drain connections before cancellation")
	enforce := fs.Bool("enforce", false, "reject SPF fail and defer temperror; default logs results only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *connections < 1 || *checks < 1 || *idle <= 0 || *grace <= 0 {
		return errors.New("resource limits and timeouts must be positive")
	}
	r, err := makeResolver(opts.dns, opts.timeout)
	if err != nil {
		return err
	}
	ln, err := listen(*network, *address)
	if err != nil {
		return err
	}
	defer ln.Close()
	logger := slog.New(slog.NewJSONHandler(errout, nil))
	logger.Info("policy service listening", "address", ln.Addr().String(), "enforce", *enforce, "max_checks", *checks, "max_connections", *connections)
	s := server{
		resolver:       r,
		receiver:       opts.receiver,
		timeout:        opts.timeout,
		ioTimeout:      *idle,
		grace:          *grace,
		enforce:        *enforce,
		maxConnections: *connections,
		slots:          make(chan struct{}, *checks),
		logger:         logger,
	}
	return s.serve(ctx, ln)
}

func listen(network, address string) (net.Listener, error) {
	switch network {
	case "tcp":
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("TCP listener must use a literal loopback IP")
		}
		return net.Listen(network, address)
	case "unix":
		// Never remove an existing socket: it may belong to a live daemon.
		ln, err := net.Listen(network, address)
		if err != nil {
			return nil, err
		}
		if err := os.Chmod(address, 0660); err != nil {
			ln.Close()
			return nil, err
		}
		return ln, nil
	default:
		return nil, errors.New("-network must be tcp or unix")
	}
}
