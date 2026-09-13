// Command spfd evaluates SPF directly or serves Postfix access-policy requests.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	spf "github.com/zaccone/spf"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: spfd check|serve [options]; use check -h or serve -h")
	}
	if args[0] != "check" && args[0] != "serve" {
		return fmt.Errorf("unknown command %q; use check or serve", args[0])
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(errout)
	dns := fs.String("dns", "127.0.0.1:53", "recursive DNS server (IP:port)")
	timeout := fs.Duration("timeout", 20*time.Second, "SPF evaluation deadline (up to 20s)")
	receiver := fs.String("receiver", "unknown", "receiving MTA hostname for SPF macros")
	if args[0] == "check" {
		ip := fs.String("ip", "", "SMTP client IP (required)")
		domain := fs.String("domain", "", "policy domain (defaults to sender domain, or HELO for null sender)")
		sender := fs.String("sender", "", "envelope sender; empty means null reverse path")
		helo := fs.String("helo", "", "SMTP HELO/EHLO identity")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		r, err := makeResolver(*dns, *timeout)
		if err != nil {
			return err
		}
		address := net.ParseIP(*ip)
		if address == nil {
			return errors.New("-ip must be an IP address")
		}
		if *domain == "" {
			*domain, err = identity(*sender, *helo)
			if err != nil {
				return err
			}
		}
		checkctx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		if *sender == "<>" {
			*sender = ""
		}
		result, explanation, diagnostic := spf.CheckHostWithOptions(checkctx, address, *domain, *sender, spf.Options{Resolver: r, HELO: *helo, Receiver: *receiver})
		message := ""
		if diagnostic != nil {
			message = diagnostic.Error()
		}
		return json.NewEncoder(out).Encode(struct {
			Result      string `json:"result"`
			Explanation string `json:"explanation,omitempty"`
			Error       string `json:"error,omitempty"`
		}{result.String(), explanation, message})
	}
	network := fs.String("network", "tcp", "listener network: tcp (loopback only) or unix")
	address := fs.String("listen", "127.0.0.1:10023", "listener address or Unix socket path")
	connections := fs.Int("max-connections", 256, "maximum open connections")
	checks := fs.Int("max-checks", 64, "maximum concurrent SPF evaluations (no waiting queue)")
	idle := fs.Duration("io-timeout", 30*time.Second, "deadline for each complete request or response")
	grace := fs.Duration("shutdown-timeout", 5*time.Second, "time to drain connections before cancellation")
	enforce := fs.Bool("enforce", false, "reject SPF fail and defer temperror; default logs results only")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *connections < 1 || *checks < 1 || *idle <= 0 || *grace <= 0 {
		return errors.New("resource limits and timeouts must be positive")
	}
	r, err := makeResolver(*dns, *timeout)
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
	s := server{resolver: r, receiver: *receiver, timeout: *timeout, ioTimeout: *idle, grace: *grace, enforce: *enforce, maxConnections: *connections, slots: make(chan struct{}, *checks), logger: logger}
	return s.serve(ctx, ln)
}

func makeResolver(address string, timeout time.Duration) (spf.ContextResolver, error) {
	if timeout <= 0 || timeout > 20*time.Second {
		return nil, errors.New("-timeout must be greater than zero and at most 20s")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) == nil {
		return nil, errors.New("-dns requires a literal IP address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("-dns requires a port between 1 and 65535")
	}
	return spf.NewMiekgDNSResolverContext(address)
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
