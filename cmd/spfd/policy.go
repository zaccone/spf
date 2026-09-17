package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	spf "github.com/zaccone/spf"
	"github.com/zaccone/spf/internal/identity"
)

const unavailable = "451 4.3.0 SPF policy service unavailable"
const maxRequestBytes = 64 * 1024

type server struct {
	resolver                  spf.ContextResolver
	receiver                  string
	timeout, ioTimeout, grace time.Duration
	enforce                   bool
	maxConnections            int
	slots                     chan struct{}
	logger                    *slog.Logger
	stopping                  atomic.Bool
}

// readRequest bounds total bytes, individual lines and attribute count. Postfix
// can add attributes over time; unknown attributes are accepted and ignored.
func readRequest(r *bufio.Reader) (map[string]string, error) {
	attrs := make(map[string]string)
	total := 0
	for count := 0; count <= 256; count++ {
		line, err := r.ReadSlice('\n')
		if err != nil {
			if errors.Is(err, io.EOF) && total != 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		total += len(line)
		if total > maxRequestBytes {
			return nil, errors.New("policy request too large")
		}
		value := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		if value == "" {
			if len(attrs) == 0 {
				return nil, errors.New("empty policy request")
			}
			return attrs, nil
		}
		key, val, ok := strings.Cut(value, "=")
		if !ok || key == "" || strings.ContainsAny(value, "\x00\r") {
			return nil, errors.New("malformed policy attribute")
		}
		// Postfix permits duplicate attributes; consistently keep the last value.
		attrs[key] = val
	}
	return nil, errors.New("too many policy attributes")
}

func disposition(result spf.Result, enforce bool) string {
	if enforce {
		switch result {
		case spf.Fail:
			return "550 5.7.23 SPF validation failed"
		case spf.Temperror:
			return "451 4.7.24 SPF evaluation temporarily unavailable"
		}
	}
	// Never return OK: passing SPF must not bypass other restrictions or relay policy.
	return "DUNNO"
}

func (s *server) policy(ctx context.Context, attrs map[string]string) string {
	if attrs["request"] != "smtpd_access_policy" || attrs["protocol_state"] == "" {
		return unavailable
	}
	if attrs["protocol_state"] != "RCPT" || attrs["sasl_username"] != "" {
		return "DUNNO"
	}
	sender, present := attrs["sender"]
	if !present {
		return unavailable
	}
	domain, err := identity.Domain(sender, attrs["helo_name"])
	ip := net.ParseIP(attrs["client_address"])
	if err != nil || ip == nil {
		return unavailable
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		s.logger.Warn("SPF evaluation capacity exhausted")
		return unavailable
	}
	checkctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	start := time.Now()
	sender = identity.NormalizeSender(sender)
	result, _, _ := spf.CheckHostWithOptions(checkctx, ip, domain, sender, spf.Options{Resolver: s.resolver, HELO: attrs["helo_name"], Receiver: s.receiver})
	// Invalid SPF domains (including HELO address literals) yield none,
	// not a service failure. Preserve that result's DUNNO disposition.
	action := disposition(result, s.enforce)
	// Do not log attacker-controlled sender addresses or DNS explanation text.
	s.logger.Info("SPF evaluation", "result", result.String(), "action", action, "elapsed_ms", time.Since(start).Milliseconds())
	return action
}

func (s *server) connection(ctx context.Context, conn net.Conn) {
	r := bufio.NewReaderSize(conn, 4096)
	for !s.stopping.Load() {
		if err := conn.SetReadDeadline(time.Now().Add(s.ioTimeout)); err != nil {
			return
		}
		attrs, err := readRequest(r)
		if errors.Is(err, io.EOF) {
			return
		}
		action := unavailable
		if err == nil && !s.stopping.Load() {
			action = s.policy(ctx, attrs)
		}
		if writeErr := conn.SetWriteDeadline(time.Now().Add(s.ioTimeout)); writeErr != nil {
			return
		}
		if _, writeErr := fmt.Fprintf(conn, "action=%s\n\n", action); writeErr != nil {
			return
		}
		if err != nil {
			return
		}
	}
}

func (s *server) serve(ctx context.Context, ln net.Listener) error {
	workctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			ln.Close()
		case <-done:
		}
	}()
	var mu sync.Mutex
	conns := make(map[net.Conn]struct{})
	var wg sync.WaitGroup
	var acceptErr error
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				acceptErr = err
			}
			break
		}
		mu.Lock()
		if len(conns) >= s.maxConnections {
			mu.Unlock()
			conn.Close()
			s.logger.Warn("connection capacity exhausted")
			continue
		}
		conns[conn] = struct{}{}
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { conn.Close(); mu.Lock(); delete(conns, conn); mu.Unlock() }()
			s.connection(workctx, conn)
		}()
	}
	close(done)
	s.stopping.Store(true)
	drained := make(chan struct{})
	go func() { wg.Wait(); close(drained) }()
	timer := time.NewTimer(s.grace)
	defer timer.Stop()
	select {
	case <-drained:
	case <-timer.C:
		cancel()
		mu.Lock()
		for conn := range conns {
			conn.Close()
		}
		mu.Unlock()
		<-drained
	}
	s.logger.Info("policy service stopped")
	return acceptErr
}
