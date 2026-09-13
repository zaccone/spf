package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// DNSResolver implements Resolver and ContextResolver using Go's resolver with
// the system DNS configuration and net.DefaultResolver.Dial, when configured.
// It uses the Go DNS path for cancelable connections, which can differ from
// platform-native resolution (for example, native split-DNS routing). Recursive
// servers supply complete alias answers; Go handles TCP fallback. Intermediate
// wire responses and retries are not observable; budgets count logical lookups.
type DNSResolver struct{}

func dnsNotFound(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrDNSLimitExceeded) {
		return false
	}
	if errors.Is(err, ErrDNSPermerror) || errors.Is(err, ErrSPFNotFound) {
		return true
	}
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// wrapDNSError preserves typed DNS and transport causes as well as the legacy
// sentinels. Checking ctx first retains cancellation even when a transport
// reports a closed socket or a platform-specific timeout.
func wrapDNSError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return errors.Join(ErrDNSTemperror, ctxErr, err)
	}
	if err == nil {
		return nil
	}
	// A socket deadline may fire before the context timer's goroutine runs.
	// Preserve the deadline cause in that race without losing the net.Error.
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			return errors.Join(ErrDNSTemperror, context.DeadlineExceeded, err)
		}
	}
	if dnsNotFound(err) {
		return errors.Join(ErrDNSPermerror, err)
	}
	return errors.Join(ErrDNSTemperror, err)
}

// LookupTXTContext returns one concatenated string per TXT resource record.
func (r *DNSResolver) LookupTXTContext(ctx context.Context, name string) ([]string, error) {
	records, err := systemResolver(ctx).LookupTXT(ctx, NormalizeFQDN(name))
	return records, wrapDNSError(ctx, err)
}

// LookupIPContext looks up only network ("ip4" or "ip6").
func (r *DNSResolver) LookupIPContext(ctx context.Context, network, name string) ([]net.IP, error) {
	if network != "ip4" && network != "ip6" {
		return nil, fmt.Errorf("invalid address network %q", network)
	}
	records, err := systemResolver(ctx).LookupIP(ctx, network, NormalizeFQDN(name))
	return records, wrapDNSError(ctx, err)
}

// LookupMXContext returns exchanges without resolving their addresses.
func (r *DNSResolver) LookupMXContext(ctx context.Context, name string) ([]*net.MX, error) {
	records, err := systemResolver(ctx).LookupMX(ctx, NormalizeFQDN(name))
	return records, wrapDNSError(ctx, err)
}

// LookupAddrContext returns reverse DNS candidates without forward validation.
func (r *DNSResolver) LookupAddrContext(ctx context.Context, addr string) ([]string, error) {
	records, err := systemResolver(ctx).LookupAddr(ctx, addr)
	return records, wrapDNSError(ctx, err)
}

func (r *DNSResolver) LookupTXTStrict(name string) ([]string, error) { return legacyTXT(r, name, true) }
func (r *DNSResolver) LookupTXT(name string) ([]string, error)       { return legacyTXT(r, name, false) }
func (r *DNSResolver) Exists(name string) (bool, error)              { return legacyExists(r, name) }
func (r *DNSResolver) MatchIP(name string, matcher IPMatcherFunc) (bool, error) {
	return legacyMatchIP(r, name, matcher)
}
func (r *DNSResolver) MatchMX(name string, matcher IPMatcherFunc) (bool, error) {
	return legacyMatchMX(r, name, matcher)
}

// systemResolver preserves the configured DNS source and wraps its connections
// so cancellation interrupts reads as well as dialing. Do not copy Resolver's
// private synchronization state or mutate the process-wide default resolver.
func systemResolver(ctx context.Context) *net.Resolver {
	base := net.DefaultResolver
	return &net.Resolver{
		PreferGo:     true,
		StrictErrors: base.StrictErrors,
		Dial: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			var conn net.Conn
			var err error
			if base.Dial != nil {
				conn, err = base.Dial(dialCtx, network, address)
			} else {
				conn, err = (&net.Dialer{}).DialContext(dialCtx, network, address)
			}
			if err != nil {
				return nil, err
			}
			c := &cancelDNSConn{Conn: conn, done: make(chan struct{})}
			c.stop = context.AfterFunc(ctx, func() { conn.Close(); close(c.done) })
			if packet, ok := conn.(net.PacketConn); ok {
				return &cancelDNSPacketConn{cancelDNSConn: c, packet: packet}, nil
			}
			return c, nil
		},
	}
}

type cancelDNSConn struct {
	net.Conn
	stop func() bool
	done chan struct{}
	once sync.Once
}

func (c *cancelDNSConn) Close() error {
	c.once.Do(func() {
		if !c.stop() {
			<-c.done
		}
	})
	return c.Conn.Close()
}

// net.Resolver distinguishes datagram and stream framing by PacketConn.
// Preserve that interface when adding the cancellation wrapper.
type cancelDNSPacketConn struct {
	*cancelDNSConn
	packet net.PacketConn
}

func (c *cancelDNSPacketConn) ReadFrom(b []byte) (int, net.Addr, error) { return c.packet.ReadFrom(b) }
func (c *cancelDNSPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.packet.WriteTo(b, addr)
}
