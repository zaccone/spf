package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// DNSResolver implements Resolver and ContextResolver using net.DefaultResolver.
// The system resolver owns alias handling and TCP fallback. Its intermediate
// wire responses and retries are not observable; budgets count logical lookups.
type DNSResolver struct{}

func dnsNotFound(err error) bool {
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
	if dnsNotFound(err) {
		return errors.Join(ErrDNSPermerror, err)
	}
	return errors.Join(ErrDNSTemperror, err)
}

// LookupTXTContext returns one concatenated string per TXT resource record.
func (r *DNSResolver) LookupTXTContext(ctx context.Context, name string) ([]string, error) {
	records, err := net.DefaultResolver.LookupTXT(ctx, NormalizeFQDN(name))
	return records, wrapDNSError(ctx, err)
}

// LookupIPContext looks up only network ("ip4" or "ip6").
func (r *DNSResolver) LookupIPContext(ctx context.Context, network, name string) ([]net.IP, error) {
	if network != "ip4" && network != "ip6" {
		return nil, fmt.Errorf("invalid address network %q", network)
	}
	records, err := net.DefaultResolver.LookupIP(ctx, network, NormalizeFQDN(name))
	return records, wrapDNSError(ctx, err)
}

// LookupMXContext returns exchanges without resolving their addresses.
func (r *DNSResolver) LookupMXContext(ctx context.Context, name string) ([]*net.MX, error) {
	records, err := net.DefaultResolver.LookupMX(ctx, NormalizeFQDN(name))
	return records, wrapDNSError(ctx, err)
}

// LookupAddrContext returns reverse DNS candidates without forward validation.
func (r *DNSResolver) LookupAddrContext(ctx context.Context, addr string) ([]string, error) {
	records, err := net.DefaultResolver.LookupAddr(ctx, addr)
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
