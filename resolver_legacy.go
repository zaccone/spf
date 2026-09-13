package spf

import (
	"context"
	"net"
)

// The old methods retain synchronous callbacks and their both-family matching
// contract. The evaluator selects ContextResolver instead whenever available.
func legacyTXT(r ContextResolver, name string, strict bool) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), evaluationTimeout)
	defer cancel()
	records, err := r.LookupTXTContext(ctx, name)
	if !strict && dnsNotFound(err) {
		return nil, nil
	}
	return records, err
}

func legacyExists(r ContextResolver, name string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), evaluationTimeout)
	defer cancel()
	ips, err := r.LookupIPContext(ctx, "ip4", name)
	if dnsNotFound(err) {
		return false, nil
	}
	return len(ips) > 0, err
}

func matchAddresses(ips []net.IP, matcher IPMatcherFunc) (bool, error) {
	for _, ip := range ips {
		if ip.To16() == nil {
			continue
		}
		if found, err := matcher(ip); found || err != nil {
			return found, err
		}
	}
	return false, nil
}

func legacyMatchIP(r ContextResolver, name string, matcher IPMatcherFunc) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), evaluationTimeout)
	defer cancel()
	return matchBothFamilies(ctx, r, name, matcher)
}

func matchBothFamilies(ctx context.Context, r ContextResolver, name string, matcher IPMatcherFunc) (bool, error) {
	for _, network := range []string{"ip4", "ip6"} {
		ips, err := r.LookupIPContext(ctx, network, name)
		if dnsNotFound(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		if found, err := matchAddresses(ips, matcher); found || err != nil {
			return found, err
		}
	}
	return false, nil
}

func legacyMatchMX(r ContextResolver, name string, matcher IPMatcherFunc) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), evaluationTimeout)
	defer cancel()
	mxs, err := r.LookupMXContext(ctx, name)
	if dnsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(mxs) > 10 {
		return false, ErrDNSLimitExceeded
	}
	for _, mx := range mxs {
		if mx == nil || mx.Host == "." {
			continue
		}
		if found, err := matchBothFamilies(ctx, r, mx.Host, matcher); found || err != nil {
			return found, err
		}
	}
	return false, nil
}
