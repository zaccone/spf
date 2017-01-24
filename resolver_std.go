package spf

import (
	"net"
	"sync"
)

// DNSResolver implements Resolver using local DNS
type DNSResolver struct{}

// LookupTXT returns the DNS TXT records for the given domain name.
func (r *DNSResolver) LookupTXT(name string) ([]string, error) {
	txts, err := net.LookupTXT(name)
	if err != nil {
		return nil, ErrDNSTemperror
	}
	return txts, nil
}

// Exists is used for a DNS A RR lookup (even when the
// connection type is IPv6).  If any A record is returned, this
// mechanism matches.
func (r *DNSResolver) Exists(name string) (bool, error) {
	ips, err := net.LookupIP(name)
	if err != nil {
		return false, ErrDNSTemperror
	}
	return len(ips) > 0, nil
}

type hit struct {
	found bool
	err   error
}

// MatchIP provides an address lookup, which should be done on the name
// using the type of lookup (A or AAAA).
// Then IPMatcherFunc used to compare checked IP to the returned address(es).
// If any address matches, the mechanism matches
func (r *DNSResolver) MatchIP(name string, match IPMatcherFunc) (bool, error) {
	ips, err := net.LookupIP(name)
	if err != nil {
		return false, ErrDNSTemperror
	}
	for _, ip := range ips {
		if match(ip) {
			return true, nil
		}
	}
	return false, nil
}

// MatchMX is similar to MatchIP but first performs an MX lookup on the
// name.  Then it performs an address lookup on each MX name returned.
// Then IPMatcherFunc used to compare checked IP to the returned address(es).
// If any address matches, the mechanism matches
func (r *DNSResolver) MatchMX(name string, match IPMatcherFunc) (bool, error) {
	mxs, err := net.LookupMX(name)
	if err != nil {
		return false, ErrDNSTemperror
	}

	var wg sync.WaitGroup
	hits := make(chan hit)

	for _, mx := range mxs {
		wg.Add(1)
		go func(name string) {
			found, err := r.MatchIP(name, match)
			hits <- hit{found, err}
			wg.Done()
		}(mx.Host)
	}

	go func() {
		wg.Wait()
		close(hits)
	}()

	for h := range hits {
		if h.found || h.err != nil {
			return h.found, h.err
		}
	}

	return false, nil
}
