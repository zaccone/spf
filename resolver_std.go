package spf

import (
	"net"
	"sync"
)

// DNSResolver implements Resolver using local DNS
type DNSResolver struct{}

func errDNS(e error) error {
	if e == nil {
		return nil
	}
	if dnsErr, ok := e.(*net.DNSError); ok {
		// That is the most reliable way I found to detect Permerror
		// https://github.com/golang/go/blob/master/src/net/dnsclient.go#L43
		if dnsErr.Err == "no such host" {
			return ErrDNSPermerror
		}
	}
	return ErrDNSTemperror
}

// LookupTXT returns the DNS TXT records for the given domain name.
func (r *DNSResolver) LookupTXT(name string) ([]string, error) {
	txts, err := net.LookupTXT(name)
	if err != nil {
		return nil, errDNS(err)
	}
	return txts, nil
}

// Exists is used for a DNS A RR lookup (even when the
// connection type is IPv6).  If any A record is returned, this
// mechanism matches.
func (r *DNSResolver) Exists(name string) (bool, error) {
	ips, err := net.LookupIP(name)
	if err != nil {
		return false, errDNS(err)
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
func (r *DNSResolver) MatchIP(name string, matcher IPMatcherFunc) (bool, error) {
	ips, err := net.LookupIP(name)
	if err != nil {
		return false, errDNS(err)
	}
	for _, ip := range ips {
		if m, e := matcher(ip); m || e != nil {
			return m, e
		}
	}
	return false, nil
}

// MatchMX is similar to MatchIP but first performs an MX lookup on the
// name.  Then it performs an address lookup on each MX name returned.
// Then IPMatcherFunc used to compare checked IP to the returned address(es).
// If any address matches, the mechanism matches
func (r *DNSResolver) MatchMX(name string, matcher IPMatcherFunc) (bool, error) {
	mxs, err := net.LookupMX(name)
	if err != nil {
		return false, errDNS(err)
	}

	var wg sync.WaitGroup
	hits := make(chan hit)

	for _, mx := range mxs {
		wg.Add(1)
		go func(name string) {
			found, err := r.MatchIP(name, matcher)
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
