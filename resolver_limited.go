package spf

import "sync/atomic"

// LimitedResolver wraps a Resolver and limits number of lookups possible to do
// with it. All overlimited calls return ErrDNSLimitExceeded.
type LimitedResolver struct {
	limit    int32
	resolver Resolver
}

// NewLimitedResolver returns a resolver which will pass up to l calls to r.
// All calls over the limit will return ErrDNSLimitExceeded.
func NewLimitedResolver(r Resolver, l int32) Resolver {
	return &LimitedResolver{
		limit:    l,
		resolver: r,
	}
}

func (r *LimitedResolver) checkAndDecrLimit() error {
	v := atomic.LoadInt32(&r.limit)
	if v < 1 {
		return ErrDNSLimitExceeded
	}
	v = atomic.AddInt32(&r.limit, -1)
	if v < 1 {
		return ErrDNSLimitExceeded
	}
	return nil
}

// LookupTXT returns the DNS TXT records for the given domain name.
// Returns nil and ErrDNSLimitExceeded if total number of lookups made
// by underlying resolver exceed the limit.
func (r *LimitedResolver) LookupTXT(name string) ([]string, error) {
	if err := r.checkAndDecrLimit(); err != nil {
		return nil, err
	}
	return r.resolver.LookupTXT(name)
}

// Exists is used for a DNS A RR lookup (even when the
// connection type is IPv6).  If any A record is returned, this
// mechanism matches.
// Returns false and ErrDNSLimitExceeded if total number of lookups made
// by underlying resolver exceed the limit.
func (r *LimitedResolver) Exists(name string) (bool, error) {
	if err := r.checkAndDecrLimit(); err != nil {
		return false, err
	}
	return r.resolver.Exists(name)
}

// MatchIP provides an address lookup, which should be done on the name
// using the type of lookup (A or AAAA).
// Then IPMatcherFunc used to compare checked IP to the returned address(es).
// If any address matches, the mechanism matches
// Returns false and ErrDNSLimitExceeded if total number of lookups made
// by underlying resolver exceed the limit.
func (r *LimitedResolver) MatchIP(name string, match IPMatcherFunc) (bool, error) {
	if err := r.checkAndDecrLimit(); err != nil {
		return false, err
	}
	return r.resolver.MatchIP(name, match)
}

// MatchMX is similar to MatchIP but first performs an MX lookup on the
// name.  Then it performs an address lookup on each MX name returned.
// Then IPMatcherFunc used to compare checked IP to the returned address(es).
// If any address matches, the mechanism matches
// Returns false and ErrDNSLimitExceeded if total number of lookups made
// by underlying resolver exceed the limit.
func (r *LimitedResolver) MatchMX(name string, match IPMatcherFunc) (bool, error) {
	if err := r.checkAndDecrLimit(); err != nil {
		return false, err
	}
	return r.resolver.MatchMX(name, match)
}
