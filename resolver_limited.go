package spf

import "sync/atomic"

// LimitResolver pass limit number of calls to wrapped resolver.
// All calls over the limit will returns ErrDNSLimitExceeded.
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

func (r *LimitedResolver) LookupTXT(name string) ([]string, error) {
	if err := r.checkAndDecrLimit(); err != nil {
		return nil, err
	}
	return r.resolver.LookupTXT(name)
}

func (r *LimitedResolver) Exists(name string) (bool, error) {
	if err := r.checkAndDecrLimit(); err != nil {
		return false, err
	}
	return r.resolver.Exists(name)
}

func (r *LimitedResolver) MatchIP(name string, match IPMatcherFunc) (bool, error) {
	if err := r.checkAndDecrLimit(); err != nil {
		return false, err
	}
	return r.resolver.MatchIP(name, match)
}

func (r *LimitedResolver) MatchMX(name string, match IPMatcherFunc) (bool, error) {
	if err := r.checkAndDecrLimit(); err != nil {
		return false, err
	}
	return r.resolver.MatchMX(name, match)
}
