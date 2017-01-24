package spf

import "sync/atomic"

type limitedResolver struct {
	limit    int32
	resolver Resolver
}

func (r *limitedResolver) checkAndDecrLimit() error {
	v := atomic.LoadInt32(&r.limit)
	if v < 1 {
		return errDNSLimitExceeded
	}
	v = atomic.AddInt32(&r.limit, -1)
	if v < 1 {
		return errDNSLimitExceeded
	}
	return nil
}

func (r *limitedResolver) LookupTXT(name string) ([]string, error) {
	if err := r.checkAndDecrLimit(); err != nil {
		return nil, err
	}
	return r.resolver.LookupTXT(name)
}

func (r *limitedResolver) Exists(name string) (bool, error) {
	if err := r.checkAndDecrLimit(); err != nil {
		return false, err
	}
	return r.resolver.Exists(name)
}

func (r *limitedResolver) MatchIP(name string, match IPMatcherFunc) (bool, error) {
	if err := r.checkAndDecrLimit(); err != nil {
		return false, err
	}
	return r.resolver.MatchIP(name, match)
}

func (r *limitedResolver) MatchMX(name string, match IPMatcherFunc) (bool, error) {
	if err := r.checkAndDecrLimit(); err != nil {
		return false, err
	}
	return r.resolver.MatchMX(name, match)
}
