package spf

import "strings"

// addrSpec abstracts Addr-Spec as it defined by RFC5322
// https://tools.ietf.org/html/rfc5322#section-3.4.1
type addrSpec struct {
	local  string
	domain string
}

// parseAddrSpec parses e-mail string address and returns *addrSpec structure.
// The "postmaster" will be used if no local part specified in addr.
// The domain will be used if no domain specified in addr.
// A bare address without @ is interpreted as a HELO domain identity.
func parseAddrSpec(addr, domain string) *addrSpec {
	const postmaster = "postmaster"
	if addr == "" {
		return &addrSpec{postmaster, domain}
	}
	i := strings.LastIndexByte(addr, '@')
	if i < 0 {
		return &addrSpec{postmaster, addr}
	}
	return &addrSpec{nonemptyString(addr[:i], postmaster), nonemptyString(addr[i+1:], domain)}
}
