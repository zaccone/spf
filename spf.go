package spf

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// Errors could be used for root couse analysis
var (
	ErrDNSTemperror      = errors.New("temporary DNS error")
	ErrDNSPermerror      = errors.New("permanent DNS error")
	ErrInvalidDomain     = errors.New("invalid domain name")
	errInvalidCIDRLength = errors.New("invalid CIDR length")
	errDNSLimitExceeded  = errors.New("limit exceeded")
)

// IPMatcherFunc returns true if ip matches to implemented rules
type IPMatcherFunc func(ip net.IP) bool

// Resolver provides abstraction for DNS layer
type Resolver interface {
	// LookupTXT returns the DNS TXT records for the given domain name.
	LookupTXT(string) ([]string, error)
	// Exists is used for a DNS A RR lookup (even when the
	// connection type is IPv6).  If any A record is returned, this
	// mechanism matches.
	Exists(string) (bool, error)
	// MatchIP provides an address lookup, which should be done on the name
	// using the type of lookup (A or AAAA).
	// Then IPMatcherFunc used to compare checked IP to the returned address(es).
	// If any address matches, the mechanism matches
	MatchIP(string, IPMatcherFunc) (bool, error)
	// MatchMX is similar to MatchIP but first performs an MX lookup on the
	// name.  Then it performs an address lookup on each MX name returned.
	// Then IPMatcherFunc used to compare checked IP to the returned address(es).
	// If any address matches, the mechanism matches
	MatchMX(string, IPMatcherFunc) (bool, error)
}

var defaultResolver Resolver = &DNSResolver{}

// Result represents result of SPF evaluation as it defined by RFC7208
// https://tools.ietf.org/html/rfc7208#section-2.6
type Result int

const (
	_ Result = iota // TODO was Illegal, saved for padding only, however it is not used internally and could be removed

	// None means either (a) no syntactically valid DNS
	// domain name was extracted from the SMTP session that could be used
	// as the one to be authorized, or (b) no SPF records were retrieved
	// from the DNS.
	None
	// Neutral result means the ADMD has explicitly stated that it
	// is not asserting whether the IP address is authorized.
	Neutral
	// Pass result is an explicit statement that the client
	// is authorized to inject mail with the given identity.
	Pass
	// Fail result is an explicit statement that the client
	// is not authorized to use the domain in the given identity.
	Fail
	// Softfail result is a weak statement by the publishing ADMD
	// that the host is probably not authorized.  It has not published
	// a stronger, more definitive policy that results in a "fail".
	Softfail
	// Temperror result means the SPF verifier encountered a transient
	// (generally DNS) error while performing the check.
	// A later retry may succeed without further DNS operator action.
	Temperror
	// Permerror result means the domain's published records could
	// not be correctly interpreted.
	// This signals an error condition that definitely requires
	// DNS operator intervention to be resolved.
	Permerror

	internalError
)

// String returns string form of the result as defined by RFC7208
// https://tools.ietf.org/html/rfc7208#section-2.6
func (r Result) String() string {
	switch r {
	case None:
		return "none"
	case Neutral:
		return "neutral"
	case Pass:
		return "pass"
	case Fail:
		return "fail"
	case Softfail:
		return "softfail"
	case Temperror:
		return "temperror"
	case Permerror:
		return "permerror"
	default:
		return strconv.Itoa(int(r))
	}
}

// CheckHost is a main entrypoint function evaluating e-mail with regard to SPF
// As per RFC 7208 it will accept 3 parameters:
// <ip> - IP{4,6} address of the connected client
// <domain> - domain portion of the MAIL FROM or HELO identity
// <sender> - MAIL FROM or HELO identity
// All the parameters should be parsed and dereferenced from real email fields.
// This means domain should already be extracted from MAIL FROM field so this
// function can focus on the core part.
func CheckHost(ip net.IP, domain, sender string) (Result, string, error) {
	return checkHost(ip, domain, sender, &limitedResolver{
		limit:    10,
		resolver: defaultResolver,
	})
}

func checkHost(ip net.IP, domain, sender string, resolver Resolver) (Result, string, error) {
	/*
	* As per RFC 7208 Section 4.3:
	* If the <domain> is malformed (e.g., label longer than 63
	* characters, zero-length label not at the end, etc.) or is not
	* a multi-label
	* domain name, [...], check_host() immediately returns None
	 */
	if !isDomainName(domain) {
		return None, "", ErrInvalidDomain
	}

	txts, err := resolver.LookupTXT(normalizeFQDN(domain))
	switch err {
	case nil:
		// continue
	case errDNSLimitExceeded:
		return Permerror, "", err
	case ErrDNSPermerror:
		return None, "", nil
	default:
		return Temperror, "", err
	}

	return newParser(sender, domain, ip, strings.Join(txts, ""), resolver).parse()
}

// isDomainName is a 1:1 copy of implementation from
// original golang codebase:
// https://github.com/golang/go/blob/master/src/net/dnsclient.go#L116
// It validates s string for conditions specified in RFC 1035 and RFC 3696
func isDomainName(s string) bool {
	// See RFC 1035, RFC 3696.
	if len(s) == 0 {
		return false
	}
	if len(s) > 255 {
		return false
	}

	last := byte('.')
	ok := false // Ok once we've seen a letter.
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			ok = true
			partlen++
		case '0' <= c && c <= '9':
			// fine
			partlen++
		case c == '-':
			// Byte before dash cannot be dot.
			if last == '.' {
				return false
			}
			partlen++
		case c == '.':
			// Byte before dot cannot be dot, dash.
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}

	return ok
}

// normalizeFQDN appends a root domain (a dot) to the FQDN.
func normalizeFQDN(name string) string {
	if len(name) == 0 {
		return ""
	}
	if name[len(name)-1] != '.' {
		return name + "."
	}
	return name
}
