package spf

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// Result represents result of SPF evaluation as it defined by RFC7208
// https://tools.ietf.org/html/rfc7208#section-2.6
type Result int

const (
	_ Result = iota // TODO was Illegal, could be removed

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
func (spf Result) String() string {
	switch spf {
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
		return strconv.Itoa(int(spf))
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
func CheckHost(ip net.IP, domain, sender string, cfg *config) (Result, string, error) {

	/*
	* As per RFC 7208 Section 4.3:
	* If the <domain> is malformed (e.g., label longer than 63
	* characters, zero-length label not at the end, etc.) or is not
	* a multi-label
	* domain name, [...], check_host() immediately returns None
	 */
	if !isDomainName(domain) {
		return None, "", fmt.Errorf("Invalid domain %v", domain)
	}
	domain = normalizeHost(domain)
	query := new(dns.Msg)
	query.SetQuestion(domain, dns.TypeTXT)
	c := new(dns.Client)
	r, _, err := c.Exchange(query, cfg.dnsAddr)
	if err != nil {
		return Temperror, "", err
	}

	/*
	* As per RFC 7208 Section 4.3:
	* [...] or if the DNS lookup returns "Name Error" (RCODE 3, also
	* known as "NXDOMAIN" [RFC2308]), check_host() immediately returns
	* the result "none".
	*
	* On the other had, any other RCODE not equal to 0 (success, so no
	* error) or 3 or timeout occurs, check_host() should return
	* Temperror which we handle too.
	 */
	if r != nil && r.Rcode != dns.RcodeSuccess {
		if r.Rcode != dns.RcodeNameError {
			return Temperror, "",
				fmt.Errorf("unsuccessful DNS response, code %d", r.Rcode)
		}
		return None, "", nil

	}

	subQueries := make([]string, 0, 1)
	for _, answer := range r.Answer {
		if ans, ok := answer.(*dns.TXT); ok {
			subQueries = append(subQueries, ans.Txt...)
		}
	}

	spfQuery := strings.Join(subQueries, "")
	parser := newParser(sender, domain, ip, spfQuery, cfg)

	return parser.parse()
}
