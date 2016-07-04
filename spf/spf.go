package spf

import (
	"net"
	"strings"

	"github.com/zaccone/goSPF/dns"
)

type SPFResult int

const (
	Illegal SPFResult = iota

	None
	Neutral
	Pass
	Fail
	Softfail
	Temperror
	Permerror

	// end of SPF
	SPFEnd
)

func (spf SPFResult) String() string {
	switch spf {
	case None:
		return "None"
	case Neutral:
		return "Neutral"
	case Pass:
		return "Pass"
	case Fail:
		return "Fail"
	case Softfail:
		return "Softfail"
	case Temperror:
		return "Temperror"
	case Permerror:
		return "Permerror"
	default:
		return "Permerror"
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
func checkHost(ip net.IP, domain, sender string) (SPFResult, error) {

	/*
			* As per RFC 7208 Section 4.3:
			* If the <domain> is malformed (e.g., label longer than 63
			* characters, zero-length label not at the end, etc.) or is not
			* a multi-label
		    * domain name, [...], check_host() immediately returns None
	*/
	if !dns.IsDomainName(domain) {
		return None, nil
	}

	query, dnsErr := dns.LookupSPF(domain)

	if dnsErr != nil {
		switch dnsErr.(type) {
		// as per RFC7208 section 4.4, DNS query errors result in Temperror
		//result immediately
		case *net.DNSError:
			/*
			* As per RFC 7208 Section 4.3:
			* [...] or if the DNS lookup returns "Name Error" (RCODE 3, also
			* known as "NXDOMAIN" [RFC2308]), check_host() immediately returns
			* the result "none".
			*
			* Sadly, net.DNSError does not provide RCODE statuses, however
			* reading it' implementation we can deduct that
			* DNSError.Err string is set to "no such host" upon RCODE 3.
			* See
			* https://github.com/golang/go/blob/master/src/net/dnsclient.go#L43
			* for the logic implementation and
			* https://github.com/golang/go/blob/master/src/net/net.go#L547 for
			* `errNoSuchHost` error definition.
			*
			* On the other had, any other RCODE not equal to 0 (success, so no
			* error) or 3 or timeout occurs, check_host() should return
			* Temperror which we handle too.
			 */
			if dnsErr.(*net.DNSError).Err == "no such host" {
				return None, nil
			} else {
				return Temperror, nil
			}
		default:
			return Permerror, nil

		}
	}

	spfQuery := strings.Join(query, " ")
	parser := NewParser(sender, domain, ip, spfQuery)

	var result SPFResult = Neutral
	var err error

	if result, err = parser.Parse(); err != nil {
		// handle error, something went wrong.
		// Let's set PermError for now.
		return Permerror, nil
	}

	// return SPF evaluation result
	return result, nil
}
