package spf

import (
	"net"

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
// As per RFC 7208 it will accept 3 parameters (strings):
// <ip> - IP{4,6} address of the connected client
// <domain> - domain portion of the MAIL FROM or HELO identity
// <sender> - MAIL FROM or HELO identity
// All the parameters should be parsed and dereferenced from real email fields.
// This means domain should already be extracted from MAIL FROM field so this
// function can focus on the core part.
func checkHost(ip net.IP, domain, sender string) (SPFResult, error) {

	// TODO(zaccone) s/_/spfRecord/
	_, dnsErr := dns.LookupSPF(domain)

	if dnsErr != nil {
		switch dnsErr.(type) {
		// as per RFC7208 section 4.4, and DNS query errors result in Temperror
		//result immediately
		case *net.DNSError:
			return Temperror, dnsErr
		default:
			return Permerror, dnsErr

		}
	}
	query := "v=spf1 a -all"
	parser := NewParser(sender, domain, ip, query)

	var result SPFResult = Neutral
	var err error

	if result, err = parser.Parse(); err != nil {
		// handle error, something went wrong.
		// Let's set PermError for now.
		return Permerror, nil
	}

	// check if there is redirect and recursively call check_host with redirect
	// as domain
	if parser.Redirect != nil {
		result, err = checkHost(ip, domain, sender)
	}

	// return SPF evaluation result
	return result, nil
}
