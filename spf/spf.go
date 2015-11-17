package spf

import (
	"log"
	"net"

	"github.com/zaccone/goSPF/mail"
	"github.com/zaccone/goSPF/spf"
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

func (spf *SPFResult) String() string {
	var str string = nil
	switch spf {
	case None:
		str = "None"
	case Neutral:
		str = "Neutral"
	case Pass:
		str = "Pass"
	case Fail:
		str = "Fail"
	case Temperror:
		str = "Temperror"
	case Permerror:
		str = "Permerror"
	default:
		str = "Permerror"
	}

	return str

}

// CheckHost is a main entrypoint function evaluating e-mail with regard to SPF
// As per RFC 7208 it will accept 3 parameters (strings):
// <ip> - IP{4,6} address of the connected client
// <domain> - domain portion of the MAIL FROM or HELO identity
// <sender> - MAIL FROM or HELO identity
// All the parameters should be parsed and dereferenced from real email fields.
// This means domain should already be extracted from MAIL FROM field so this
// function can focus on the core part.
func checkHost(ip, domain, sender string) (SPFResult, error) {

	spfRecord, dnsErr = spf.LookupSPF(domain)

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

}
