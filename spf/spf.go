package spf

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// SPFResult represents SPF defined result - None, Neutral, Pass, Pass, Fail,
// Softfail, Temperror or Permerror
type SPFResult int

// SPFResult available values. Illegal and SPFEnd are used as a guards values
// and should be used for validation checking.
const (
	Illegal SPFResult = iota

	None
	Neutral
	Pass
	Fail
	Softfail
	Temperror
	Permerror

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
func checkHost(ip net.IP, domain, sender string) (SPFResult, string, error) {

	/*
			* As per RFC 7208 Section 4.3:
			* If the <domain> is malformed (e.g., label longer than 63
			* characters, zero-length label not at the end, etc.) or is not
			* a multi-label
		    * domain name, [...], check_host() immediately returns None
	*/
	if !IsDomainName(domain) {
		fmt.Println("Invalid domain")
		return None, "", nil
	}
	domain = NormalizeHost(domain)
	query := new(dns.Msg)
	query.SetQuestion(domain, dns.TypeTXT)
	subQueries := make([]string, 0, 1)
	c := new(dns.Client)
	r, _, err := c.Exchange(query, Nameserver)
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
			return Temperror, "", nil
		} else {
			return None, "", nil
		}
	} else {
		for _, answer := range r.Answer {
			if ans, ok := answer.(*dns.TXT); ok {
				for _, txt := range ans.Txt {
					subQueries = append(subQueries, txt)
				}
			}
		}
	}
	spfQuery := strings.Join(subQueries, " ")
	parser := NewParser(sender, domain, ip, spfQuery)

	var result = Neutral
	var explanation string = ""

	if result, explanation, err = parser.Parse(); err != nil {
		// handle error, something went wrong.
		// Let's set PermError for now.
		return Permerror, "", nil
	}

	// return SPF evaluation result
	return result, explanation, nil
}
