package spf

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

func matchingResult(qualifier tokenType) (SPFResult, error) {
	if !qualifier.isQualifier() {
		return SPFEnd, errors.New("Not a Qualifier")
	}

	var result SPFResult

	switch qualifier {
	case qPlus:
		result = Pass
	case qMinus:
		result = Fail
	case qQuestionMark:
		result = Neutral
	case qTilde:
		result = Softfail
	}
	return result, nil
}

// Parser represents parsing structure. It keeps all arguments provided by top
// level checkHost method as well as tokenized terms from TXT RR. One should
// call Parser.Parse() for a proper SPF evaluation.
type Parser struct {
	Sender      string
	Domain      string
	IP          net.IP
	Query       string
	Mechanisms  []*Token
	Explanation *Token
	Redirect    *Token
}

// NewParser creates new Parser objects and returns its reference.
// It accepts checkHost() parameters as well as SPF query (fetched from TXT RR
// during initial DNS lookup.
func NewParser(sender, domain string, ip net.IP, query string) *Parser {
	return &Parser{sender, domain, ip, query, make([]*Token, 0, 10), nil, nil}
}

// Parse aggregates all steps required for SPF evaluation.
// After lexing and tokenizing step it sorts tokens (and returns Permerror if
// there is any syntax error) and starts evaluating
// each token (from left to right). Once a token matches Parse stops and
// returns matched result.
func (p *Parser) Parse() (SPFResult, string, error) {
	var result = None
	tokens := Lex(p.Query)

	if err := p.sortTokens(tokens); err != nil {
		return Permerror, "", err
	}
	var matches bool
	for _, token := range p.Mechanisms {
		switch token.Mechanism {

		case tVersion:
			matches, result = p.parseVersion(token)
		case tAll:
			matches, result = p.parseAll(token)
		case tA:
			matches, result = p.parseA(token)
		case tIP4:
			matches, result = p.parseIP4(token)
		case tIP6:
			matches, result = p.parseIP6(token)
		case tMX:
			matches, result = p.parseMX(token)
		case tInclude:
			matches, result = p.parseInclude(token)
		case tExists:
			matches, result = p.parseExists(token)
		}

		if matches {
			if result == Fail && p.Explanation != nil {
				return result, p.handleExplanation(), nil
			}
			return result, "", nil
		}

	}

	result = p.handleRedirect(result)

	return result, "", nil
}

func (p *Parser) sortTokens(tokens []*Token) error {
	all := false
	for _, token := range tokens {
		if token.Mechanism.isErr() {
			return errors.New("Token syntax error")
		} else if token.Mechanism.isMechanism() && all == false {
			p.Mechanisms = append(p.Mechanisms, token)

			if token.Mechanism == tAll {
				all = true
			}
		} else {

			if token.Mechanism == tRedirect {
				if p.Redirect == nil {
					p.Redirect = token
				} else {
					return errors.New("Modifier redirect musn't appear more than once")
				}
			} else if token.Mechanism == tExp {
				if p.Explanation == nil {
					p.Explanation = token
				} else {
					return errors.New("Modifier exp musn't appear more than once")
				}
			}
		}
	}

	if all {
		p.Redirect = nil
	}

	return nil
}

func (p *Parser) setDomain(t *Token) string {
	if !isEmpty(&t.Value) {
		return t.Value
	} else {
		return p.Domain
	}
}

func (p *Parser) parseVersion(t *Token) (bool, SPFResult) {
	if t.Value == "spf1" {
		return false, None
	}
	return true, Permerror
}

func (p *Parser) parseAll(t *Token) (bool, SPFResult) {
	if result, err := matchingResult(t.Qualifier); err != nil {
		return true, Permerror
	} else {
		return true, result
	}
}

func (p *Parser) parseIP4(t *Token) (bool, SPFResult) {
	result, _ := matchingResult(t.Qualifier)

	if ip, ipnet, err := net.ParseCIDR(t.Value); err == nil {
		if ip.To4() == nil {
			return true, Permerror
		} else {
			return ipnet.Contains(p.IP), result
		}
	} else {
		if ip := net.ParseIP(t.Value).To4(); ip == nil {
			return true, Permerror
		} else {
			return ip.Equal(p.IP), result
		}
	}
}

func (p *Parser) parseIP6(t *Token) (bool, SPFResult) {
	result, _ := matchingResult(t.Qualifier)

	if ip, ipnet, err := net.ParseCIDR(t.Value); err == nil {
		if ip.To16() == nil {
			return true, Permerror
		} else {
			return ipnet.Contains(p.IP), result
		}
	} else {
		ip := net.ParseIP(t.Value)
		if ip.To4() != nil || ip.To16() == nil {
			return true, Permerror
		} else {
			return ip.Equal(p.IP), result
		}
	}
}

func (p *Parser) parseA(t *Token) (bool, SPFResult) {

	result, _ := matchingResult(t.Qualifier)
	domain := p.setDomain(t)

	var host string
	var v4Network *net.IPMask
	var v6Network *net.IPMask
	var ok bool
	ips4 := make([]net.IP, 0, 1)
	ips6 := make([]net.IP, 0, 1)
	ok, host, v4Network, v6Network = splitToHostNetwork(domain)
	host = NormalizeHost(host)
	// return Permerror if there was syntax error
	if !ok {
		return true, Permerror
	}

	var queries [2]dns.Msg

	queries[0].SetQuestion(host, dns.TypeA)
	queries[1].SetQuestion(host, dns.TypeAAAA)

	for _, query := range queries {
		c := new(dns.Client)
		r, _, err := c.Exchange(&query, Nameserver)
		if err != nil {
			return true, Temperror
		}

		if r != nil && r.Rcode != dns.RcodeSuccess {
			if r.Rcode != dns.RcodeNameError {
				return true, Temperror
			} else {
				return false, None
			}
		} else {
			for _, answer := range r.Answer {
				if ans, ok := answer.(*dns.A); ok {
					ips4 = append(ips4, ans.A)
				} else if ans, ok := answer.(*dns.AAAA); ok {
					ips6 = append(ips6, ans.AAAA)
				}
			}
		}
	}

	v4Ipnet := net.IPNet{}
	v4Ipnet.Mask = *v4Network

	v6Ipnet := net.IPNet{}
	v6Ipnet.Mask = *v6Network

	for _, address := range ips4 {
		v4Ipnet.IP = address
		if v4Ipnet.Contains(p.IP) {
			return true, result
		}
	}

	for _, address := range ips6 {
		v6Ipnet.IP = address
		if v6Ipnet.Contains(p.IP) {
			return true, result
		}
	}

	return false, result
}

func (p *Parser) parseMX(t *Token) (bool, SPFResult) {
	result, _ := matchingResult(t.Qualifier)

	domain := p.setDomain(t)

	var host string
	var v4Network *net.IPMask
	var v6Network *net.IPMask
	var ok bool
	ok, host, v4Network, v6Network = splitToHostNetwork(domain)
	host = NormalizeHost(host)

	// return Permerror if there was syntax error
	if !ok {
		return true, Permerror
	}

	var err error
	// TODO(zaccone): Ensure returned errors are correct.
	query := new(dns.Msg)
	query.SetQuestion(host, dns.TypeMX)
	c := new(dns.Client)
	response, _, err := c.Exchange(query, Nameserver)
	if err != nil {
		return false, None
	}

	if response != nil && response.Rcode != dns.RcodeSuccess {
		if response.Rcode != dns.RcodeNameError {
			return true, Temperror
		} else {
			return false, None
		}
	}

	mxs := make([]string, 0, len(response.Answer))
	for _, answer := range response.Answer {
		if mx, ok := answer.(*dns.MX); ok {
			mxs = append(mxs, mx.Mx)
		}
	}

	var wg sync.WaitGroup

	pipe := make(chan bool)

	wg.Add(len(mxs))

	go func() {
		wg.Wait()
		close(pipe)
	}()

	for _, mmx := range mxs {
		go func(mx string, v4Network, v6Network *net.IPMask) {
			defer wg.Done()
			mx = NormalizeHost(mx)
			v4Ipnet := net.IPNet{}
			v4Ipnet.Mask = *v4Network

			v6Ipnet := net.IPNet{}
			v6Ipnet.Mask = *v6Network

			ips4 := make([]net.IP, 0, 1)
			ips6 := make([]net.IP, 0, 1)

			var queries [2]dns.Msg

			queries[0].SetQuestion(mx, dns.TypeA)
			queries[1].SetQuestion(mx, dns.TypeAAAA)

			for _, query := range queries {
				c := new(dns.Client)
				response, _, err := c.Exchange(&query, Nameserver)

				if err != nil {
					pipe <- false
					return
				}

				if response != nil && response.Rcode != dns.RcodeSuccess {
					pipe <- false
					return
				}

				for _, answer := range response.Answer {
					if ans, ok := answer.(*dns.A); ok {
						ips4 = append(ips4, ans.A)
					} else if ans, ok := answer.(*dns.AAAA); ok {
						ips6 = append(ips6, ans.AAAA)
					}
				}

			}

			var contains bool

			for _, address := range ips4 {
				v4Ipnet.IP = address
				contains = v4Ipnet.Contains(p.IP)
				pipe <- contains
			}

			for _, address := range ips6 {
				v6Ipnet.IP = address
				contains = v6Ipnet.Contains(p.IP)
				pipe <- contains
			}

		}(mmx, v4Network, v6Network)
	}

	verdict := false
	for subverdict := range pipe {
		verdict = verdict || subverdict
	}
	return verdict, result
}

func (p *Parser) parseInclude(t *Token) (bool, SPFResult) {
	result, _ := matchingResult(t.Qualifier)
	domain := t.Value
	if isEmpty(&domain) {
		return true, Permerror
	}
	matchesInclude := false
	if includeResult, _, err := checkHost(p.IP, domain, p.Sender); err != nil {
		return false, None
	} else { // it's all fine
		switch includeResult {
		case Pass:
			matchesInclude = true
		case Fail, Softfail, Neutral:
			matchesInclude = false
		case Temperror:
			matchesInclude = false
			result = Temperror
		case Permerror, None:
			matchesInclude = false
			result = Permerror
		}
	}

	if matchesInclude {
		return true, result
	}

	return false, None

}

func (p *Parser) parseExists(t *Token) (bool, SPFResult) {
	result, _ := matchingResult(t.Qualifier)
	resolvedDomain, err := ParseMacroToken(p, t)
	if err != nil || isEmpty(&resolvedDomain) {
		return true, Permerror
	}
	resolvedDomain = NormalizeHost(resolvedDomain)
	var queries [2]dns.Msg

	queries[0].SetQuestion(resolvedDomain, dns.TypeA)
	queries[1].SetQuestion(resolvedDomain, dns.TypeAAAA)
	ips := 0
	for _, query := range queries {
		c := new(dns.Client)
		response, _, err := c.Exchange(&query, Nameserver)
		if err != nil {
			return true, Temperror
		}

		if response != nil && response.Rcode != dns.RcodeSuccess {
			if response.Rcode == dns.RcodeNameError {
				return false, result
			} else {
				return true, Temperror
			}
		} else {
			ips += len(response.Answer)
		}
		/* We can check prematurely and avoid futher DNS calls if matching
		* hosts were already found.
		 */
		if ips > 0 {
			return true, result
		}
	}

	return false, result
}

func (p *Parser) handleRedirect(oldResult SPFResult) SPFResult {
	var err error
	result := oldResult
	if result != None || p.Redirect == nil {
		return result
	}

	redirectDomain := p.Redirect.Value

	if result, _, err = checkHost(p.IP, redirectDomain, p.Sender); err != nil {
		//TODO(zaccone): confirm result value
		result = Permerror
	} else if result == None || result == Permerror {
		// See RFC7208, section 6.1
		//
		// if no SPF record is found, or if the <target-name> is malformed, the
		// result is a "permerror" rather than "none".
		result = Permerror
	}

	return result
}

func (p *Parser) handleExplanation() string {
	resolvedDomain, err := ParseMacroToken(p, p.Explanation)
	if err != nil || isEmpty(&resolvedDomain) {
		// TODO(zaccone): Should we return some internal error
		return ""
	}
	resolvedDomain = NormalizeHost(resolvedDomain)
	query := new(dns.Msg)
	query.SetQuestion(Nameserver, dns.TypeTXT)
	c := new(dns.Client)
	response, _, err := c.Exchange(query, Nameserver)
	if err != nil || (response != nil && response.Rcode != dns.RcodeSuccess) {
		return ""
	}

	explanation := make([]string, 0, len(response.Answer))
	for _, answer := range response.Answer {
		if q, ok := answer.(*dns.TXT); ok {
			for _, txt := range q.Txt {
				explanation = append(explanation, txt)
			}
		}
	}

	// RFC 7208, section 6.2 specifies that result string should be
	// concatenated with no spaces.
	parsedExplanation, err := ParseMacro(p, strings.Join(explanation, ""))
	if err != nil {
		return ""
	}
	return parsedExplanation
}

func splitToHostNetwork(domain string) (bool, string, *net.IPMask, *net.IPMask) {
	var host string

	const v4Len = 32
	n4s := "32"

	const v6Len = 128
	n6s := "128"

	line := strings.SplitN(domain, "/", 3)
	if len(line) == 3 {
		host, n4s, n6s = line[0], line[1], line[2]
	} else if len(line) == 2 {
		host, n4s = line[0], line[1]
	} else {
		host = line[0]
	}

	if !IsDomainName(host) {
		return false, host, nil, nil
	}

	if isEmpty(&n4s) {
		// empty values default to maximum netmask
		n4s = "32"
	}

	if isEmpty(&n6s) {
		// empty values default to maximum netmask
		n6s = "128"
	}

	var err error
	var n4 int
	var n6 int

	var v4Network net.IPMask
	var v6Network net.IPMask

	if n4, err = strconv.Atoi(n4s); err != nil {
		return false, host, nil, nil
	} else if n4 < 0 || n4 > v4Len {
		return false, host, nil, nil
	} else {
		v4Network = net.CIDRMask(n4, v4Len)
	}

	if n6, err = strconv.Atoi(n6s); err != nil {
		return false, host, nil, nil
	} else if n6 < 0 || n6 > v6Len {
		return false, host, nil, nil
	} else {
		v6Network = net.CIDRMask(n6, v6Len)
	}

	return true, host, &v4Network, &v6Network

}
