package spf

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/zaccone/goSPF/dns"
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
func (p *Parser) Parse() (SPFResult, error) {
	var result = None
	tokens := Lex(p.Query)

	if err := p.sortTokens(tokens); err != nil {
		return Permerror, err
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
		}

		if matches {
			return result, nil
		}

	}

	result = p.handleRedirect(result)

	return result, nil
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

	SplitToHostNetwork := func(domain string, isIPv4 bool) (bool, string, *net.IPMask) {
		var host string

		addrLen := 128
		ns := "128"

		if isIPv4 {
			addrLen = 32
			ns = "32"
		}

		r := strings.SplitN(domain, "/", 2)

		if len(r) == 2 {
			host, ns = r[0], r[1]
		} else {
			host = r[0]
		}

		if !dns.IsDomainName(host) {
			return false, host, nil
		}

		// if the network mask is invalid it means data provided in the SPF
		//term is invalid and there is syntax error.
		if n, err := strconv.Atoi(ns); err != nil {
			return false, host, &net.IPMask{}
		} else {

			// network mask must be within [0, 32/128]
			if n < 0 || n > addrLen {
				return false, host, &net.IPMask{}
			}

			// looks like we are all OK
			network := net.CIDRMask(n, addrLen)
			return true, host, &network
		}
	}

	result, _ := matchingResult(t.Qualifier)
	domain := p.setDomain(t)

	var isIPv4 bool
	if ok := p.IP.To4(); ok != nil {
		isIPv4 = true
	}

	var host string
	var network *net.IPMask
	var ok bool
	ok, host, network = SplitToHostNetwork(domain, isIPv4)

	// return Permerror if there was syntax error
	if !ok {
		return true, Permerror
	}

	if ips, err := net.LookupIP(host); err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.Err != dns.RCODE3 || dnsErr.Timeout() {
				return true, Temperror
			} else if dnsErr.Err == dns.RCODE3 {
				return false, None
			}
		}
		//TODO(marek): Apparently non DNS error, what shall we do then?
		return false, None
	} else {
		ipnet := net.IPNet{}
		ipnet.Mask = *network
		for _, address := range ips {
			// skip if Parser.IP is IPv4 and tested isn't
			if isIPv4 && address.To4() == nil {
				continue
			}
			ipnet.IP = address
			if ipnet.Contains(p.IP) {
				return true, result
			}
		}
	}
	return false, result
}

func (p *Parser) parseMX(t *Token) (bool, SPFResult) {
	result, _ := matchingResult(t.Qualifier)

	domain := p.setDomain(t)
	if !dns.IsDomainName(domain) {
		return true, Permerror
	}

	var err error
	var mxs []*net.MX

	if mxs, err = net.LookupMX(domain); err != nil {

		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.Err != dns.RCODE3 || dnsErr.Timeout() {
				return true, Temperror
			} else if dnsErr.Err == dns.RCODE3 {
				return false, None
			}
		}

		return false, None
	}

	var wg sync.WaitGroup

	pipe := make(chan bool)

	wg.Add(len(mxs))

	for _, mmx := range mxs {
		go func(mx *net.MX) {
			defer wg.Done()

			if ips, err := net.LookupIP(mx.Host); err != nil {
				//TODO(marek): Log DNS lookup error
				return
			} else {
				for _, ip := range ips {
					pipe <- p.IP.Equal(ip)

				}
			}
		}(mmx)
	}

	go func() {
		wg.Wait()
		close(pipe)
	}()

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
	if includeResult, err := checkHost(p.IP, domain, p.Sender); err != nil {
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

func (p *Parser) handleRedirect(oldResult SPFResult) SPFResult {
	var err error
	result := oldResult
	if result != None || p.Redirect == nil {
		return result
	}

	redirectDomain := p.Redirect.Value

	if result, err = checkHost(p.IP, redirectDomain, p.Sender); err != nil {
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
