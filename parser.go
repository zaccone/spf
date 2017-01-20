package spf

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

func matchingResult(qualifier tokenType) (SPFResult, error) {
	if !qualifier.isQualifier() {
		return SPFEnd, fmt.Errorf("invalid qualifier (%d)", qualifier)
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

// ParseError represents parsing error, it holds reference to faulty token
// as well as error describing fault
type ParseError struct {
	token *Token
	err   error
}

func (pe ParseError) Error() string {
	return fmt.Sprintf("parse error for token %v: %v", pe.token, pe.err.Error())
}

// Parser represents parsing structure. It keeps all arguments provided by top
// level CheckHost method as well as tokenized terms from TXT RR. One should
// call Parser.Parse() for a proper SPF evaluation.
type Parser struct {
	Sender      string
	Domain      string
	IP          net.IP
	Query       string
	Mechanisms  []*Token
	Explanation *Token
	Redirect    *Token
	Config      *Config
}

// NewParser creates new Parser objects and returns its reference.
// It accepts CheckHost() parameters as well as SPF query (fetched from TXT RR
// during initial DNS lookup.
func NewParser(sender, domain string, ip net.IP, query string, config *Config) *Parser {
	return &Parser{sender, domain, ip, query, make([]*Token, 0, 10), nil, nil, config}
}

// Parse aggregates all steps required for SPF evaluation.
// After lexing and tokenizing step it sorts tokens (and returns Permerror if
// there is any syntax error) and starts evaluating
// each token (from left to right). Once a token matches Parse stops and
// returns matched result.
func (p *Parser) Parse() (SPFResult, string, error) {
	tokens := Lex(p.Query)

	if err := p.sortTokens(tokens); err != nil {
		return Permerror, "", err
	}

	var result = None
	var matches bool
	var err error

	for _, token := range p.Mechanisms {
		switch token.Mechanism {
		case tVersion:
			matches, result, err = p.parseVersion(token)
		case tAll:
			matches, result, err = p.parseAll(token)
		case tA:
			matches, result, err = p.parseA(token)
		case tIP4:
			matches, result, err = p.parseIP4(token)
		case tIP6:
			matches, result, err = p.parseIP6(token)
		case tMX:
			matches, result, err = p.parseMX(token)
		case tInclude:
			matches, result, err = p.parseInclude(token)
		case tExists:
			matches, result, err = p.parseExists(token)
		}

		if matches {
			if result == Fail && p.Explanation != nil {
				explanation, expError := p.handleExplanation()
				return result, explanation, expError
			}
			return result, "", err
		}

	}

	result, err = p.handleRedirect(result)

	return result, "", err
}

func (p *Parser) sortTokens(tokens []*Token) error {
	all := false
	for _, token := range tokens {
		if token.Mechanism.isErr() {
			return fmt.Errorf("syntax error for token: %v", token.Value)
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
					return errors.New("modifier redirect musn't appear more than once")
				}
			} else if token.Mechanism == tExp {
				if p.Explanation == nil {
					p.Explanation = token
				} else {
					return errors.New("modifier exp musn't appear more than once")
				}
			}
		}
	}

	if all {
		p.Redirect = nil
	}

	return nil
}

func safeString(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (p *Parser) parseVersion(t *Token) (bool, SPFResult, error) {
	if t.Value == "spf1" {
		return false, None, nil
	}
	return true, Permerror, ParseError{t,
		fmt.Errorf("invalid spf qualifier: %v", t.Value)}
}

func (p *Parser) parseAll(t *Token) (bool, SPFResult, error) {
	result, err := matchingResult(t.Qualifier)
	if err != nil {
		return true, Permerror, ParseError{t, err}
	}
	return true, result, nil

}

func (p *Parser) parseIP4(t *Token) (bool, SPFResult, error) {
	result, _ := matchingResult(t.Qualifier)

	if ip, ipnet, err := net.ParseCIDR(t.Value); err == nil {
		if ip.To4() == nil {
			return true, Permerror, ParseError{t, errors.New("address isn't ipv4")}
		}
		return ipnet.Contains(p.IP), result, nil
	}

	ip := net.ParseIP(t.Value).To4()
	if ip == nil {
		return true, Permerror, ParseError{t, errors.New("address isn't ipv4")}
	}
	return ip.Equal(p.IP), result, nil
}

func (p *Parser) parseIP6(t *Token) (bool, SPFResult, error) {
	result, _ := matchingResult(t.Qualifier)

	if ip, ipnet, err := net.ParseCIDR(t.Value); err == nil {
		if ip.To16() == nil {
			return true, Permerror, ParseError{t, errors.New("address isn't ipv6")}
		}
		return ipnet.Contains(p.IP), result, nil

	}

	ip := net.ParseIP(t.Value)
	if ip.To4() != nil || ip.To16() == nil {
		return true, Permerror, ParseError{t, errors.New("address isn't ipv6")}
	}
	return ip.Equal(p.IP), result, nil

}

func (p *Parser) parseA(t *Token) (bbb bool, rrr SPFResult, eee error) {
	result, _ := matchingResult(t.Qualifier)
	var (
		host      string
		v4Network net.IPMask
		v6Network net.IPMask
		ok        bool
		err       error
	)
	ok, host, v4Network, v6Network, err = splitToHostNetwork(safeString(t.Value, p.Domain))
	host = NormalizeHost(host)
	// return Permerror if there was syntax error
	if !ok {
		return true, Permerror, ParseError{t, err}
	}

	ip4Net := net.IPNet{
		Mask: v4Network,
	}

	ip6Net := net.IPNet{
		Mask: v6Network,
	}

	var queries [2]dns.Msg
	queries[0].SetQuestion(host, dns.TypeA)
	queries[1].SetQuestion(host, dns.TypeAAAA)
	for _, query := range queries {
		c := new(dns.Client)
		r, _, err := c.Exchange(&query, p.Config.Nameserver)
		if err != nil {
			return true, Temperror, ParseError{t, err}
		}

		if r != nil && r.Rcode != dns.RcodeSuccess {
			if r.Rcode != dns.RcodeNameError {
				return true, Temperror, ParseError{t,
					fmt.Errorf("unsuccessful DNS response, code %d", r.Rcode)}
			}
			return false, None, nil
		}
		for _, a := range r.Answer {
			switch t := a.(type) {
			case *dns.A:
				ip4Net.IP = t.A
				if !ip4Net.Contains(p.IP) {
					continue
				}
				return true, result, nil
			case *dns.AAAA:
				ip6Net.IP = t.AAAA
				if !ip6Net.Contains(p.IP) {
					continue
				}
				return true, result, nil
			}
		}
	}

	return false, result, nil
}

func (p *Parser) parseMX(t *Token) (bool, SPFResult, error) {
	result, _ := matchingResult(t.Qualifier)

	var (
		host    string
		ip4Mask net.IPMask
		ip6Mask net.IPMask
		ok      bool
		err     error
	)
	ok, host, ip4Mask, ip6Mask, err = splitToHostNetwork(safeString(t.Value, p.Domain))
	host = NormalizeHost(host)

	// return Permerror if there was syntax error
	if !ok {
		return true, Permerror, ParseError{t, err}
	}

	// TODO(zaccone): Ensure returned errors are correct.
	query := new(dns.Msg)
	query.SetQuestion(host, dns.TypeMX)
	c := new(dns.Client)
	response, _, err := c.Exchange(query, p.Config.Nameserver)
	if err != nil {
		return false, None, ParseError{t, err}
	}

	if response != nil && response.Rcode != dns.RcodeSuccess {
		if response.Rcode != dns.RcodeNameError {
			return true, Temperror, ParseError{t,
				fmt.Errorf("unsuccessful DNS response, code %d", response.Rcode)}
		}
		return false, None, ParseError{t, err}

	}

	if len(response.Answer) == 0 {
		return false, result, nil
	}

	firstMatch := func(h string, ip4Mask, ip6Mask net.IPMask) bool {
		ip4Net := net.IPNet{
			Mask: ip4Mask,
		}

		ip6Net := net.IPNet{
			Mask: ip6Mask,
		}

		var queries [2]dns.Msg

		queries[0].SetQuestion(h, dns.TypeA)
		queries[1].SetQuestion(h, dns.TypeAAAA)

		c := new(dns.Client)
		for _, query := range queries {
			response, _, err := c.Exchange(&query, p.Config.Nameserver)

			if err != nil {
				return false
			}

			if response != nil && response.Rcode != dns.RcodeSuccess {
				return false
			}

			for _, a := range response.Answer {
				switch t := a.(type) {
				case *dns.A:
					ip4Net.IP = t.A
					if !ip4Net.Contains(p.IP) {
						continue
					}
					return true
				case *dns.AAAA:
					ip6Net.IP = t.AAAA
					if !ip6Net.Contains(p.IP) {
						continue
					}
					return true
				}
			}
		}

		return false
	}

	var wg sync.WaitGroup
	hits := make(chan bool)
	for _, a := range response.Answer {
		mx, ok := a.(*dns.MX)
		if !ok {
			continue
		}
		wg.Add(1)
		go func(h string, m4, m6 net.IPMask) {
			hit := firstMatch(h, m4, m6)
			hits <- hit
			wg.Done()
		}(mx.Mx, ip4Mask, ip6Mask)
	}

	go func() {
		wg.Wait()
		close(hits)
	}()

	for hit := range hits {
		if hit {
			return true, result, nil
		}
	}
	return false, result, nil
}

func (p *Parser) parseInclude(t *Token) (bool, SPFResult, error) {
	result, _ := matchingResult(t.Qualifier)
	domain := t.Value
	if isEmpty(&domain) {
		return true, Permerror, ParseError{t, errors.New("empty domain")}
	}
	matchesInclude := false
	includeResult, _, err := CheckHost(p.IP, domain, p.Sender, p.Config)
	if err != nil {
		return false, None, ParseError{t, err}
	}

	// it's all fine
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

	if matchesInclude {
		return true, result, nil
	}
	return false, None, nil
}

func (p *Parser) parseExists(t *Token) (bool, SPFResult, error) {
	result, _ := matchingResult(t.Qualifier)
	resolvedDomain, err := ParseMacroToken(p, t)
	if err != nil {
		return true, Permerror, ParseError{t, err}
	} else if isEmpty(&resolvedDomain) {
		return true, Permerror, ParseError{t, errors.New("empty domain")}
	}
	resolvedDomain = NormalizeHost(resolvedDomain)
	var queries [2]dns.Msg

	queries[0].SetQuestion(resolvedDomain, dns.TypeA)
	queries[1].SetQuestion(resolvedDomain, dns.TypeAAAA)
	for _, query := range queries {
		c := new(dns.Client)
		response, _, err := c.Exchange(&query, p.Config.Nameserver)
		if err != nil {
			return true, Temperror, ParseError{t, err}
		}

		if response != nil && response.Rcode != dns.RcodeSuccess {
			if response.Rcode == dns.RcodeNameError {
				return false, result, nil
			}
			return true, Temperror, ParseError{t,
				fmt.Errorf("unsuccessful DNS response, code %d", response.Rcode)}
		}
		/* We can check prematurely and avoid further DNS calls if matching
		 * hosts were already found.
		 */
		if len(response.Answer) > 0 {
			return true, result, nil
		}
	}

	return false, result, nil
}

func (p *Parser) handleRedirect(oldResult SPFResult) (SPFResult, error) {
	var err error
	result := oldResult
	if result != None || p.Redirect == nil {
		return result, nil
	}

	redirectDomain := p.Redirect.Value

	if result, _, err = CheckHost(p.IP, redirectDomain, p.Sender, p.Config); err != nil {
		//TODO(zaccone): confirm result value
		result = Permerror
	} else if result == None || result == Permerror {
		// See RFC7208, section 6.1
		//
		// if no SPF record is found, or if the <target-name> is malformed, the
		// result is a "permerror" rather than "none".
		result = Permerror
	}

	return result, err
}

func (p *Parser) handleExplanation() (string, error) {
	resolvedDomain, err := ParseMacroToken(p, p.Explanation)
	if err != nil {
		return "", ParseError{p.Explanation, err}
	} else if isEmpty(&resolvedDomain) {
		return "", ParseError{p.Explanation, errors.New("empty domain")}
	}
	resolvedDomain = NormalizeHost(resolvedDomain)
	query := new(dns.Msg)
	query.SetQuestion(resolvedDomain, dns.TypeTXT)
	c := new(dns.Client)
	response, _, err := c.Exchange(query, p.Config.Nameserver)
	if err != nil {
		return "", ParseError{p.Explanation, err}
	} else if response != nil && response.Rcode != dns.RcodeSuccess {
		return "", ParseError{p.Explanation,
			fmt.Errorf("unsuccessful DNS response, code %d", response.Rcode)}
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
		return "", ParseError{p.Explanation, err}
	}
	return parsedExplanation, nil
}

func splitToHostNetwork(domain string) (bool, string, net.IPMask, net.IPMask, error) {
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
		return false, host, nil, nil, fmt.Errorf("invalid hostname %v", host)
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
		return false, host, nil, nil,
			fmt.Errorf("error converting %v to int: %v",
				n4s, err.(*strconv.NumError).Err)
	} else if n4 < 0 || n4 > v4Len {
		return false, host, nil, nil,
			fmt.Errorf("netmask out of ipv4 range: %d", n4)
	} else {
		v4Network = net.CIDRMask(n4, v4Len)
	}

	if n6, err = strconv.Atoi(n6s); err != nil {
		return false, host, nil, nil,
			fmt.Errorf("error converting %v to int: %v",
				n6s, err.(*strconv.NumError).Err)
	} else if n6 < 0 || n6 > v6Len {
		return false, host, nil, nil,
			fmt.Errorf("netmask out of ipv6 range: %d", n6)
	} else {
		v6Network = net.CIDRMask(n6, v6Len)
	}

	return true, host, v4Network, v6Network, nil
}
