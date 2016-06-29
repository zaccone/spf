package spf

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
)

const spfPrefix = "spf1"

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

type Parser struct {
	Sender      string
	Domain      string
	Ip          net.IP
	Query       string
	Mechanisms  []*Token
	Explanation *Token
	Redirect    *Token
}

func NewParser(sender, domain string, ip net.IP, query string) *Parser {
	return &Parser{sender, domain, ip, query, make([]*Token, 0, 10), nil, nil}
}

func (p *Parser) Parse() (SPFResult, error) {
	var result SPFResult = None
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
		case tIp4:
			matches, result = p.parseIp4(token)
		case tIp6:
			matches, result = p.parseIp6(token)
		case tMX:
			matches, result = p.parseMX(token)
		case tInclude:
			matches, result = p.parseInclude(token)
		}

		if matches {
			return result, nil
		}

	}
	return None, nil
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
					return errors.New("Modifier exp/explanation musn't appear more than once")
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
	if t.Value == spfPrefix {
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

func (p *Parser) parseIp4(t *Token) (bool, SPFResult) {
	result, _ := matchingResult(t.Qualifier)

	if ip, ipnet, err := net.ParseCIDR(t.Value); err == nil {
		if ip.To4() == nil {
			return true, Permerror
		} else {
			return ipnet.Contains(p.Ip), result
		}
	} else {
		if ip := net.ParseIP(t.Value).To4(); ip == nil {
			return true, Permerror
		} else {
			return ip.Equal(p.Ip), result
		}
	}
}

func (p *Parser) parseIp6(t *Token) (bool, SPFResult) {
	result, _ := matchingResult(t.Qualifier)

	if ip, ipnet, err := net.ParseCIDR(t.Value); err == nil {
		if ip.To16() == nil {
			return true, Permerror
		} else {
			return ipnet.Contains(p.Ip), result
		}
	} else {
		ip := net.ParseIP(t.Value)
		if ip.To4() != nil || ip.To16() == nil {
			return true, Permerror
		} else {
			return ip.Equal(p.Ip), result
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
	if ok := p.Ip.To4(); ok != nil {
		isIPv4 = true
	}

	var host string
	var network *net.IPMask
	var ok bool
	ok, host, network = SplitToHostNetwork(domain, isIPv4)

	// return Fail if there was syntax error
	if !ok {
		return true, Fail
	}

	if ips, err := net.LookupIP(host); err != nil {
		//TODO(marek):  confirm SPFResult
		return true, Fail
	} else {
		ipnet := net.IPNet{}
		ipnet.Mask = *network
		for _, address := range ips {
			// skip if Parser.Ip is IPv4 and tested isn't
			if isIPv4 && address.To4() == nil {
				continue
			}
			ipnet.IP = address
			if ipnet.Contains(p.Ip) {
				return true, result
			}
		}
	}
	return false, result
}

func (p *Parser) parseMX(t *Token) (bool, SPFResult) {
	result, _ := matchingResult(t.Qualifier)

	domain := p.setDomain(t)

	var err error
	var mxs []*net.MX

	if mxs, err = net.LookupMX(domain); err != nil {
		// TODO(marek): confirm SPFResult
		return true, Fail
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
					pipe <- p.Ip.Equal(ip)

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
	if includeResult, err := checkHost(p.Ip, domain, p.Sender); err != nil {
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
