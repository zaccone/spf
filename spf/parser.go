package spf

import (
	"errors"
	"net"
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
	var result SPFResult
	tokens := Lex(p.Query)

	if err := p.sortTokens(tokens); err != nil {
		return Permerror, err
	}

	for _, token := range p.Mechanisms {
		switch token.Mechanism {
		/*
			case tVersion:
				result = p.parseVersion(token)
			case tAll:
				result = p.parseAll(token)
			case tA:
				result = p.parseA(token)
			case tIp4:
				result = p.parseIp4(token)
			case tIp6:
				result = p.parseIp6(token)
			case tMX:
				result = p.parseMX(token)
			case tPTR:
				result = p.parsePTR(token)
			case tInclude:
				result = p.parseInclude(token)
		*/
		}

	}
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
		return true, None
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

// TODO(marek): This function will not detect that address is v4 instead of v6
func (p *Parser) parseIp6(t *Token) (bool, SPFResult) {
	result, _ := matchingResult(t.Qualifier)

	if ip, ipnet, err := net.ParseCIDR(t.Value); err == nil {
		if ip.To16() == nil {
			return true, Permerror
		} else {
			return ipnet.Contains(p.Ip), result
		}
	} else {
		if ip := net.ParseIP(t.Value).To16(); ip == nil {
			return true, Permerror
		} else {
			return ip.Equal(p.Ip), result
		}
	}
}

func (p *Parser) parseA(t *Token) (bool, SPFResult) {
	result, _ := matchingResult(t.Qualifier)

	var host string
	if !isEmpty(&t.Value) {
		host = t.Value
	} else {
		host = p.Domain
	}

	if ips, err := net.LookupIP(host); err != nil {
		//TODO(marek): Handle error here
		panic(err)
	} else {
		var wg sync.WaitGroup
		wg.Add(len(ips))
		for _, address := range ips {
			if p.Ip.Equal(address) {
				return true, result
			}
		}
	}
	return false, result
}

func (p *Parser) parseMX(t *Token) (bool, SPFResult) {
	result, _ := matchingResult(t.Qualifier)

	domain := t.Value
	if isEmpty(&domain) {
		domain = p.Domain
	}

	mxs, _ := net.LookupMX(domain)
	var wg sync.WaitGroup

	pipe := make(chan bool)

	for _, mx := range mxs {
		go func() {
			ips, _ := net.LookupIP(mx.Host)
			wg.Add(len(ips))
			for _, ip := range ips {
				pipe <- p.Ip.Equal(ip)
				wg.Done()
			}
		}()
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
