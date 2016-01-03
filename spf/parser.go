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
			/* case tPTR:
			result = p.parsePTR(token)
			case tInclude:
				matches, result = p.parseInclude(token)
			*/
		}

		if matches {
			return result, nil
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

	domain := p.setDomain(t)
	if ips, err := net.LookupIP(domain); err != nil {
		//TODO(marek):  confirm SPFResult
		return true, Fail
	} else {
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
