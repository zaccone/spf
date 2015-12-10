package spf

import (
	"errors"
	"net"
)

const spfPrefix = "spf1"

func matchingResult(qualifier tokenType) (SPFResult, error) {
	if !qualifier.isQualifier() {
		return SPFEnd, errors.New("Not a Qualifier")
	}

	switch qualifier {
	case qPlus:
		return Pass, nil
	case qMinus:
		return Fail, nil
	case qQuestionMark:
		return Neutral, nil
	case qTilde:
		return Softfail, nil
	}
	return Permerror, nil
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
	return &Parser{sender, domain, ip, query, nil, nil, nil}
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

	for _, token := range tokens {
		if token.Mechanism.isMechanism() {
			p.Mechanisms = append(p.Mechanisms, token)

			if token.Mechanism == tAll {
				p.Redirect = nil // cleaning just in case
				return nil
			}
		} else {

			if token.Mechanism == tRedirect && p.Redirect != nil {
				return errors.New("Modifier redirect musn't appear more than once")
			} else {
				p.Redirect = token
			}

			if token.Mechanism == tExp && p.Explanation != nil {
				return errors.New("Modifier exp/explanation musn't appear more than once")
			} else {
				p.Explanation = token
			}
		}
	}
	return nil
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

	if _, ipnet, err := net.ParseCIDR(t.Value); err == nil {
		return ipnet.Contains(p.Ip), result
	} else {
		ip := net.ParseIP(t.Value)
		return ip.Equal(p.Ip), result
	}
}
