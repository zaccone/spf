package spf

import (
	"errors"
)

const spfPrefix = "spf1"

type Parser struct {
	Sender      string
	Domain      string
	Ip          string
	Query       string
	Mechanisms  []*Token
	Explanation *Token
	Redirect    *Token
}

func NewParser(sender, domain, ip, query string) *Parser {
	return &Parser{sender, domain, ip, query, nil, nil, nil}
}

func (p *Parser) Parse() (SPFResult, error) {
	var result SPFResult
	tokens := Lex(p.Query)

	if err := p.SortTokens(tokens); err != nil {
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

func (p *Parser) parseVersion(t *Token) SPFResult {
	if t.Value == spfPrefix {
		return None
	}
	return Permerror
}

func (p *Parser) SortTokens(tokens []*Token) error {

	for _, token := range tokens {
		if token.Mechanism.isMechanism() {
			p.Mechanisms = append(p.Mechanisms, token)

			if token.Mechanism == tAll {
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

func parseAll(t *Token) SPFResult {
	if t.Qualifier == qMinus {
		return None
	}
	return Temperror
}

func parseA(t *Token) SPFResult {
	return Permerror
}
