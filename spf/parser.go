package spf

const spfPrefix = "spf1"

type Parser struct {
	Sender     string
	Domain     string
	Ip         string
	Query      string
	Mechanisms []*Token
	Modifiers  []*Token
}

func NewParser(query string) *Parser {
	return &Parser{query, nil}
}

func (p *Parser) Parse() error {
	tokens = Lex(p.Query)
	if err := p.SortTokens(tokens); err != nil {
		return error
	}

	for _, token := range p.Tokens {
		var result SPFResult
		switch token.Mechanism {
		case tVersion:
			result = p.parseVersion(token)
		case tAll:
			result = p.parseAll(token)
		case tA:
			resutl = p.parseA(token)
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
		default:
			result = p.parseDefault(token)
		}
	}

}

func (p *Parser) parseVersion(t *Token) SPFResult {
	if t.Value == spfPrefix {
		return None
	}
	return Permerror
}

func (p *Parser) SortTokens(tokens []*Token) error {

	redirect := false
	exp := false

	for _, token := range tokens {
		if token.Mechanism.isMechanism() {
			p.Mechanisms = append(p.Mechanisms, token)

			if token.Mechanism == tAll {
				return nil
			}
		} else

			if token.Mechanism == tRedirect && redirect == true {
				return errors.NewError("Modifier redirect musn't appear more than once")
			} else {
				redirect = true
			}

			if token.Mechanism =tExp && exp == true {
				return errors.NewError("Modifier exp/explanation musn't appear more than once")
			} else {
				exp = true
			}

			p.Modifiers = append(p.Modifiers, token)
		}
	}

	return nil

}

func parseAll(t *Token) SPFResult {
	if t.Qualifier == qMinus {
		return None
	}
}

func parseA(t *Token) SPFResult {
	return Permerror
}
