package spf

const spfPrefix = "spf1"

type Parser struct {
	Sender string
	Domain string
	Ip     string
	Query  string
	Tokens []*Token
}

func NewParser(query string) *Parser {
	return &Parser{query, nil}
}

func (p *Parser) Parse() {
	p.Tokens = Lex(p.Query)

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

func parseAll(t *Token) SPFResult {
	if t.Qualifier == qMinus {
		return None
	}
}

func parseA(t *Token) {

}
