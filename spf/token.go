package spf

type tokenType int

const (
	tEOF tokenType = iota
	tErr

	mechanism_beg

	tVersion // used only for v=spf1 starter
	tAll     // all
	tA       // a
	tIp4     // ip4
	tIp6     // ip6
	tMX      // mx
	tPTR     // ptr
	tInclude // include
	tExists  // exists

	mechanism_end

	modifier_beg

	tRedirect // redirect
	tExp      // explanation

	modifier_end

	qualifier_beg

	qEmpty
	qPlus
	qMinus
	qTilde
	qQuestionMark

	qualifier_end

	qErr
)

var qualifiers = map[rune]tokenType{
	'+': qPlus,
	'-': qMinus,
	'?': qQuestionMark,
	'~': qTilde,
}

func tokenTypeFromString(s string) tokenType {
	switch s {
	case "v":
		return tVersion
	case "all":
		return tAll
	case "a":
		return tA
	case "ip4":
		return tIp4
	case "ip6":
		return tIp6
	case "mx":
		return tMX
	case "ptr":
		return tPTR
	case "include":
		return tInclude
	case "redirect":
		return tRedirect
	case "exists":
		return tExists
	case "explanation", "exp":
		return tExp
	default:
		return tErr
	}
}

func (tok tokenType) isErr() bool { return tok == tErr }

func (tok tokenType) isMechanism() bool {
	return tok > mechanism_beg && tok < mechanism_end
}

func (tok tokenType) isModifier() bool {
	return tok > modifier_beg && tok < modifier_end
}

func (tok tokenType) isQualifier() bool {
	return tok > qualifier_beg && tok < qualifier_end
}

func checkTokenSyntax(token *Token, delimiter rune) bool {
	if token == nil {
		return false
	}

	if token.Mechanism == tErr && token.Qualifier == qErr {
		return true // syntax is ok
	}

	// special case for v=spf1 token

	if token.Mechanism == tVersion {
		return true
	}

	if token.Mechanism.isModifier() && delimiter != '=' {
		return false
	}
	if token.Mechanism.isMechanism() && delimiter != ':' {
		return false
	}

	return true
}

type Token struct {
	Mechanism tokenType // all, include, a, mx, ptr, ip4, ip6, exists etc.
	Qualifier tokenType // +, -, ~, ?, defaults to +
	Value     string    // value for a mechanism
}
