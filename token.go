package spf

type tokenType int

const (
	tEOF tokenType = iota
	tErr

	mechanismBeg

	tVersion // used only for v=spf1 starter
	tAll     // all
	tA       // a
	tIP4     // ip4
	tIP6     // ip6
	tMX      // mx
	tPTR     // ptr
	tInclude // include
	tExists  // exists

	mechanismEnd

	modifierBeg

	tRedirect // redirect
	tExp      // explanation

	modifierEnd

	qualifierBeg

	qEmpty
	qPlus
	qMinus
	qTilde
	qQuestionMark

	qualifierEnd

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
		return tIP4
	case "ip6":
		return tIP6
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
	return tok > mechanismBeg && tok < mechanismEnd
}

func (tok tokenType) isModifier() bool {
	return tok > modifierBeg && tok < modifierEnd
}

func (tok tokenType) isQualifier() bool {
	return tok > qualifierBeg && tok < qualifierEnd
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

	//mechanism include must not have empty content
	if token.Mechanism == tInclude && isEmpty(&token.Value) {
		return false
	}
	if token.Mechanism.isModifier() && delimiter != '=' {
		return false
	}
	if token.Mechanism.isMechanism() && delimiter != ':' {
		return false
	}

	return true
}

// Token represents SPF term (modifier or mechanism) like all, include, a, mx,
// ptr, ip4, ip6, exists, redirect etc.
// It's a base structure later parsed by Parser.
type Token struct {
	Mechanism tokenType // all, include, a, mx, ptr, ip4, ip6, exists etc.
	Qualifier tokenType // +, -, ~, ?, defaults to +
	Value     string    // value for a mechanism
}
