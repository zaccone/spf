package spf

type tokenType int

const (
	tEOF tokenType = iota
	tErr

	mechanism_beg

	tVersion  // used only for v=spf1 starter
	tAll      // all
	tA        // a
	tIp4      // ip4
	tIp6      // ip6
	tMX       // mx
	tPTR      // ptr
	tInclude  // include
	tRedirect // redirect
	tExists   // exists
	tExp      // explanation

	mechanism_end

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

type Token struct {
	Mechanism tokenType // all, include, a, mx, ptr, ip4, ip6, exists etc.
	Qualifier tokenType // +, -, ~, ?, defaults to +
	Value     string    // value for a mechanism
}
