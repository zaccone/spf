package spf

import "fmt"

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

	qError
)

var qualifiers = map[rune]tokenType{
	'+': qPlus,
	'-': qMinus,
	'?': qQuestionMark,
	'~': qTilde,
}

func tokenTypeFromString(s string) tokenType {
	switch s {
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
	case "explanation":
		return tExp
	default:
		return tErr
	}
}

// isMechanism return true when token is SPF mechanism, false otherwise
func (tok tokenType) isMechanism() bool { return tok > mechanism_beg && tok < mechanism_end }

// isQalifier return true when token is SPF qualifier, false otherwise
func (tok tokenType) isQualifier() bool { return tok > qualifier_beg && tok < qualifier_end }

func (tok tokenType) isEOF() bool { return tok == tEOF }

func (tok tokenType) isErr() bool { return tok == tErr }

type Token struct {
	Mechanism tokenType // all, include, a, mx, ptr, ip4, ip6, exists etc.
	Qualifier tokenType // +, -, ~, ?, defaults to +
	Value     string    // value for a mechanism
}

func (tok Token) Stringer() string {
	return fmt.Sprintf("M: %s, Q:%s, V: %s", tok.Mechanism, tok.Qualifier,
		tok.Value)
}
