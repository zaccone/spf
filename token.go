package spf

import (
	"strconv"
	"strings"
)

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
	tUnknown  // ignored extension modifier

	modifierEnd

	_ // qEmpty - deadcode, not used
	qPlus
	qMinus
	qTilde
	qQuestionMark

	qErr
)

var qualifiers = map[rune]tokenType{
	'+': qPlus,
	'-': qMinus,
	'?': qQuestionMark,
	'~': qTilde,
}

func (tok tokenType) String() string {
	switch tok {
	case tVersion:
		return "v"
	case tAll:
		return "all"
	case tIP4:
		return "ip4"
	case tIP6:
		return "ip6"
	case tMX:
		return "mx"
	case tPTR:
		return "ptr"
	case tInclude:
		return "include"
	case tRedirect:
		return "redirect"
	case tExists:
		return "exists"
	case tExp:
		return "exp"
	default:
		return strconv.Itoa(int(tok))
	}
}

func tokenTypeFromString(s string) tokenType {
	switch strings.ToLower(s) {
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
	case "exp":
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

// token represents SPF term (modifier or mechanism) like all, include, a, mx,
// ptr, ip4, ip6, exists, redirect etc.
// It's a base structure later parsed by Parser.
type token struct {
	mechanism tokenType // all, include, a, mx, ptr, ip4, ip6, exists etc.
	qualifier tokenType // +, -, ~, ?, defaults to +
	value     string    // value for a mechanism
}
