package spf

import (
	"fmt"
	"unicode/utf8"
)

type tokenType int

const (
	tEOF tokenType = iota

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
	qError

	qualifier_end
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
		return tEOF
	}
}

type Token struct {
	Mechanism tokenType // all, include, a, mx, ptr, ip4, ip6, exists etc.
	Qualifier tokenType // +, -, ~, ?, defaults to +
	Value     string    // value for a mechanism
}

type Lexer struct {
	start  int
	pos    int
	prev   int
	length int
	input  string
}

func (tok Token) Stringer() string {
	return fmt.Sprintf("M: %s, Q:%s, V: %s", tok.Mechanism, tok.Qualifier,
		tok.Value)
}

// Lex reads SPF record and returns list of Tokens along with
// their modifiers and values. Parser should parse the Tokens and execute
// relevant actions
func Lex(input string) []*Token {

	tokens := make([]*Token, 0)
	lexer := &Lexer{0, 0, 0, len(input), input}
	for {
		token := lexer.Scan()
		if token.Mechanism == tEOF {
			break
		}
		tokens = append(tokens, token)
	}

	return tokens
}

// Scan scans input and returns a Token structure
func (l *Lexer) Scan() *Token {

	for {
		if r, eof := l.next(); eof == true {
			return &Token{tEOF, tEOF, ""}
		} else if isWhitespace(r) || l.eof() { // we just scanned some meaningful data
			token := l.scanIdent()
			l.scanWhitespaces()
			l.moveon()
			return token
		}
	}
}

func (l *Lexer) eof() bool {
	return l.pos >= l.length
}

func (l *Lexer) next() (rune, bool) {
	if l.eof() {
		return 0, true
	}
	r, size := utf8.DecodeRuneInString(l.input[l.pos:])
	// TODO(zaccone): check for operation success/failure
	l.prev = l.pos
	l.pos += size
	return r, false
}

func (l *Lexer) moveon() {
	l.start = l.pos
}

func (l *Lexer) back() {
	l.pos = l.prev
}

func (l *Lexer) peek() (rune, bool) {
	ch, eof := l.next()
	l.back()
	return ch, eof
}

// scanWhitespaces moves position to a first rune which is not a
// whitespace or tab
func (l *Lexer) scanWhitespaces() {
	for {
		if ch, eof := l.next(); eof == true {
			return
		} else if isWhitespace(ch) == false {
			l.back()
			return
		}
	}
}

// scanIdent does actual scanning between [l.start:l.pos) positions.
func (l *Lexer) scanIdent() *Token {
	t := &Token{tEOF, qPlus, ""}
	cursor := l.start
	for cursor <= l.pos {
		ch, size := utf8.DecodeRuneInString(l.input[cursor:])
		cursor += size
		if isQualifier(ch) {
			var ok bool
			if t.Qualifier, ok = qualifiers[ch]; ok == false {
				t.Qualifier = qPlus
			}
			l.start = cursor
		} else if isDelimiter(ch) {
			t.Mechanism = tokenTypeFromString(l.input[l.start : cursor-size])
			if t.Mechanism == tEOF {
				t.Qualifier = tEOF
				return t
			}
			l.start = cursor
		} else if (isWhitespace(ch)) && t.Mechanism.isEOF() == false {
			t.Value = l.input[l.start : cursor-size]
			return t
		} else if cursor >= l.pos && t.Mechanism.isEOF() == false {
			t.Value = string(l.input[l.start:cursor])
			return t
		} else if isWhitespace(ch) {
			t.Mechanism = tokenTypeFromString(l.input[l.start : cursor-size])
			return t
		} else if cursor >= l.pos {
			t.Mechanism = tokenTypeFromString(l.input[l.start:cursor])
			return t
		}
	} // for

	return t // should not happen
}

// isMechanism return true when token is SPF mechanism, false otherwise
func (tok tokenType) isMechanism() bool { return tok > mechanism_beg && tok < mechanism_end }

// isQalifier return true when token is SPF qualifier, false otherwise
func (tok tokenType) isQualifier() bool { return tok > qualifier_beg && tok < qualifier_end }

func (tok tokenType) isEOF() bool { return tok == tEOF }

// isWhitespace returns true if the rune is a space, tab, or newline.
func isWhitespace(ch rune) bool { return ch == ' ' || ch == '\t' || ch == '\n' }

// isLetter returns true if the rune is a letter.
func isLetter(ch rune) bool { return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') }

func isDelimiter(ch rune) bool { return ch == ':' || ch == '=' }

// isDigit returns true if the rune is a digit.
func isDigit(ch rune) bool { return (ch >= '0' && ch <= '9') }

func isQualifier(ch rune) bool { return ch == '+' || ch == '-' || ch == '~' || ch == '?' }
