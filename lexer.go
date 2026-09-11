package spf

import (
	"strings"
	"unicode/utf8"
)

// lexer represents lexing structure
type lexer struct {
	start  int
	pos    int
	prev   int
	length int
	input  string
}

// lex reads SPF record and returns list of Tokens along with
// their modifiers and values. Parser should parse the Tokens and execute
// relevant actions
func lex(input string) []*token {
	var tokens []*token
	l := &lexer{0, 0, 0, len(input), input}
	for {
		token := l.scan()
		if token.mechanism == tEOF {
			break
		}
		tokens = append(tokens, token)
	}
	return tokens
}

// scan scans input and returns a Token structure
func (l *lexer) scan() *token {
	for {
		r, eof := l.next()
		if eof {
			return &token{tEOF, tEOF, ""}
		} else if isWhitespace(r) || l.eof() { // we just scanned some meaningful data
			token := l.scanIdent()
			l.scanWhitespaces()
			l.moveon()
			return token
		}
	}
}

// Lexer.eof() return true when scanned record has ended, false otherwise
func (l *lexer) eof() bool { return l.pos >= l.length }

// Lexer.next() returns next read rune and boolean indicator whether scanned
// record has ended. Method also moves `pos` value to size (length of read rune),
// and `prev` to previous `pos` location.
func (l *lexer) next() (rune, bool) {
	if l.eof() {
		return 0, true
	}
	r, size := utf8.DecodeRuneInString(l.input[l.pos:])
	// TODO(zaccone): check for operation success/failure
	l.prev = l.pos
	l.pos += size
	return r, false
}

// Lexer.moveon() sets Lexer.start to Lexer.pos. This is usually done once the
// ident has been scanned.
func (l *lexer) moveon() { l.start = l.pos }

// Lexer.back() moves back current Lexer.pos to a previous position.
func (l *lexer) back() { l.pos = l.prev }

// scanWhitespaces moves position to a first rune which is not a
// space
func (l *lexer) scanWhitespaces() {
	for {
		if ch, eof := l.next(); eof {
			return
		} else if !isWhitespace(ch) {
			l.back()
			return
		}
	}
}

// scanIdent is a Lexer method executed after an ident was found.
// It operates on a slice with constraints [l.start:l.pos).
// A cursor tries to find delimiters and set proper `mechanism`, `qualifier`
// and value itself.
// The default token has `mechanism` set to tErr, that is, error state.
func (l *lexer) scanIdent() *token {
	raw := strings.TrimRight(l.input[l.start:l.pos], " ")
	bad := &token{tErr, qErr, ""}
	if raw == "" {
		return bad
	}
	t := &token{tErr, qPlus, ""}
	qualified := isQualifier(rune(raw[0]))
	if qualified {
		t.qualifier = qualifiers[rune(raw[0])]
		raw = raw[1:]
	}
	end := strings.IndexAny(raw, ":=/")
	name := raw
	if end >= 0 {
		name = raw[:end]
	}
	if !validName(name) {
		return bad
	}
	t.mechanism = tokenTypeFromString(name)
	if end >= 0 {
		switch raw[end] {
		case '=':
			if qualified {
				return bad
			}
			if t.mechanism != tVersion && t.mechanism != tRedirect && t.mechanism != tExp {
				t.mechanism = tUnknown
			}
			t.value = raw[end+1:]
		case ':':
			if !t.mechanism.isMechanism() || t.mechanism == tVersion || t.mechanism == tAll {
				return bad
			}
			t.value = raw[end+1:]
			if t.value == "" {
				return bad
			}
			if t.mechanism == tA || t.mechanism == tMX {
				if strings.HasPrefix(t.value, "/") && !validDomainSpec(t.value) {
					return bad
				}
			}
		case '/':
			if t.mechanism != tA && t.mechanism != tMX {
				return bad
			}
			t.value = raw[end:]
			domain, _, _, err := splitDomainDualCIDR(t.value)
			if err != nil || domain != "" {
				return bad
			}
		}
	} else if t.mechanism != tAll && t.mechanism != tA && t.mechanism != tMX && t.mechanism != tPTR {
		return bad
	}
	if t.mechanism.isErr() {
		return bad
	}
	return t
}

// isWhitespace returns true if the rune is an ASCII space.
func isWhitespace(ch rune) bool { return ch == ' ' }

// isQualifier returns true if rune is a SPF delimiter (+,-,!,?)
func isQualifier(ch rune) bool { return ch == '+' || ch == '-' || ch == '~' || ch == '?' }

// isDigit returns true if rune is a numer (between '0' and '9'), false otherwise
func isDigit(ch rune) bool { return ch >= '0' && ch <= '9' }
