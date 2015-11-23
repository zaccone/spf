package spf

import (
	"strings"
	"unicode/utf8"
)

type Lexer struct {
	start  int
	pos    int
	prev   int
	length int
	input  string
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
		r, eof := l.next()
		if eof {
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

func (l *Lexer) scanIdent() *Token {
	t := &Token{tErr, qPlus, ""}
	cursor := l.start
	for cursor < l.pos {
		ch, size := utf8.DecodeRuneInString(l.input[cursor:])
		cursor += size

		if isQualifier(ch) {
			t.Qualifier, _ = qualifiers[ch]
			l.start = cursor
			continue
		} else if isDelimiter(ch) { // add error handling
			t.Mechanism = tokenTypeFromString(l.input[l.start : cursor-size])
			t.Value = strings.TrimSpace(l.input[cursor:l.pos])
			if isEmpty(&t.Value) {
				t.Qualifier = qError
				t.Mechanism = tErr
			}

			break
		}
	}

	if t.Mechanism.isErr() {
		t.Mechanism = tokenTypeFromString(
			strings.TrimSpace(l.input[l.start:cursor]))
		if t.Mechanism.isErr() {
			t.Qualifier = qError
			t.Value = ""
		}
	}
	return t
}

// isWhitespace returns true if the rune is a space, tab, or newline.
func isWhitespace(ch rune) bool { return ch == ' ' || ch == '\t' || ch == '\n' }

func isEmpty(s *string) bool { return *s == "" }

// isLetter returns true if the rune is a letter.
func isLetter(ch rune) bool { return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') }

func isDelimiter(ch rune) bool { return ch == ':' || ch == '=' }

// isDigit returns true if the rune is a digit.
func isDigit(ch rune) bool { return (ch >= '0' && ch <= '9') }

func isQualifier(ch rune) bool { return ch == '+' || ch == '-' || ch == '~' || ch == '?' }
