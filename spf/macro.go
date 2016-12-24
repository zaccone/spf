package spf

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/zaccone/goSPF/mail"
)

// DELIMITER is a constant rune other than any allowed delimiter.
// It indicates lack of allowed delimiters, hence no split in delimiter
const DELIMITER rune = '*'

// NEGATIVE is a special value indicating there will be no split on macro.
const NEGATIVE int = -1

type macro struct {
	start  int
	pos    int
	prev   int
	length int
	input  string
	output []string
	state  stateFn
}

func newMacro(input string) *macro {
	return &macro{0, 0, 0, len(input), input, make([]string, 0, 0), nil}
}

type stateFn func(*macro, *Parser) (stateFn, error)

// ParseMacro evaluates whole input string and replaces keywords with appropriate
// values from
func ParseMacro(p *Parser, input string) (string, error) {
	m := newMacro(input)
	var err error
	for m.state = scanText; m.state != nil; {
		m.state, err = m.state(m, p)
		if err != nil {
			// log error
			return "", err
		}

	}
	return strings.Join(m.output, ""), nil
}

// ParseMacroToken evaluates whole input string and replaces keywords with appropriate
// values from
func ParseMacroToken(p *Parser, t *Token) (string, error) {
	return ParseMacro(p, t.Value)
}

// macro.eof() return true when scanned record has ended, false otherwise
func (m *macro) eof() bool { return m.pos >= m.length }

// next() returns next read rune and boolean indicator whether scanned
// record has ended. Method also moves `pos` value to size (length of read rune),
// and `prev` to previous `pos` location.
func (m *macro) next() (rune, bool) {
	if m.eof() {
		return 0, true
	}
	r, size := utf8.DecodeRuneInString(m.input[m.pos:])
	m.prev = m.pos
	m.pos += size
	return r, false
}

// macro.moveon() sets macro.start to macro.pos. This is usually done once the
// ident has been scanned.
func (m *macro) moveon() { m.start = m.pos }

// macro.back() moves back current macro.pos to a previous position.
func (m *macro) back() { m.pos = m.prev }

// State functions

func scanText(m *macro, p *Parser) (stateFn, error) {
	for {

		r, eof := m.next()

		if eof {
			m.output = append(m.output, m.input[m.start:m.pos])
			m.moveon()
			break
		}

		if r == '%' {
			// TODO(zaccone): excercise more with peek(),next(), back()
			m.output = append(m.output, m.input[m.start:m.prev])
			m.moveon()
			return scanPercent, nil
		}

	}
	return nil, nil
}

func scanPercent(m *macro, p *Parser) (stateFn, error) {
	r, eof := m.next()
	if eof {
		return nil, errors.New("Unexpected end of macro")
	}
	switch r {
	case '{':
		m.moveon()
		return scanMacro, nil
	case '%':
		m.output = append(m.output, "%")
	case '_':
		m.output = append(m.output, " ")
	case '-':
		m.output = append(m.output, "%20")
	default:
		return nil, fmt.Errorf("forbidden character (%v) after '%'", r)
	}

	m.moveon()
	return scanText, nil
}

type item struct {
	value       string
	cardinality int
	delimiter   rune
	reversed    bool
}

func scanMacro(m *macro, p *Parser) (stateFn, error) {

	r, eof := m.next()
	if eof {
		return nil, errors.New("macro ended too early")
	}
	var curItem item

	var err error
	var result string
	var email *mail.Email

	switch r {
	case 's':
		curItem = item{p.Sender, NEGATIVE, DELIMITER, false}
		m.moveon()
		result, err = parseDelimiter(m, &curItem)
		if err != nil {
			break
		}
		m.output = append(m.output, result)
		m.moveon()

	case 'l':
		email, err = mail.SplitEmails(p.Sender, p.Sender)
		if err != nil {
			break
		}
		curItem = item{email.User, NEGATIVE, DELIMITER, false}
		m.moveon()
		result, err = parseDelimiter(m, &curItem)
		if err != nil {
			break
		}
		m.output = append(m.output, result)
		m.moveon()

	case 'o':
		email, err = mail.SplitEmails(p.Sender, p.Sender)
		if err != nil {
			break
		}
		curItem = item{email.Domain, NEGATIVE, DELIMITER, false}
		m.moveon()
		result, err = parseDelimiter(m, &curItem)
		if err != nil {
			break
		}
		m.output = append(m.output, result)
		m.moveon()

	case 'd', 'h':
		curItem = item{p.Domain, NEGATIVE, DELIMITER, false}
		m.moveon()
		result, err = parseDelimiter(m, &curItem)
		if err != nil {
			break
		}
		m.output = append(m.output, result)
		m.moveon()

	case 'i':
		curItem = item{p.IP.String(), NEGATIVE, DELIMITER, false}
		m.moveon()
		result, err = parseDelimiter(m, &curItem)
		if err != nil {
			break
		}
		m.output = append(m.output, result)
		m.moveon()

	case 'p':
		// let's not use it for the moment, RFC doesn't recommend it.
	case 'v':
		// TODO(zaccone): move such functions to some generic utils module
		if p.IP.To4() == nil {
			m.output = append(m.output, "ip6")
		} else {
			m.output = append(m.output, "in-addr")
		}
		m.moveon()
		// TODO(zaccone): add remaining "c", "r", "t"
	}

	if err != nil {
		return nil, errors.New("Macro parsing error: " + err.Error())
	}

	r, eof = m.next()
	if eof {
		// macro not ended properly, handle error here
		return nil, errors.New("Macro ended too early.")
	} else if r != '}' {
		// macro not ended properly, handle error here
		return nil, errors.New("Invalid syntax.")
	}

	m.moveon()
	return scanText, nil

}

func parseDelimiter(m *macro, curItem *item) (string, error) {
	// ismacroDelimiter is a private function that returns true if the rune is
	// a macro delimiter.
	// It's important to ephasize delimiters defined in RFC 7208 section 7.1,
	// hence separate function for this.
	isMacroDelimiter := func(ch rune) bool {
		return strings.ContainsRune(".-+,/_=", ch)
	}

	r, eof := m.next()
	if eof {
		return "", errors.New("unexpected eof")
	}

	if isDigit(r) {
		m.back()
		for {
			r, eof := m.next()
			if eof {
				return "", errors.New("unexpected eof")
			}

			if !isDigit(r) {
				m.back()
				var err error
				curItem.cardinality, err = strconv.Atoi(
					m.input[m.start:m.pos])
				if err != nil {
					return "", err
				}
				break
			}
		}

		r, eof = m.next()
		if eof {
			return "", errors.New("unexpected eof")
		}
	}

	if r == 'r' {
		curItem.reversed = true
		r, eof = m.next()
		if eof {
			return "", errors.New("unexpected eof")
		}
	}
	if isMacroDelimiter(r) {
		curItem.delimiter = r
		r, eof = m.next()
		if eof {
			return "", errors.New("unexpected eof")
		}
	}
	if r != '}' {
		// syntax error
		return "", fmt.Errorf("unexpcted character '%v'\n", r)
	}

	m.back()

	// handle curItem
	var parts []string
	if curItem.cardinality > 0 ||
		curItem.reversed ||
		curItem.delimiter != DELIMITER {

		if curItem.delimiter == DELIMITER {
			curItem.delimiter = '.'
		}
		parts = strings.Split(curItem.value, string(curItem.delimiter))
		if curItem.reversed {
			first, last := 0, len(parts)-1
			for first < last {
				parts[first], parts[last] = parts[last], parts[first]
				first++
				last--
			}
		}
	} else {
		parts = []string{curItem.value}
	}

	if curItem.cardinality == NEGATIVE {
		curItem.cardinality = len(parts)
	}

	if curItem.cardinality > NEGATIVE && curItem.cardinality > len(parts) {
		curItem.cardinality = len(parts)
	}
	return strings.Join(parts[len(parts)-curItem.cardinality:], "."), nil
}
