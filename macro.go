package spf

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

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
	return &macro{length: len(input), input: input}
}

type stateFn func(*macro, *parser) (stateFn, error)

// parseMacro expands macro text using the handwritten state machine.
func parseMacro(p *parser, input string) (string, error) {
	m := newMacro(input)
	var err error
	for m.state = scanText; m.state != nil; {
		if e, ok := p.resolver.(*evaluation); ok {
			if err := e.ctx.Err(); err != nil {
				return "", err
			}
		}
		m.state, err = m.state(m, p)
		if err != nil {
			return "", err
		}

	}
	return strings.Join(m.output, ""), nil
}

// parseMacroToken expands the token value.
func parseMacroToken(p *parser, t *token) (string, error) {
	return parseMacro(p, t.value)
}

// macro.eof() return true when scanned record has ended, false otherwise
func (m *macro) eof() bool { return m.pos >= m.length }

// next() returns next read rune and boolean indicator whether scanned
// record has ended. Method also moves `pos` value to size (length of read rune),
// and `prev` to previous `pos` location.
// Upon eof found, an non nil error is returned.
func (m *macro) next() (rune, error) {
	if m.eof() {
		return 0, fmt.Errorf("unexpected eof for macro (%v)", m.input)
	}
	r, size := utf8.DecodeRuneInString(m.input[m.pos:])
	m.prev = m.pos
	m.pos += size
	return r, nil
}

// macro.moveon() sets macro.start to macro.pos. This is usually done once the
// ident has been scanned.
func (m *macro) moveon() { m.start = m.pos }

// State functions

func scanText(m *macro, p *parser) (stateFn, error) {
	for {

		r, err := m.next()

		if err != nil {
			m.output = append(m.output, m.input[m.start:m.pos])
			m.moveon()
			break
		}

		if r == '%' {
			m.output = append(m.output, m.input[m.start:m.prev])
			m.moveon()
			return scanPercent, nil
		}

	}
	return nil, nil
}

func scanPercent(m *macro, p *parser) (stateFn, error) {
	r, err := m.next()
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("forbidden character (%v) after %%", r)
	}

	m.moveon()
	return scanText, nil
}

// scanMacro retains the handwritten scanner and applies one transformation
// pipeline to every macro letter. Syntax is checked before any DNS expansion.
func scanMacro(m *macro, p *parser) (stateFn, error) {
	start := m.pos
	for {
		r, err := m.next()
		if err != nil {
			return nil, err
		}
		if r == '}' {
			break
		}
	}
	spec := m.input[start:m.prev]
	if valid, _ := validMacroStringLetters("%{"+spec+"}", "slodiphvcrtSLODIPHVCRT"); !valid {
		return nil, fmt.Errorf("invalid macro %q", spec)
	}
	letter := spec[0]
	value, err := macroValue(p, letter|0x20)
	if err != nil {
		return nil, err
	}
	value = transformMacro(value, spec[1:])
	if letter >= 'A' && letter <= 'Z' {
		value = escapeMacro(value)
	}
	m.output = append(m.output, value)
	m.moveon()
	return scanText, nil
}

func macroValue(p *parser, letter byte) (string, error) {
	var options Options
	e, _ := p.resolver.(*evaluation)
	if e != nil {
		options = e.options
	}
	switch letter {
	case 's':
		return p.Sender, nil
	case 'l':
		return parseAddrSpec(p.Sender, p.Domain).local, nil
	case 'o':
		return parseAddrSpec(p.Sender, p.Domain).domain, nil
	case 'd':
		return p.Domain, nil
	case 'h':
		return nonemptyString(options.HELO, "unknown"), nil
	case 'c':
		return p.IP.String(), nil
	case 'r':
		return nonemptyString(options.Receiver, "unknown"), nil
	case 't':
		return strconv.FormatInt(options.Time.Unix(), 10), nil
	case 'v':
		if p.IP.To4() != nil {
			return "in-addr", nil
		}
		return "ip6", nil
	case 'i':
		if p.IP.To4() != nil {
			return p.IP.String(), nil
		}
		ip := p.IP.To16()
		if ip == nil {
			return "", ErrInvalidIP
		}
		const hex = "0123456789abcdef"
		var b strings.Builder
		for i, octet := range ip {
			if i > 0 {
				b.WriteByte('.')
			}
			b.WriteByte(hex[octet>>4])
			b.WriteByte('.')
			b.WriteByte(hex[octet&15])
		}
		return b.String(), nil
	case 'p':
		if e == nil {
			return "unknown", nil
		}
		if !e.explaining {
			if err := e.useTerm(); err != nil {
				return "", err
			}
		}
		names, err := e.reverseNames(p.IP)
		if errors.Is(err, ErrUnsupportedResolver) {
			return "unknown", nil
		}
		if err != nil {
			return "", err
		}
		if e.reverseDNSFailed {
			return "unknown", nil
		}
		for _, name := range names {
			if strings.EqualFold(strings.TrimSuffix(name, "."), strings.TrimSuffix(p.Domain, ".")) {
				return strings.TrimSuffix(name, "."), nil
			}
		}
		for _, name := range names {
			if withinDomain(name, p.Domain) {
				return strings.TrimSuffix(name, "."), nil
			}
		}
		if len(names) > 0 {
			return strings.TrimSuffix(names[0], "."), nil
		}
		return "unknown", nil
	}
	return "", fmt.Errorf("unsupported macro letter %q", letter)
}

func transformMacro(value, spec string) string {
	if spec == "" {
		return value
	}
	i, count := 0, 0
	// Saturate at the maximum possible number of parts, avoiding integer
	// overflow for arbitrarily long (but syntactically valid) digit strings.
	for i < len(spec) && isDigit(rune(spec[i])) {
		if count <= len(value) {
			count = min(len(value)+1, count*10+int(spec[i]-'0'))
		}
		i++
	}
	reverse := i < len(spec) && (spec[i] == 'r' || spec[i] == 'R')
	if reverse {
		i++
	}
	var delimiters [128]bool
	for _, c := range nonemptyString(spec[i:], ".") {
		delimiters[c] = true
	}
	// strings.FieldsFunc would discard empty parts, which the RFC preserves.
	var parts []string
	start := 0
	for j := 0; j < len(value); j++ {
		if value[j] < 128 && delimiters[value[j]] {
			parts = append(parts, value[start:j])
			start = j + 1
		}
	}
	parts = append(parts, value[start:])
	if reverse {
		for left, right := 0, len(parts)-1; left < right; left, right = left+1, right-1 {
			parts[left], parts[right] = parts[right], parts[left]
		}
	}
	if count > 0 && count < len(parts) {
		parts = parts[len(parts)-count:]
	}
	return strings.Join(parts, ".")
}

// Escape only RFC 3986 unreserved bytes; QueryEscape and PathEscape have
// different rules for spaces, slashes, and other reserved characters.
func escapeMacro(value string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if isAlphanum(c) || strings.ContainsRune("-._~", rune(c)) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}

// expandDomain is the common path for every evaluated domain-spec. Invalid
// expanded names produce Permerror (RFC 7208 section 4.8 leaves this choice
// to implementations). Explanation failures instead use the empty fallback.
func (p *parser) expandDomain(input string) (string, error) {
	if valid, _ := validMacroString(input); !valid {
		return "", ErrInvalidDomain
	}
	name, err := parseMacro(p, input)
	if err != nil {
		return "", err
	}
	for len(strings.TrimSuffix(name, ".")) > 253 {
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			return "", ErrInvalidDomain
		}
		name = name[dot+1:]
	}
	if !validExpandedDomain(name) {
		return "", ErrInvalidDomain
	}
	return name, nil
}

func macroErrorResult(err error) Result {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return Temperror
	}
	return Permerror
}

// Use label boundaries and case-insensitive comparison, following section
// 5.5's prose/example (its later subdomain bullet reverses the relationship).
func withinDomain(name, domain string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	return name == domain || strings.HasSuffix(name, "."+domain)
}

// Expanded DNS labels are not restricted to hostname letters/digits/hyphens.
// Macro literals and escapes can produce punctuation and spaces (RFC 7208
// sections 4.8 and 7). Dots separate labels; no DNS presentation escapes apply.
func validExpandedDomain(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i := range label {
			if label[i] < ' ' || label[i] > '~' {
				return false
			}
		}
	}
	return true
}

func (p *parser) expandDomainOrCurrent(input string) (string, error) {
	if input == "" {
		return p.Domain, nil
	}
	return p.expandDomain(input)
}
