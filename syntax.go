package spf

import (
	"errors"
	"net"
	"strings"
)

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func validName(s string) bool {
	if s == "" || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !isAlpha(c) && !isDigit(rune(c)) && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// validMacroString checks RFC 7208 section 7 syntax without expanding macros
// or performing DNS work. The second result identifies a final macro-expand.
func validMacroString(s string) (bool, bool) {
	finalMacro := false
	for i := 0; i < len(s); {
		finalMacro = false
		if s[i] < '!' || s[i] > '~' {
			return false, false
		}
		if s[i] != '%' {
			i++
			continue
		}
		i++
		if i == len(s) {
			return false, false
		}
		switch s[i] {
		case '%', '_', '-':
			i++
		case '{':
			i++
			if i == len(s) || !strings.ContainsRune("slodiphvSLODIPHV", rune(s[i])) {
				return false, false
			}
			i++
			start := i
			nonzero := false
			for i < len(s) && isDigit(rune(s[i])) {
				nonzero = nonzero || s[i] != '0'
				i++
			}
			// A transformer count must be nonzero; do not convert unbounded digits
			// to an int merely to validate the syntax.
			if i > start && !nonzero {
				return false, false
			}
			if i < len(s) && (s[i] == 'r' || s[i] == 'R') {
				i++
			}
			for i < len(s) && strings.ContainsRune(".-+,/_=", rune(s[i])) {
				i++
			}
			if i == len(s) || s[i] != '}' {
				return false, false
			}
			i++
		default:
			return false, false
		}
		finalMacro = true
	}
	return true, finalMacro
}

func validDomainSpec(s string) bool {
	valid, finalMacro := validMacroString(s)
	if !valid || s == "" {
		return false
	}
	if finalMacro {
		return true
	}
	// domain-end is a literal dot and top label, optionally followed by a dot.
	s = strings.TrimSuffix(s, ".")
	dot := strings.LastIndexByte(s, '.')
	if dot < 0 {
		return false
	}
	label := s[dot+1:]
	if label == "" || !isAlphanum(label[0]) || !isAlphanum(label[len(label)-1]) {
		return false
	}
	hasLetterOrHyphen := false
	for i := 0; i < len(label); i++ {
		if !isAlphanum(label[i]) && label[i] != '-' {
			return false
		}
		hasLetterOrHyphen = hasLetterOrHyphen || isAlpha(label[i]) || label[i] == '-'
	}
	return hasLetterOrHyphen
}

func isAlphanum(c byte) bool { return isAlpha(c) || isDigit(rune(c)) }

func validIPNetwork(value string, ipv6 bool) bool {
	addr, mask, hasMask := strings.Cut(value, "/")
	ip := net.ParseIP(addr)
	if ip == nil || strings.Contains(addr, ":") != ipv6 {
		return false
	}
	if !ipv6 && ip.To4() == nil {
		return false
	}
	if hasMask {
		if mask == "" {
			return false
		}
		bits := 32
		if ipv6 {
			bits = 128
		}
		if _, err := parseCIDRMask(mask, bits); err != nil {
			return false
		}
	}
	return true
}

// validateRecord completes syntax checking before evaluation can short circuit.
// DNS validity of expanded names belongs to evaluation, not this grammar pass.
func validateRecord(query string, tokens []*token) error {
	if len(tokens) == 0 || query == "" || query[0] == ' ' {
		return errors.New("missing SPF version")
	}
	for i := 0; i < len(query); i++ {
		if query[i] < ' ' || query[i] > '~' {
			return errors.New("invalid SPF character")
		}
	}
	for i, t := range tokens {
		valid := false
		if i == 0 {
			valid = t.mechanism == tVersion && strings.EqualFold(t.value, "spf1")
		} else {
			// Outside the version section, v= is an unknown modifier.
			if t.mechanism == tVersion {
				t.mechanism = tUnknown
			}
			switch t.mechanism {
			case tAll:
				valid = t.value == ""
			case tIP4, tIP6:
				valid = validIPNetwork(t.value, t.mechanism == tIP6)
			case tA, tMX:
				_, _, _, err := splitDomainDualCIDR(t.value)
				valid = err == nil
			case tPTR:
				valid = t.value == "" || validDomainSpec(t.value)
			case tInclude, tExists, tRedirect, tExp:
				valid = validDomainSpec(t.value)
			case tUnknown:
				valid, _ = validMacroString(t.value)
			}
		}
		if !valid {
			return SyntaxError{t, errors.New("invalid SPF term syntax")}
		}
	}
	return nil
}
