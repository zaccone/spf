package spf

import "strings"

const (
	// SpfPrexif is a constant value for term indicating start of the SPF query
	spfPrefix     = "v=spf1 "
	spfPrefixTrim = "v=spf1"
)

func checkSPFVersion(spf []string) bool {
	if len(spf) == 0 {
		return false
	}

	first := spf[0]

	if len(first) >= len(spfPrefix) && strings.HasPrefix(first, spfPrefix) {
		return true
	}

	if len(first) == len(spfPrefixTrim) && first == spfPrefixTrim {
		return true
	}

	return false
}

// IsDomainName is a 1:1 copy of implementation from
// original golang codebase:
// https://github.com/golang/go/blob/master/src/net/dnsclient.go#L116
// It validates s string for conditions specified in RFC 1035 and RFC 3696
func IsDomainName(s string) bool {
	// See RFC 1035, RFC 3696.
	if len(s) == 0 {
		return false
	}
	if len(s) > 255 {
		return false
	}

	last := byte('.')
	ok := false // Ok once we've seen a letter.
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			ok = true
			partlen++
		case '0' <= c && c <= '9':
			// fine
			partlen++
		case c == '-':
			// Byte before dash cannot be dot.
			if last == '.' {
				return false
			}
			partlen++
		case c == '.':
			// Byte before dot cannot be dot, dash.
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}

	return ok
}

// NormalizeHost appends a root domain (a dot) to the FQDN.
func NormalizeHost(host string) string {
	if len(host) == 0 {
		return ""
	}
	if host[len(host)-1] != '.' {
		return host + "."
	}
	return host
}
