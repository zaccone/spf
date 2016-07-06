package dns

import (
	"errors"
	"net"
	"strings"
)

const (
	// RCODE3 respresents string value set to net.DNSError.Err variable
	// after underlying resolver returned RCODE 3.
	RCODE3 = "no such host"
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

// LookupSPF retireves SPF query from domain in question.
// If also carries out initial validation on whether the TXT record is an SPF
// record (by comparing the string to a 'v=spf1' value)
// In the future function should properly handle all known DNS related errors
// as well as recurively query for SPF records
// TODO(zaccone): Handle typical DNS errors and recusive calls
func LookupSPF(domain string) ([]string, error) {
	var spfRecords []string
	var err error
	if spfRecords, err = net.LookupTXT(domain); err != nil {
		/*
			Note(zaccone): We need to handle DNS related errors in the upper
			layer, as depending on error type a SPF related result/exception
			will be raised.
		*/
		return nil, err
	}

	if checkSPFVersion(spfRecords) == false {
		return nil, errors.New(strings.Join(
			[]string{"Invalid SPF record: ", strings.Join(spfRecords, " ")},
			" "))
	}

	return spfRecords, nil
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
