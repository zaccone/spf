package dns

import (
	"errors"
	"net"
	"strings"
)

const spfPrefix = "v=spf1 "
const spfPrefixTrim = "v=spf1"

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
// If also carries out initial validation on whether the TXT record is an SPF record (by comparing the string to a 'v=spf1' value)
// In the future function should properly handle all known DNS related errors as well as recurively query for SPF records
// TODO(zaccone): Handle typical DNS errors and recusive calls
func LookupSPF(domain string) ([]string, error) {
	var spfRecords []string
	var err error
	if spfRecords, err = net.LookupTXT(domain); err != nil {
		/*
			Note(zaccone): We need to handle DNS related errors in the upper layer, as depending on error type a SPF related
			result/exception will be raised.
		*/
		return nil, err
	}

	if checkSPFVersion(spfRecords) == false {
		return nil, errors.New(strings.Join([]string{"Invalid SPF record: ", strings.Join(spfRecords, " ")}, " "))
	}

	return spfRecords, nil
}
