// Package identity implements the identity conventions shared by spfd transports.
package identity

import (
	"errors"
	"strings"
)

// NormalizeSender converts the SMTP null reverse path to the library representation.
func NormalizeSender(sender string) string {
	if sender == "<>" {
		return ""
	}
	return sender
}

// Domain derives the policy domain from the envelope sender, falling back to HELO.
func Domain(sender, helo string) (string, error) {
	if sender == "" || sender == "<>" {
		if helo == "" {
			return "", errors.New("null sender requires HELO")
		}
		return helo, nil
	}
	i := strings.LastIndexByte(sender, '@')
	if i <= 0 || i == len(sender)-1 || strings.ContainsAny(sender, "\r\n\x00") {
		return "", errors.New("invalid envelope sender")
	}
	return sender[i+1:], nil
}
