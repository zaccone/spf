package spf

import (
	"errors"
	"strings"
)

const postmaster string = "postmaster"

type Email struct {
	User   string
	Domain string
}

func SplitEmails(sender, helo string) (*Email, error) {
	if sender == "" {
		return &Email{postmaster, helo}, nil
	}

	fields := strings.SplitN(sender, "@", 2)
	if fields[0] == "" {
		fields[0] = postmaster
	}

	if len(fields) == 2 {
		return &Email{fields[0], fields[1]}, nil
	} else {
		return &Email{postmaster, sender}, nil
	}

	return nil, errors.New("error parsing sender and helo parameters")
}
