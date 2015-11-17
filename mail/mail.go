package mail

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
	if sender == nil || sender == "" {
		return &Email{postmaster, helo}
	}

	fields := strings.SplitN(sender, "@", 2)
	if fields[0] == "" {
		fields[0] = postmaster
	}

	if len(fields) == 2 {
		return &Email{fields[0], fields[1]}, nil
	} else {
		return &Email{postmaster, sender}
	}

	return nil, errors.New("error parsing sender and helo parameters")
}
