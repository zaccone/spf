package spf

import "strings"

const postmaster string = "postmaster"

// Email abstracts e-mail address. There're are two struct's fields - User and
// Domain.
type Email struct {
	User   string
	Domain string
}

// SplitEmails parses e-mail string address and retuens *Email structure.
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
	}
	return &Email{postmaster, sender}, nil
}
