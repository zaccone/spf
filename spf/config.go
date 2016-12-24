package spf

// Config represents configuration for SPF
type Config struct {
	// Nameserver in a format <ip>:<port> represents DNS endpoint where
	// resolver will point it's queries.
	Nameserver string
}
