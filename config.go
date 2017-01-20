package spf

// config represents configuration for SPF
type config struct {
	// dnsAddr in a format <ip>:<port> represents DNS endpoint where
	// resolver will point it's queries.
	dnsAddr string
}
