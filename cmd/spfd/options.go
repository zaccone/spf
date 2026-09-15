package main

import (
	"errors"
	"flag"
	"net"
	"strconv"
	"time"

	spf "github.com/zaccone/spf"
)

type resolverOptions struct {
	dns      string
	timeout  time.Duration
	receiver string
}

func (o *resolverOptions) registerFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.dns, "dns", "127.0.0.1:53", "recursive DNS server (IP:port)")
	fs.DurationVar(&o.timeout, "timeout", 20*time.Second, "SPF evaluation deadline (up to 20s)")
	fs.StringVar(&o.receiver, "receiver", "unknown", "receiving MTA hostname for SPF macros")
}

func makeResolver(address string, timeout time.Duration) (spf.ContextResolver, error) {
	if timeout <= 0 || timeout > 20*time.Second {
		return nil, errors.New("-timeout must be greater than zero and at most 20s")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) == nil {
		return nil, errors.New("-dns requires a literal IP address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("-dns requires a port between 1 and 65535")
	}
	return spf.NewServerResolver(address)
}
