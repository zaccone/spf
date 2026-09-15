package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"

	spf "github.com/zaccone/spf"
)

func runCheck(ctx context.Context, args []string, out, errout io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(errout)
	var opts resolverOptions
	opts.registerFlags(fs)
	ip := fs.String("ip", "", "SMTP client IP (required)")
	domain := fs.String("domain", "", "policy domain (defaults to sender domain, or HELO for null sender)")
	sender := fs.String("sender", "", "envelope sender; empty means null reverse path")
	helo := fs.String("helo", "", "SMTP HELO/EHLO identity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	r, err := makeResolver(opts.dns, opts.timeout)
	if err != nil {
		return err
	}
	address := net.ParseIP(*ip)
	if address == nil {
		return errors.New("-ip must be an IP address")
	}
	if *domain == "" {
		*domain, err = identity(*sender, *helo)
		if err != nil {
			return err
		}
	}
	checkctx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()
	if *sender == "<>" {
		*sender = ""
	}
	result, explanation, diagnostic := spf.CheckHostWithOptions(checkctx, address, *domain, *sender, spf.Options{Resolver: r, HELO: *helo, Receiver: opts.receiver})
	message := ""
	if diagnostic != nil {
		message = diagnostic.Error()
	}
	return json.NewEncoder(out).Encode(struct {
		Result      string `json:"result"`
		Explanation string `json:"explanation,omitempty"`
		Error       string `json:"error,omitempty"`
	}{result.String(), explanation, message})
}
