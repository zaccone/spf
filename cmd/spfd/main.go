// Command spfd evaluates SPF directly or serves Postfix access-policy requests.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: spfd check|serve [options]; use check -h or serve -h")
	}
	command := args[0]
	commandArgs := args[1:]

	var err error
	switch command {
	case "check":
		err = runCheck(ctx, commandArgs, out, errout)
	case "serve":
		err = runServe(ctx, commandArgs, errout)
	default:
		return fmt.Errorf("unknown command %q; use check or serve", command)
	}
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}
