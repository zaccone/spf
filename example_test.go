package spf_test

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/zaccone/spf"
)

// A deterministic resolver for this example; production applications can use
// spf.NewServerResolver("192.0.2.53:53") or their own ContextResolver.
type exampleResolver struct{}

func (exampleResolver) LookupTXTContext(_ context.Context, name string) ([]string, error) {
	if name == "example.com." {
		return []string{"v=spf1 ip4:192.0.2.0/24 -all"}, nil
	}
	return nil, nil
}
func (exampleResolver) LookupIPContext(context.Context, string, string) ([]net.IP, error) {
	return nil, nil
}
func (exampleResolver) LookupMXContext(context.Context, string) ([]*net.MX, error)  { return nil, nil }
func (exampleResolver) LookupAddrContext(context.Context, string) ([]string, error) { return nil, nil }

func ExampleCheckHostWithOptions() {
	result, explanation, err := spf.CheckHostWithOptions(
		context.Background(), net.ParseIP("192.0.2.1"), "example.com", "sender@example.com",
		spf.Options{Resolver: exampleResolver{}, HELO: "mail.example.com", Receiver: "mx.receiver.example"},
	)
	fmt.Println(result, explanation == "", err)
	// Output: pass true <nil>
}

func ExampleCheckHostWithOptions_cancellation() {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, _, err := spf.CheckHostWithOptions(ctx, net.ParseIP("192.0.2.1"), "example.com", "sender@example.com", spf.Options{Resolver: exampleResolver{}})
	fmt.Println(result, errors.Is(err, context.Canceled))
	// Output: temperror true
}
