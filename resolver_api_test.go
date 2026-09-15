package spf_test

import (
	"context"
	"errors"
	"testing"

	"github.com/zaccone/spf"
)

// Check source compatibility from a caller's package, including the exact old
// constructor signatures and alias identity.
var (
	_ func(string) (spf.Resolver, error)        = spf.NewMiekgDNSResolver
	_ func(string) (spf.ContextResolver, error) = spf.NewMiekgDNSResolverContext
	_ *spf.MiekgDNSResolver                     = (*spf.ServerResolver)(nil)
	_ *spf.ServerResolver                       = (*spf.MiekgDNSResolver)(nil)
)

func TestServerResolverPublicAPI(t *testing.T) {
	for _, address := range []string{"127.0.0.1:53", "[::1]:53", "resolver.example:53"} {
		r, err := spf.NewServerResolver(address)
		if err != nil || r == nil {
			t.Fatalf("NewServerResolver(%q) = %v, %v", address, r, err)
		}
		var legacy spf.Resolver = r
		options := spf.Options{Resolver: r}
		if any(legacy) != any(options.Resolver) {
			t.Fatal("constructor must support both interfaces with the same instance")
		}
	}

	for name, constructor := range map[string]func(string) (spf.ContextResolver, error){
		"preferred": func(addr string) (spf.ContextResolver, error) {
			r, err := spf.NewServerResolver(addr)
			if err != nil {
				return nil, err
			}
			return r, nil
		},
		"legacy context": spf.NewMiekgDNSResolverContext,
		"legacy": func(addr string) (spf.ContextResolver, error) {
			r, err := spf.NewMiekgDNSResolver(addr)
			if err != nil {
				if r != nil {
					t.Fatal("legacy constructor returned a non-nil interface on error")
				}
				return nil, err
			}
			return r.(spf.ContextResolver), nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := constructor("missing-port")
			if err == nil || r != nil {
				t.Fatalf("invalid address returned %v, %v", r, err)
			}
			r, err = constructor("127.0.0.1:53")
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := r.(*spf.MiekgDNSResolver); !ok {
				t.Fatal("legacy type assertion no longer works")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := r.LookupTXTContext(ctx, "example.test."); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled lookup returned %v", err)
			}
		})
	}
	if r, err := spf.NewServerResolver("missing-port"); err == nil || r != nil {
		t.Fatalf("preferred constructor returned %v, %v for invalid address", r, err)
	}
}
