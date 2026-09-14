// Synthetic resolver benchmark; intentionally excludes DNS transport and MTA overhead.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	spf "github.com/zaccone/spf"
)

type resolver struct {
	delay    time.Duration
	scenario string
}

func (r resolver) LookupTXTContext(ctx context.Context, n string) ([]string, error) {
	if r.delay > 0 {
		select {
		case <-time.After(r.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if r.scenario == "include" && n == "example.com." {
		return []string{"v=spf1 include:child.example.com -all"}, nil
	}
	return []string{"v=spf1 ip4:192.0.2.0/24 -all"}, nil
}
func (r resolver) LookupIPContext(context.Context, string, string) ([]net.IP, error) {
	panic("unexpected IP query")
}
func (r resolver) LookupMXContext(context.Context, string) ([]*net.MX, error) {
	panic("unexpected MX query")
}
func (r resolver) LookupAddrContext(context.Context, string) ([]string, error) {
	panic("unexpected PTR query")
}
func main() {
	workers := flag.Int("workers", 1, "")
	n := flag.Int("n", 20000, "")
	delay := flag.Int("delay", 0, "microseconds per DNS call")
	scenario := flag.String("scenario", "simple", "")
	flag.Parse()
	if *workers < 1 || *n < 1 || *delay < 0 || (*scenario != "simple" && *scenario != "include") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "workers and n must be positive, delay must be nonnegative, and scenario must be simple or include; positional arguments are not accepted")
		os.Exit(2)
	}
	r := resolver{time.Duration(*delay) * time.Microsecond, *scenario}
	ip := net.ParseIP("192.0.2.1")
	check := func() {
		result, _, err := spf.CheckHostWithOptions(context.Background(), ip, "example.com", "sender@example.com", spf.Options{Resolver: r})
		if err != nil || result != spf.Pass {
			panic("unexpected SPF result")
		}
	}
	for i := 0; i < 100; i++ {
		check()
	}
	samples := make([]float64, *n)
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < *n; i += *workers {
				t := time.Now()
				check()
				samples[i] = float64(time.Since(t).Nanoseconds()) / 1000
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	sort.Float64s(samples)
	json.NewEncoder(os.Stdout).Encode(map[string]any{"implementation": "go", "workers": *workers, "n": *n, "delay_us": *delay, "scenario": *scenario, "seconds": elapsed, "checks_per_second": float64(*n) / elapsed, "p50_us": samples[*n/2], "p95_us": samples[*n*95/100], "p99_us": samples[*n*99/100]})
}
