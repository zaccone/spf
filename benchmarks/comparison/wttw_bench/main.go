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

	spf "github.com/wttw/spf"
	"github.com/miekg/dns"
)

type resolver struct{ scenario string }

func (r resolver) Resolve(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
	name := q.Question[0].Name
	policy := "v=spf1 ip4:192.0.2.0/24 -all"
	if r.scenario == "include" && name == "example.com." {
		policy = "v=spf1 include:child.example.com -all"
	}
	m := new(dns.Msg)
	m.SetReply(q)
	m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{policy}}}
	return m, nil
}

func main() {
	workers := flag.Int("workers", 1, "concurrent workers")
	n := flag.Int("n", 20000, "checks")
	scenario := flag.String("scenario", "simple", "simple or include")
	flag.Parse()
	if *workers < 1 || *n < 1 || (*scenario != "simple" && *scenario != "include") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "invalid benchmark arguments")
		os.Exit(2)
	}
	c := spf.NewChecker()
	c.Resolver = resolver{scenario: *scenario}
	ip := net.ParseIP("192.0.2.1")
	check := func() {
		r := c.CheckHost(context.Background(), ip, "example.com.", "sender@example.com", "")
		if r.Type != spf.Pass {
			panic(r.String())
		}
	}
	for i := 0; i < 100; i++ { check() }
	samples := make([]float64, *n)
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := worker; i < *n; i += *workers {
				t := time.Now(); check()
				samples[i] = float64(time.Since(t).Nanoseconds()) / 1000
			}
		}(w)
	}
	wg.Wait()
	seconds := time.Since(start).Seconds()
	sort.Float64s(samples)
	json.NewEncoder(os.Stdout).Encode(map[string]any{
		"implementation": "wttw", "scenario": *scenario, "workers": *workers, "n": *n,
		"seconds": seconds, "checks_per_second": float64(*n) / seconds,
		"p50_us": samples[*n/2], "p95_us": samples[*n*95/100], "p99_us": samples[*n*99/100],
	})
}
