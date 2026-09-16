// Mixed-result, bounded-memory load driver for real DNS and Postfix policy.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	spf "github.com/zaccone/spf"
)

type Case struct {
	Name, Domain, IP, Expected string
	Queries                    int
}
type Counts struct {
	N          uint64
	Errors     uint64
	Hist       [20001]uint64
	Cases      map[string]uint64
	FirstError string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	manifest := flag.String("cases", "", "case manifest")
	mode := flag.String("mode", "spf", "spf or policy (enforcement enabled)")
	address := flag.String("dns", "127.0.0.1:53", "resolver")
	policy := flag.String("policy", "127.0.0.1:10023", "daemon")
	selected := flag.String("case", "", "single case name; empty mixes all")
	workers := flag.Int("workers", 1, "parallel closed-loop workers")
	duration := flag.Duration("duration", time.Second, "measurement duration")
	once := flag.Bool("once", false, "evaluate each case once serially")
	seed := flag.Int64("seed", 1, "deterministic per-worker seed")
	distribution := flag.String("distribution", "uniform", "uniform or zipf")
	flag.Parse()
	if *workers < 1 || *workers > 4096 || *duration <= 0 || (*mode != "spf" && *mode != "policy") || (*distribution != "uniform" && *distribution != "zipf") {
		return fmt.Errorf("invalid benchmark options")
	}
	data, err := os.ReadFile(*manifest)
	if err != nil {
		return err
	}
	var cases []Case
	if err = json.Unmarshal(data, &cases); err != nil {
		return err
	}
	filtered := cases[:0]
	for _, c := range cases {
		if *selected == "" || c.Name == *selected {
			if net.ParseIP(c.IP) == nil {
				return fmt.Errorf("invalid IP")
			}
			filtered = append(filtered, c)
		}
	}
	cases = filtered
	if len(cases) == 0 {
		return fmt.Errorf("no cases")
	}
	if *once {
		*workers = 1
	}
	resolver, err := spf.NewServerResolver(*address)
	if err != nil {
		return err
	}
	results := make([]Counts, *workers)
	start := make(chan struct{})
	var ready, done sync.WaitGroup
	var deadline time.Time
	for w := 0; w < *workers; w++ {
		ready.Add(1)
		done.Add(1)
		go func(w int) {
			defer done.Done()
			r := &results[w]
			r.Cases = map[string]uint64{}
			rng := rand.New(rand.NewSource(*seed + int64(w)))
			zipf := rand.NewZipf(rng, 1.2, 1, uint64(len(cases)-1))
			var conn net.Conn
			var reader *bufio.Reader
			defer func() {
				if conn != nil {
					conn.Close()
				}
			}()
			ready.Done()
			<-start
			for i := 0; ; i++ {
				if *once {
					if i >= len(cases) {
						break
					}
				} else if !time.Now().Before(deadline) {
					break
				}
				index := i
				if !*once {
					if *distribution == "zipf" {
						index = int(zipf.Uint64())
					} else {
						index = rng.Intn(len(cases))
					}
				}
				c := cases[index]
				t := time.Now()
				var failure error
				if *mode == "spf" {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					res, _, e := spf.CheckHostWithOptions(ctx, net.ParseIP(c.IP), c.Domain, "sender@"+c.Domain, spf.Options{Resolver: resolver, HELO: "mail.spfbench.test"})
					cancel()
					if res.String() != c.Expected || (c.Expected == "pass" && e != nil) {
						failure = fmt.Errorf("%s: got %s (%v), want %s", c.Name, res, e, c.Expected)
					}
				} else {
					if conn == nil {
						conn, failure = net.DialTimeout("tcp", *policy, 3*time.Second)
						if failure == nil {
							reader = bufio.NewReader(conn)
						}
					}
					if failure == nil {
						conn.SetDeadline(time.Now().Add(3 * time.Second))
						_, failure = fmt.Fprintf(conn, "request=smtpd_access_policy\nprotocol_state=RCPT\nclient_address=%s\nsender=sender@%s\nhelo_name=mail.spfbench.test\n\n", c.IP, c.Domain)
					}
					if failure == nil {
						var line, blank string
						line, failure = reader.ReadString('\n')
						if failure == nil {
							blank, failure = reader.ReadString('\n')
						}
						want := "action=DUNNO\n"
						if c.Expected == "fail" {
							want = "action=550 5.7.23 SPF validation failed\n"
						}
						if c.Expected == "temperror" {
							want = "action=451 4.7.24 SPF evaluation temporarily unavailable\n"
						}
						if failure == nil && (line != want || blank != "\n") {
							failure = fmt.Errorf("%s: unexpected response %q %q", c.Name, line, blank)
						}
					}
					if failure != nil && conn != nil {
						conn.Close()
						conn = nil
					}
				}
				us := time.Since(t).Microseconds() / 100
				if us > 20000 {
					us = 20000
				}
				r.Hist[us]++
				r.N++
				r.Cases[c.Name]++
				if failure != nil {
					r.Errors++
					if r.FirstError == "" {
						r.FirstError = failure.Error()
					}
				}
			}
		}(w)
	}
	ready.Wait()
	t := time.Now()
	deadline = t.Add(*duration)
	close(start)
	done.Wait()
	seconds := time.Since(t).Seconds()
	total := Counts{Cases: map[string]uint64{}}
	for _, r := range results {
		total.N += r.N
		total.Errors += r.Errors
		for i, n := range r.Hist {
			total.Hist[i] += n
		}
		for c, n := range r.Cases {
			total.Cases[c] += n
		}
		if total.FirstError == "" {
			total.FirstError = r.FirstError
		}
	}
	out := map[string]any{"mode": *mode, "workers": *workers, "distribution": *distribution, "seed": *seed, "gomaxprocs": runtime.GOMAXPROCS(0), "n": total.N, "errors": total.Errors, "first_error": total.FirstError, "seconds": seconds, "qps": float64(total.N) / seconds, "case_counts": total.Cases, "overflow_2s": total.Hist[20000]}
	for _, p := range []uint64{50, 95, 99} {
		var n uint64
		for i, count := range total.Hist {
			n += count
			if n >= (total.N*p+99)/100 {
				out[fmt.Sprintf("p%d_us_upper", p)] = (i + 1) * 100
				break
			}
		}
	}
	if total.Hist[20000] > 0 {
		for k := range out {
			if strings.HasSuffix(k, "_us_upper") {
				out[k] = nil
			}
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		return err
	}
	if total.Errors > 0 {
		return fmt.Errorf("%d mismatches: %s", total.Errors, total.FirstError)
	}
	return nil
}
