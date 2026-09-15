// Cached loopback benchmark. Each worker owns its measurement histogram.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	spf "github.com/zaccone/spf"
)

type memory struct{ spf.ContextResolver }

func (memory) LookupTXTContext(_ context.Context, n string) ([]string, error) {
	if strings.HasPrefix(n, "include.") {
		return []string{"v=spf1 include:simple.benchmark.test -all"}, nil
	}
	if strings.HasPrefix(n, "chain") {
		var i int
		fmt.Sscanf(n, "chain%d.", &i)
		if i < 9 {
			return []string{fmt.Sprintf("v=spf1 include:chain%d.benchmark.test -all", i+1)}, nil
		}
	}
	return []string{"v=spf1 ip4:192.0.2.0/24 -all"}, nil
}
func main() {
	mode := flag.String("mode", "spf", "spf, memory, dns, reuse, policy")
	scenario := flag.String("scenario", "simple", "simple, include, chain0")
	workers := flag.Int("workers", 16, "concurrent workers")
	duration := flag.Duration("duration", 5*time.Second, "measurement duration")
	profile := flag.String("profile", "", "CPU profile path")
	flag.Parse()
	if *workers < 1 || *duration <= 0 {
		panic("invalid settings")
	}
	domain := *scenario + ".benchmark.test"
	r, _ := spf.NewServerResolver("127.0.0.1:53")
	var resolver spf.ContextResolver = r
	if *mode == "memory" {
		resolver = memory{}
	}
	ip := net.ParseIP("192.0.2.1")
	type result struct {
		hist      []uint64
		n, errors uint64
	}
	results := make([]result, *workers)
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	var deadline time.Time
	for w := 0; w < *workers; w++ {
		ready.Add(1)
		done.Add(1)
		go func(w int) {
			defer done.Done()
			h := make([]uint64, 100001)
			var n, errs uint64
			client := new(dns.Client)
			var dc *dns.Conn
			var conn net.Conn
			var reader *bufio.Reader
			if *mode == "reuse" {
				var err error
				dc, err = client.Dial("127.0.0.1:53")
				if err != nil {
					panic(err)
				}
				defer dc.Close()
			}
			if *mode == "policy" {
				var err error
				conn, err = net.Dial("tcp", "127.0.0.1:10023")
				if err != nil {
					panic(err)
				}
				defer conn.Close()
				reader = bufio.NewReader(conn)
			}
			req := new(dns.Msg)
			req.SetQuestion(domain+".", dns.TypeTXT)
			wire := fmt.Sprintf("request=smtpd_access_policy\nprotocol_state=RCPT\nclient_address=192.0.2.1\nsender=sender@%s\nhelo_name=mail.benchmark.test\n\n", domain)
			ready.Done()
			<-start
			for time.Now().Before(deadline) {
				t := time.Now()
				var err error
				switch *mode {
				case "spf", "memory":
					var res spf.Result
					res, _, err = spf.CheckHostWithOptions(context.Background(), ip, domain, "sender@"+domain, spf.Options{Resolver: resolver})
					if err == nil && res != spf.Pass {
						err = fmt.Errorf("SPF %s", res)
					}
				case "dns":
					_, err = r.LookupTXTContext(context.Background(), domain)
				case "reuse":
					var res *dns.Msg
					res, _, err = client.ExchangeWithConn(req, dc)
					if err == nil && (res.Rcode != 0 || len(res.Answer) == 0) {
						err = fmt.Errorf("bad DNS")
					}
				case "policy":
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					_, err = fmt.Fprint(conn, wire)
					if err == nil {
						var line string
						line, err = reader.ReadString('\n')
						if err == nil && line != "action=DUNNO\n" {
							err = fmt.Errorf("bad policy %s", line)
						}
						if err == nil {
							_, err = reader.ReadString('\n')
						}
					}
				default:
					panic("unknown mode")
				}
				us := time.Since(t).Microseconds()
				if us > 100000 {
					us = 100000
				}
				h[us]++
				n++
				if err != nil {
					errs++
				}
			}
			results[w] = result{h, n, errs}
		}(w)
	}
	ready.Wait()
	if *profile != "" {
		f, e := os.Create(*profile)
		if e != nil {
			panic(e)
		}
		defer f.Close()
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	t := time.Now()
	deadline = t.Add(*duration)
	close(start)
	done.Wait()
	seconds := time.Since(t).Seconds()
	h := make([]uint64, 100001)
	var n, errs uint64
	for _, r := range results {
		n += r.n
		errs += r.errors
		for i, v := range r.hist {
			h[i] += v
		}
	}
	out := map[string]any{"mode": *mode, "scenario": *scenario, "workers": *workers, "gomaxprocs": runtime.GOMAXPROCS(0), "n": n, "errors": errs, "seconds": seconds, "qps": float64(n) / seconds}
	for _, p := range []int{50, 75, 90, 99} {
		var sum uint64
		for i, v := range h {
			sum += v
			if sum >= (n*uint64(p)+99)/100 {
				out[fmt.Sprintf("p%d_us", p)] = i
				break
			}
		}
	}
	json.NewEncoder(os.Stdout).Encode(out)
}
