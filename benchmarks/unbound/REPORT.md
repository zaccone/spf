# SPF with cached local Unbound: throughput and bottlenecks

Run: 15 September 2026. Four-vCPU Ubuntu VM. SPF/Go tests use IPv4 loopback;
the independent dnsperf control uses IPv6 loopback.

## Findings

The highest repeated throughput for the simple policy was **232,517 library
checks/s** and **98,860 spfd policy requests/s**. These are ceilings measured for
this fixture and shared four-core setup, not universal SPF capacity limits.

**DNS client transport is the main library bottleneck.** The SPF CPU profile
places 82.53% of samples under `ServerResolver.lookup`, including 31.04% under
`net.Dialer.DialContext`. System calls account for 42.11% of flat CPU samples.
The resolver opens and closes a UDP socket for every query. Unbound used about
0.75 CPU cores while SPF used 3.14 cores at peak simple-policy throughput.

**Go concurrency works.** At 16 workers, increasing GOMAXPROCS from 1 to 2 to 4
raised simple cached SPF throughput from 88,095 to 159,898 to 226,642 checks/s.
More outstanding work eventually adds latency without useful throughput gains.

**Unbound has headroom at the current SPF ceiling.** A direct DNS control using
one persistent UDP socket per worker achieved 623,991 lookups/s, versus 271,112
for the existing ServerResolver without SPF evaluation. The reusable-socket
control omits some resolver validation/cancellation work; its 2.30× advantage is
evidence for investigating transport reuse, not a promised SPF speedup.

For simple policies, 16 workers/connections offer a useful measured operating
point: 225,256 library checks/s at p99 404 µs, or 93,082 daemon requests/s at p99
1,037 µs. Moving to 64 gains only 3.2% and 6.2% throughput respectively, while
p99 grows to 1,690 and 3,456 µs.

## SPF library versus spfd

Each row reports medians across three separate ten-second trials. QPS is completed
SPF evaluations or policy requests per second. Percentiles are medians of trial
percentiles, not percentiles of pooled samples. Latencies are in **microseconds**.

The library path calls `CheckHostWithOptions` directly. The `spfd` path sends a
Postfix policy request over an already-established loopback TCP connection,
parses and validates its attributes, calls the same library, maps the SPF result
to a Postfix action, emits its structured log record, and writes the response.
Connection establishment and process startup are outside each timed operation.

| Path | Policy / DNS queries per check | Workers | QPS | QPS min–max | p50 | p75 | p90 | p99 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Library | Simple / 1 | 64 | 232,517 | 232,101–233,504 | 150 | 376 | 673 | 1,690 |
| Library | Include / 2 | 64 | 117,541 | 116,930–118,864 | 425 | 732 | 1,120 | 2,450 |
| Library | Include chain / 10 | 64 | 24,127 | 23,864–24,327 | 2,457 | 3,205 | 4,139 | 7,151 |
| spfd | Simple / 1 | 64 | 98,860 | 98,167–99,646 | 483 | 735 | 1,363 | 3,456 |
| spfd | Include / 2 | 64 | 61,989 | 61,602–63,132 | 770 | 1,253 | 2,228 | 4,572 |
| spfd | Include chain / 10 | 16 | 16,911 | 16,880–16,953 | 805 | 1,085 | 1,519 | 3,082 |
| Library | Simple / 1, lower concurrency | 16 | 225,256 | 225,194–227,972 | 43 | 84 | 138 | 404 |
| spfd | Simple / 1, lower concurrency | 16 | 93,082 | 92,673–94,826 | 133 | 189 | 278 | 1,037 |

Peak configurations were selected from the initial sweep, then remeasured.
The ten-query daemon policy peaked at 16 connections; adding connections reduced
throughput and increased latency. Policy-service latency includes sending the
request and reading the response over a persistent loopback TCP connection.
Library latency covers `CheckHostWithOptions` through its return.

### Controls

| Control | Workers | Operations/s | p50 µs | p75 µs | p90 µs | p99 µs | Client CPU | Unbound CPU |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Immediate TXT callback + SPF, simple | 16 | 3,173,777 | 1 | 1 | 1 | 1 | 393.5% | 0% |
| Existing ServerResolver TXT lookup | 64 | 271,112 | 130 | 306 | 537 | 1,617 | 303.2% | 82.7% |
| Persistent UDP socket TXT control | 128 | 623,991 | 43 | 146 | 283 | 3,410 | 226.5% | 151.2% |

CPU percentages use 100% per core. The persistent-socket row maximizes throughput;
it is not its best latency setting. In the initial sweep, 16 persistent-socket
workers achieved 526,292 lookups/s with p99 263 µs.

The no-DNS simple policy is over 13× faster than cached loopback SPF. Removing
SPF work while retaining the existing DNS transport improves throughput only
about 17%. Both controls and the profile favor DNS transport work ahead of a
parser rewrite.

### Independent Unbound capacity control

Native `dnsperf` 2.15.0, 64 clients, up to 256 outstanding queries, no QPS cap,
one cached simple-policy TXT record, 15 seconds per setting. These are single
diagnostic trials, separate from the three-run Go medians.

| dnsperf threads | DNS queries/s | Mean latency µs | Queries lost | Unbound CPU |
|---:|---:|---:|---:|---:|
| 1 | 426,887 | 25 | 0 | 108.8% |
| 2 | 715,395 | 113 | 0 | 155.6% |
| 4 | 534,910 | 422 | 0 | 125.9% |

All 25,159,502 responses were NOERROR cache hits, with no rate-limit drops or
cache misses. This establishes at least 715k cached queries/s in the tested
co-located DNS setup, not Unbound's absolute standalone limit. Four generator
threads performed worse than two, illustrating contention and generator effects
on a shared four-core VM.

The packaged tool initially selected an IPv4-mapped IPv6 target and sent zero
queries; a verbose diagnostic reported `Network is unreachable`, and forcing
the IPv4 family failed address selection. Those invalid runs are retained as
`results/dnsperf-{1,2,4}.txt` and excluded. I enabled Unbound on `::1`, restarted
it, re-primed the cache, and ran with `-f inet6 -s ::1 -a ::1`. All SPF and Go DNS
measurements remained IPv4. Because address families differ, use the 624k/s Go
IPv4 control for the closest transport comparison; dnsperf is independent
corroboration of server headroom. The final configuration includes both loopbacks.

## Scaling and the latency tradeoff

Initial three-second trials; these are exploratory single runs, not the repeated
headline results above. All rows here use the simple policy and GOMAXPROCS=4.

| Workers / connections | Library checks/s | Library p99 µs | spfd requests/s | spfd p99 µs |
|---:|---:|---:|---:|---:|
| 1 | 33,512 | 54 | 16,425 | 101 |
| 4 | 137,961 | 103 | 53,410 | 162 |
| 16 | 226,642 | 454 | 100,083 | 874 |
| 64 | 235,360 | 2,125 | 101,134 | 3,351 |
| 128 | 234,299 | 3,639 | 99,986 | 6,116 |

At 16 workers, the immediate-callback simple SPF control scales from 757,597 to
1,519,440 to 3,217,231 operations/s for GOMAXPROCS=1, 2, and 4. This demonstrates
parallel evaluator execution. GOMAXPROCS controls Go execution parallelism; these
runs do not pin whole processes to that many CPU cores. Unbound remains at four
threads during the Go scaling controls.

With the current resolver, a ten-query policy sustains approximately the same
aggregate DNS query rate as a one-query policy. Its evaluations are slower
because those dependent lookups occur sequentially. Adding goroutines within
each SPF evaluation would not remove dependencies between parent and included
records. Independent requests already run concurrently.

## CPU evidence and interpretation

Separate 15-second profiled runs are excluded from the throughput medians.
The simple SPF profile contains 47.04 CPU-seconds over 15.01 wall-seconds:

| Stack / function | CPU share | Interpretation |
|---|---:|---|
| `ServerResolver.lookup` | 82.53% cumulative | Most evaluator CPU is inside DNS lookup work |
| `net.Dialer.DialContext` | 31.04% cumulative | Per-query socket establishment is expensive |
| `dns.Client.ExchangeWithConnContext` | 30.57% cumulative | DNS exchange, I/O and encoding/decoding |
| Linux `Syscall6` | 42.11% flat | Kernel crossings are the largest individual sampled cost |
| `runtime.mallocgc` | 7.50% cumulative | Allocation is a secondary source of cost |
| SPF lexer `next` | 0.66% cumulative | Small contribution for this simple policy |

Cumulative entries overlap and must not be added together. CPU sampling is not
wall-clock latency attribution. See `results/spf-profile.txt` and the raw pprof
files for the evidence.

For the simple policy at 64 connections, spfd used approximately 248.6% CPU,
the load generator 46.2%, and Unbound 39.8%. Its throughput also includes protocol
parsing, TCP I/O, admission controls, deadline handling, and per-request JSON log
encoding. Logs go to `/dev/null`, so disk and journald backpressure are excluded.
These co-located measurements do not isolate the daemon's capacity with a remote
or dedicated load generator. The difference from library throughput cannot be
assigned entirely to SPF code or to logging.

The separate spfd perf sample also shows kernel socket/wakeup work: its largest
flat symbol was `_raw_spin_unlock_irqrestore` at 7.65%, with 6.86% under
`__wake_up_sync_key`; the call graph includes UDP receive/wakeup paths reached
from DNS writes. No samples were lost. This supports transport/scheduling work
as a follow-up but does not identify one dominant daemon-specific lock or prove
that logging is its bottleneck. See `results/daemon-perf.txt`.

## Environment and configuration

- Repository: `zaccone/spf`, newest fetched `origin/master` at start,
  **`6903f42590eaeece3e80606cb5f5ffda73fcd6ad`**.
- The VM received an archive of that revision plus this benchmark harness.
  Production library and daemon source were unmodified.
- Ubuntu 26.04.1, Linux `7.0.0-31-generic`, KVM/QEMU virtual CPU, four vCPUs,
  one thread per core, approximately 7.2 GiB RAM, no swap use observed.
- Go `go1.27.1 linux/amd64`; miekg/dns `v1.1.73` from the repository module.
- Apt-installed Unbound `1.24.2-1ubuntu2.2`, plus dnsutils, dnsperf and sysstat.
- Unbound listens at `127.0.0.1:53`; four threads, `so-reuseport: yes`, four
  cache slabs, 128 MiB message cache and 256 MiB RRset cache.
- `ratelimit: 0`, `ip-ratelimit: 0`, `num-queries-per-thread: 4096`,
  `outgoing-range: 8192`; 4 MiB receive/send socket buffers. Kernel maxima were
  already 16 MiB. Unbound's systemd file-descriptor limit was 524,288, with no
  CPU quota or CPU affinity restriction.
- `spfd serve -max-checks 4096 -max-connections 4096`; at most 128 connections
  used. Application admission caps therefore did not constrain the sweep.
- SPF's standards-related per-evaluation DNS budgets remain enabled.
- Prefetch and expired-answer serving disabled. Fixture TTL is 86,400 seconds.
- Test zone is explicitly insecure to allow deterministic locally forwarded
  fixtures; this does not benchmark DNSSEC validation on a cache miss.
- No CPU pinning or physical-host isolation. Loopback avoids an external network
  round trip, but still incurs socket, kernel, scheduling, and DNS-server work.

The installed configuration is archived in `unbound.conf`. The VM run directory
is `/home/marek/spf-unbound-20260915`; Unbound remains running after the tests.
The fixture authority and temporary spfd processes are stopped after the run.
System DNS stub configuration was not changed.

`go test ./...` passed before benchmarking. After measurements,
`go vet ./...` and `go test -race ./...` passed on the VM. Final process checks
confirmed Unbound running and no remaining temporary spfd or fixture authority.

## Method and validity

The fixture authority runs temporarily at `127.0.0.1:15353`. The runner queries
all twelve fixture names through Unbound, then terminates the authority before
measurement. Every trial records Unbound counters before and after execution.
The recorded counters show zero cache misses during the sweep and repeated trials.
Query counts match exactly: one, two, or ten queries per evaluation/request,
one per DNS control operation, and zero for the memory control.

All library evaluations assert `pass`. DNS controls check lookup success, and
policy clients check complete `action=DUNNO` responses. Each operation is counted,
including errors; no errors were observed. There were 67 exploratory trials and
33 repeated ten-second trials. The repeated trials alone completed 148,350,701
operations, including the much faster memory control.

Clients are closed-loop: each worker sends its next request only after the
previous request completes. This measures throughput and latency at a fixed
number of outstanding operations. It does **not** model a fixed arrival rate or
an external queue, so these percentiles must not be read as open-loop production
SLO guarantees. An overloaded arrival stream could have much longer queueing.

Histograms use 1 µs buckets, rounded down, with overflow at 100 ms. All reported
percentiles fall below the overflow bucket. The 1 µs values in the memory control
reflect this resolution and do not imply identical individual latencies.
Worker/connection startup precedes timing; loop/timestamp/histogram bookkeeping
contributes to QPS. CPU accounting is approximate, with startup/teardown included
in client CPU but not in the elapsed-time denominator.

These intentionally small, fully cached IPv4 policies exclude public DNS misses,
large TXT answers, TCP fallback, MX/PTR address walks, non-pass explanations, and
real mail traffic distributions. The ten-query memory fixture also constructs
policy strings in its callback; use the simple memory fixture for the cleanest
evaluator-only comparison. pyspf was not rerun in this series.

## Follow-ups to discuss

1. **Prototype bounded UDP connection reuse in ServerResolver.** Compare complete
   SPF and spfd throughput against this baseline. Preserve response ID/question/
   source validation, cancellation, deadlines, TCP fallback, and safe concurrent
   use. Prevent late responses from leaking between borrowers. The DNS control
   demonstrates opportunity, not the final performance gain of a safe pool.
2. **Tune concurrency against a latency target.** Start further testing near 16
   active checks for this VM. The optimum depends on DNS misses and workload;
   do not turn the 4096 benchmark caps into a deployment recommendation.
3. **Profile daemon-specific costs after transport reuse.** Evaluate protocol
   allocations, repeated deadline/context work, and JSON logging with realistic
   log destinations. Use a separate load-generator host or dedicated cores to
   distinguish service capacity from shared-machine contention.
4. **Consider bounded parsing or DNS caching only with measured justification.**
   Parsing is a smaller opportunity in this baseline. A parsed-record cache can
   key on the fetched policy string; a DNS cache additionally needs correct TTL,
   negative-answer, concurrency, and SPF-budget semantics. Avoid indefinite
   caching or weakening limits for throughput.
5. **Validate the next candidate with a realistic policy mix and arrival-rate
   tests.** Include cache misses, DNSSEC, failures, MX/PTR, TCP fallback and log
   backpressure; compare error rates as well as throughput and p99.

No production performance fix was applied during this measurement. The proposed
changes above are discussion items, with socket reuse the highest-priority
candidate based on the current evidence.

## Go SPF library versus pyspf

A follow-up run configured pyspf 2.0.14 with dnspython 2.8.0 to query the same
warmed Unbound explicitly at `127.0.0.1:53`. It used the same client IP, sender,
HELO and three policies. Dnspython's resolver was created with `configure=False`,
`nameservers=['127.0.0.1']`, port 53 and no dnspython cache. Thus these results do
not use the VM's systemd-resolved stub or an external resolver.

Peak settings were selected independently: 64 goroutines for Go and eight Python
processes for pyspf. Values are medians of three ten-second trials.

| Policy / DNS queries | Implementation | Workers | QPS | p50 µs | p75 µs | p90 µs | p99 µs |
|---|---|---:|---:|---:|---:|---:|---:|
| Simple / 1 | Go | 64 | 232,517 | 150 | 376 | 673 | 1,690 |
| Simple / 1 | pyspf processes | 8 | 24,801 | 312 | 344 | 469 | 640 |
| Include / 2 | Go | 64 | 117,541 | 425 | 732 | 1,120 | 2,450 |
| Include / 2 | pyspf processes | 8 | 12,761 | 608 | 678 | 780 | 1,066 |
| Include chain / 10 | Go | 64 | 24,127 | 2,457 | 3,205 | 4,139 | 7,151 |
| Include chain / 10 | pyspf processes | 8 | 2,684 | 2,937 | 3,104 | 3,332 | 4,388 |

Go's peak throughput is 9.38×, 9.21× and 8.99× pyspf's for the simple,
include and ten-query policies respectively.

The percentile comparison above is at each implementation's maximum-throughput
setting, so concurrency differs. Go carries more outstanding operations and has
higher p99 than pyspf for these peak configurations. A matched four-worker view
from the exploratory sweeps makes per-operation latency easier to compare:

| Policy | Go QPS | pyspf, four processes QPS | Go advantage | Go p50 / p99 µs | pyspf p50 / p99 µs |
|---|---:|---:|---:|---:|---:|
| Simple | 137,961 | 23,377 | 5.90× | 23 / 103 | 157 / 320 |
| Include | 69,518 | 12,216 | 5.69× | 50 / 168 | 303 / 587 |
| Include chain | 14,268 | 2,571 | 5.55× | 264 / 585 | 1,507 / 2,372 |

One pyspf thread peaked at 6,993, 3,556 and 757 checks/s respectively. Additional
threads reduced throughput while increasing latency because the standard Python
build has the GIL. Separate processes scaled across cores: four processes reached
23,404 simple checks/s, and eight reached 24,801; sixteen fell to 23,857 with
higher latency. The practical peak on this VM was eight processes.

Go `spfd` is also faster than the bare pyspf library at their measured peak
settings: 98,860 versus 24,801 requests/checks per second for simple (3.99×),
61,989 versus 12,761 for include (4.86×), and 16,911 versus 2,684 for the chain
(6.30×). This is not a service-to-service comparison: `spfd` includes Postfix
protocol I/O and logging, whereas the pyspf measurement is a direct library call.
A pyspf policy daemon would add its own wrapper overhead.

All timed pyspf checks returned pass. Each subprocess also performed 100 warm-up
checks before timing; Unbound counters exactly equal `(timed checks + 100)` times
the policy's DNS-query count. Every answer was a cache hit, with zero misses,
timeouts, wait-limit events, or rate-limit drops. The three repeated eight-process
trials completed 1,208,896 timed checks.

The configured `DNSLookup` adapter duplicates pyspf's bundled dnspython lookup
behavior but calls a dedicated resolver instance per worker so the target server
is explicit. It retains pyspf's TXT representation and error mapping. These tests
measure pyspf library evaluation, dnspython encoding/decoding, and real loopback
DNS I/O; they exclude a Python Postfix policy wrapper.

## Artifacts

- [Reproduction instructions](README.md), `main.go`, `authority.py`, `run.py`,
  `confirm.py`, `dnsperf_ipv6.py`, `verify.py`, and `unbound.conf`.
- `sweep.jsonl`: all 67 exploratory trials, per-process CPU and Unbound deltas.
- `confirm.jsonl`: all 33 repeated trials with the same diagnostics.
- `pyspf-thread-sweep.jsonl`, `pyspf-sweep.jsonl`, `pyspf-extra.jsonl`,
  `pyspf-confirm.jsonl`, and `pyspf-peak.jsonl`: thread/process selection and
  repeated pyspf results.
- `results/`: CPU profile summaries and raw Go profiles, independent dnsperf
  outputs, and daemon perf summary. The larger raw daemon perf recording remains
  on the VM under its `results/` directory.
