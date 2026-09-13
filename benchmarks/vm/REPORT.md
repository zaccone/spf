# Go SPF versus pyspf: Ubuntu VM benchmark report

Run date: 14 September 2026 (Europe/Warsaw; VM UTC clock was 13 September).

## Findings

The Go library already executes independent SPF evaluations concurrently. On
this four-vCPU VM, Go has a substantial throughput advantage on two small,
CPU-bound synthetic policies. Python threads also overlap simulated DNS waits;
Python processes improve CPU-bound throughput. These results support building a
bounded concurrent Go policy service, but do not establish production SMTP
capacity or performance against an installed pyspf policy daemon.

## Environment and provenance

- Ubuntu 26.04.1 LTS, Linux 7.0.0-31-generic, x86-64, KVM/QEMU virtual CPU.
- Four vCPUs, one thread per core, approximately 7.2 GiB RAM; initial load average
  0.17 / 0.10 / 0.09. Shared VM, no CPU pinning or host isolation.
- Go 1.27.1, `GOMAXPROCS=4`.
- Python 3.14.4, standard GIL enabled, pyspf 2.0.14, dnspython 2.8.0.
- Go library commit `e6f1fae7aa1e280798d3d0ecf9b5a052f4b9bab4`, plus the
  accompanying benchmark harness. Production library files were unchanged.
- pyspf is the pinned PyPI 2.0.14 release, not the upstream development revision
  used to source the repository's conformance fixtures.
- Tools and source remain in `~/spf-benchmark-20260914` on the supplied VM.
  No MTA or system service was installed or reconfigured.

## Method

Both implementations check IP `192.0.2.1`, sender `sender@example.com` and HELO
`unknown`. Every timed check asserts SPF `pass`. Each check has fresh evaluation
state; there is no cross-request DNS or parsed-policy cache.

Two deterministic policies are served through custom resolver callbacks:

- **Simple:** `v=spf1 ip4:192.0.2.0/24 -all` — one TXT callback per evaluation.
- **Include:** `v=spf1 include:child.example.com -all`, with the simple policy at
  the child — two TXT callbacks per evaluation.

Resolvers either return immediately or sleep for a requested 1 ms per callback.
Actual sleeps can exceed 1 ms due to scheduler/timer behavior. No DNS packets,
recursive server, socket transport or public DNS are involved. The Go callback
uses a context-aware timer; the Python callback uses `time.sleep`. These
fixtures measure evaluator costs and waiting behavior, not DNS client equality.

The concurrency sweep uses 1, 4, 16 and 64 workers, 20,000 evaluations per
zero-delay trial and 1,000 per delayed trial. Extended trials use 200,000
zero-delay evaluations at 1 and 4 workers and add four Python processes; delayed
extended trials use 1,000 evaluations. Each trial warms up 100 evaluations and
runs three times. Implementations alternate order between repetitions and never
run simultaneously. Final extended trials ran after validation completed.

Reported throughput is the median of three trial throughputs. The range is the
minimum–maximum across those trials, not a confidence interval. Latencies are
medians of each trial's percentiles, not pooled percentiles. Worker count is a
closed-loop concurrency level, not a request arrival rate. Pool/goroutine startup
and joining are timed; Python additionally gathers sample lists and, in process
mode, serializes them. Interpreter launch, warmup and final sorting are excluded.
Python process overhead therefore reflects this harness, not a tuned persistent
policy daemon. Short high-concurrency delayed trials are indicative only.

## CPU-bound results (longer trials)

Checks per second, zero simulated DNS delay:

| Policy | Implementation | Workers | Median checks/s | Min–max checks/s | p95 µs |
|---|---|---:|---:|---:|---:|
| simple | go | 1 | 864,343 | 856,028–867,834 | 1.3 |
| simple | go | 4 | 2,041,427 | 2,037,247–2,275,888 | 2.8 |
| simple | pyspf | 1 | 97,877 | 97,515–98,747 | 10.2 |
| simple | pyspf | 4 | 96,448 | 96,039–96,471 | 12.5 |
| simple | pyspf-processes | 4 | 373,071 | 365,330–376,167 | 10.6 |
| include | go | 1 | 500,062 | 494,796–500,893 | 2.3 |
| include | go | 4 | 1,288,161 | 1,122,367–1,382,695 | 4.0 |
| include | pyspf | 1 | 62,866 | 61,835–63,802 | 16.2 |
| include | pyspf | 4 | 61,311 | 61,225–61,441 | 20.1 |
| include | pyspf-processes | 4 | 238,508 | 236,755–242,159 | 17.2 |

At four workers, Go / four-process Python throughput ratios are 5.47× (simple) and 5.40× (include). These ratios apply only to these fixtures.

## Simulated DNS delay: concurrency sweep

Requested delay is 1 ms per TXT callback. Throughput medians:

| Policy | Workers | Go checks/s | Python threads checks/s | Go p95 µs | Python p95 µs |
|---|---:|---:|---:|---:|---:|
| simple | 1 | 940 | 926 | 1072 | 1099 |
| simple | 4 | 3,749 | 3,692 | 1086 | 1099 |
| simple | 16 | 14,713 | 14,352 | 1115 | 1099 |
| simple | 64 | 55,272 | 24,614 | 1173 | 1913 |
| include | 1 | 470 | 465 | 2142 | 2181 |
| include | 4 | 1,868 | 1,831 | 2164 | 2198 |
| include | 16 | 7,298 | 7,203 | 2223 | 2199 |
| include | 64 | 27,293 | 17,824 | 2279 | 3131 |

The near-equal low-concurrency results show why faster parsing alone cannot
remove DNS latency. Higher concurrency overlaps independent waits. Python also
benefits from this; the difference grows as scheduling and evaluation CPU costs
become more significant.

Four-process Python delayed throughput (extended trials):

- simple: 3,635 checks/s.
- include: 1,835 checks/s.

## Validation and limits

Linux `go test ./...`, `go test -race ./...` and `go vet ./...` passed.
All 156 retained trials completed and their evaluations asserted `pass`.
The ordinary tests include the existing deterministic conformance corpus;
the timing fixtures are intentionally much narrower.

Not measured: real UDP/TCP DNS behavior, caching, DNSSEC, MX/PTR or macro-heavy
policies, failures and timeouts under load, IPv6, SMTP/policy protocol costs,
queueing and overload, sustained saturation, memory/RSS, CPU utilization, or
free-threaded Python. The race suite validates covered code paths; the concurrent
benchmark itself was built normally, without race instrumentation. Virtualization
and timer scheduling add noise. Do not use these figures as production sizing
numbers or as a claim that every Go workload outperforms every pyspf deployment.

## Recommended next implementation

Build `cmd/spfd` as a Postfix policy service using the existing library. Bound
active requests, queue length and connection count; apply deadlines, support
graceful shutdown, and expose request latency, outcomes, overload and DNS metrics.
Keep SPF mechanism ordering and per-evaluation budgets intact while processing
independent requests with goroutines. Use a local caching recursive DNS server.

Then compare the actual Go service with an explicitly selected Python policy
service, using identical DNS fixtures through a real DNS server and an external
load generator. Measure sustained request rates, p50/p95/p99 end-to-end latency,
RSS and CPU across success, rejection, timeout and overload workloads. Postfix
integration and systemd packaging should be validated before production sizing.
Postfix documents the integration protocol in its
[SMTP policy delegation guide](https://www.postfix.org/SMTPD_POLICY_README.html).

## What “DNS budget” means

A DNS budget limits work **within one SPF evaluation**, not concurrency across
messages. Our evaluator enforces:

- At most ten evaluated DNS-causing terms (`include`, `a`, `mx`, `ptr`, `exists`
  and `redirect`), shared through recursion. `ip4`, `ip6` and `all` do not consume
  this term budget. The initial SPF TXT retrieval does not consume a term either.
- At most two void logical lookups (NXDOMAIN or an empty answer).
- MX expansion limited to ten exchange address lookups; PTR validation examines
  at most ten returned names.
- A shared 20-second evaluation deadline, or an earlier caller deadline.

This is not a limit of ten DNS packets: one term can cause several queries,
and transport retries are different from SPF term accounting. Exceeding term
or void limits yields `permerror`; deadline expiry yields `temperror`.
These rules follow the work-limiting model in
[RFC 7208 §4.6.4](https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.4),
with the concrete implementation in `evaluation_context.go`.
A server-level concurrency limit is a separate resource control.

## Artifacts and reproduction

- [Harness and instructions](README.md)
- [Concurrency sweep, 96 raw trials](results.jsonl)
- [Extended comparison, 60 raw trials](extended.jsonl)
- [Report generator](report.py)

Run `python3 benchmarks/vm/report.py` to regenerate this report from the archived
results. No benchmark dependencies are added to the Go library.
