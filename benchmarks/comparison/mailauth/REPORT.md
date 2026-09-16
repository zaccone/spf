# SPF benchmark: this Go library versus Stalwart mail-auth

Measured on the supplied four-vCPU VM, 15 September 2026 UTC. Both libraries
were invoked directly, using deterministic DNS fixtures cached in the same local
Unbound. This compares library-plus-resolver paths, not SMTP servers or parsers
alone. Source versions and build details are in [PROVENANCE.md](PROVENANCE.md).

## Conclusions

- With identical measured DNS work, the Go library delivered **19–58% higher
  throughput** across the tested policies and concurrency levels.
- mail-auth delivered **lower p99 latency at concurrency 16 and 64** in all three
  policies, despite lower throughput in that equal-DNS configuration.
- Sharing mail-auth's resolver across workers changed the result dramatically:
  repeated-domain response sharing reduced actual DNS traffic and gave Rust
  substantially higher throughput at high concurrency. This is a real advantage
  of that resolver path for this workload, not evidence of a faster SPF parser.
- Both implementations passed their own tests. A common conformance corpus was
  not run, so this does **not** establish equal completeness or RFC compliance.

## Equal-DNS results

Medians of three three-second trials per cell. DNS queries per evaluation are
exactly 1 for simple, 2 for include, and 10 for chain0. Rust uses an independent
resolver per worker to prevent cross-worker request sharing; its answer cache
is disabled and optional mail-auth parsed-record caches are not supplied.

| Policy | Workers | Go checks/s | mail-auth checks/s | Go / Rust | Go p99 µs | Rust p99 µs |
|---|---:|---:|---:|---:|---:|---:|
| simple | 1 | 34,323 | 28,105 | 1.22× | 55 | 58 |
| simple | 4 | 136,370 | 92,532 | 1.47× | 100 | 94 |
| simple | 16 | 222,970 | 159,035 | 1.40× | 407 | 209 |
| simple | 64 | 235,035 | 188,167 | 1.25× | 1776 | 606 |
| include | 1 | 17,016 | 14,354 | 1.19× | 104 | 108 |
| include | 4 | 68,632 | 43,558 | 1.58× | 171 | 171 |
| include | 16 | 112,878 | 79,466 | 1.42× | 682 | 378 |
| include | 64 | 117,169 | 92,972 | 1.26× | 2639 | 1183 |
| chain0 | 1 | 3,593 | 2,819 | 1.27× | 473 | 474 |
| chain0 | 4 | 13,859 | 8,760 | 1.58× | 617 | 771 |
| chain0 | 16 | 22,911 | 16,092 | 1.42× | 2080 | 1568 |
| chain0 | 64 | 23,899 | 18,628 | 1.28× | 6759 | 4864 |

All 72 trials passed validation: 15,783,103 timed checks, all SPF Pass, exact
expected Unbound query/cache-hit counts, and zero recorded misses or drops.
Rust's 100 untimed warmup checks per trial are included in DNS accounting.

## Shared-resolver results

A separate experiment uses one mail-auth authenticator/resolver across workers.
Hickory 0.26.3 shares identical concurrent requests even with `cache_size = 0`.
The source stores shared futures in its active-request map until creator cleanup;
answer-cache settings alone therefore do not ensure one DNS request per check.
The extremely low observed DNS counts in some cells should be interpreted as
response reuse in this tight repeated-domain workload, not independent DNS-backed
evaluations. We did not test expiry or varied-domain behavior here.

Medians of three two-second trials:

| Policy | Workers | Shared mail-auth checks/s | Actual DNS queries/check* |
|---|---:|---:|---:|
| simple | 4 | 611,951 | 0.020525 |
| simple | 16 | 1,798,487 | 0.000028 |
| simple | 64 | 1,767,726 | 0.000028 |
| include | 4 | 43,871 | 0.501771 |
| include | 16 | 882,981 | 0.000189 |
| include | 64 | 924,616 | 0.000131 |
| chain0 | 4 | 8,691 | 2.564804 |
| chain0 | 16 | 31,443 | 0.716821 |
| chain0 | 64 | 74,538 | 0.444120 |

*DNS ratios include the 100 warmup checks and their queries. At very low ratios,
warmup dominates the counted DNS requests. Medians are computed independently.

All 27 trials passed: 36,916,004 timed checks, all SPF Pass, zero recorded DNS
misses or drops. At 64 workers this path delivered approximately **7.5×, 7.9×,
and 3.1×** the Go throughput for simple, include, and chain0 respectively, while
doing far less DNS work. These are not equal-DNS speedups. Scheduling sensitivity
was visible: simple at four workers ranged from approximately 553k to 792k/s.

## Correctness and scope

Go `go test ./...` passed. Rust `cargo test --release --lib spf::` passed five
matching tests, including SPF verification over 170 expected-result entries in
13 resource files. These are separate test corpora. Timed cases cover only
successful IPv4 ip4/include policies, not macros, IPv6, MX/PTR, malformed records,
DNS failures, lookup limits, explanations, or other SPF outcomes.

The VM's four cores also run Unbound; there is no CPU pinning or hypervisor
isolation. Trials are short, closed-loop, and use warm local DNS, not public DNS
latency or a heterogeneous mail stream. Runtime scheduling, socket behavior, and
resolver implementation costs are included. No claim about general Go versus
Rust performance, deployment popularity, or production capacity follows.

For a production-oriented follow-up, use a common correctness corpus and a
mixed-domain workload with explicit application-cache, TTL, DNS-latency, and
concurrent-request-sharing policies. Neither library was modified in this work.

## Reproduction and evidence

- [README.md](README.md): fixture, build, and run procedure; timing details.
- [PROVENANCE.md](PROVENANCE.md): pinned commits, toolchains, binary hashes.
- [results.jsonl](results.jsonl): all equal-DNS trials.
- [shared.jsonl](shared.jsonl): all shared-resolver trials.
- [summarize.py](summarize.py): validates both archives and prints these tables.
- [go-tests.log](go-tests.log) and [spf-tests.log](spf-tests.log): test output.
- Cargo lockfiles archive both benchmark and upstream-test dependencies.
