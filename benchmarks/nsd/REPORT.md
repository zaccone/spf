# SPF / spfd readiness benchmark — 16 September 2026

The library and daemon passed this synthetic real-DNS suite: **13,913,356
completed evaluations across 126 trials, with zero result/action mismatches**.
The 60-second daemon soak completed **2,256,428 checks** at **37,605 checks/s**.
All strict DNS/cache gates and the separate overload, recovery, deadline,
connection-limit and active-DNS shutdown checks passed. No production-code
changes were necessary to pass these tests.

This supports a controlled production rollout with deployment-specific
validation. It does **not** establish universal production readiness, Internet
cold-DNS capacity, or the absence of long-term leaks. The corpus is synthetic,
load is closed-loop, and the soak is only one minute.

## Reproduction and evidence

Follow [README.md](README.md). Exact evidence is under
[results/20260916](results/20260916):

- [metadata.json](results/20260916/metadata.json): versions, flags, source and
  binary hashes, fixture/config hashes, and VM platform;
- [results.jsonl](results/20260916/results.jsonl): all trials, per-case operation
  counts, DNS counters, daemon result counts, CPU/RSS snapshots, and gates;
- [resilience.json](results/20260916/resilience.json): operational checks;
- generated case manifests, NSD/Unbound configurations, and all three zones.

The archived configurations contain the original run directory. Generate new
ones for another VM rather than copying those absolute paths unchanged.
`summarize.py` validates completion and prints the complete comparison table.

The measured production source is base commit `3563443` on `spf_benchmarks`,
with the new benchmark harness added in the working tree. Exact source hashes
identify the code measured; the benchmark commit also adds documentation,
result summarization, and harness failure tests. No library or daemon source
was modified. Both binaries were built with `-trimpath`.

Environment: four-vCPU x86-64 Ubuntu VM, Linux `7.0.0-31-generic`, Go 1.27.1,
Unbound 1.24.2, NSD 4.14.0, `GOMAXPROCS=4`. Load generator, resolver, authority,
and daemon shared the VM without CPU pinning. The resolver used one thread and
NSD one serving process. The daemon ran with enforcement enabled, 256 active
checks, 512 connections, a three-second evaluation timeout, and JSON logging
written normally to a file.

Run options: 34 base fixtures plus 1,000 tenant owners, three five-second repeats,
uniform and Zipf distributions, 1/16/64/128 workers, one serial cold evaluation
per base case per mode, and a 60-second uniform daemon soak at 128 workers.

## Throughput and latency

Selected median results across three trials:

| Mode | Distribution | Workers | Median checks/s | Median p99 upper bound |
|---|---|---:|---:|---:|
| Library | Uniform | 128 | 64,768 | 9.1 ms |
| Library | Zipf | 128 | 99,373 | 8.1 ms |
| Daemon | Uniform | 16 | 37,935 | 2.0 ms |
| Daemon | Uniform | 64 | 40,629 | 6.9 ms |
| Daemon | Uniform | 128 | 38,900 | 14.5 ms |
| Daemon | Zipf | 16 | 52,191 | 1.7 ms |
| Daemon | Zipf | 64 | 57,115 | 5.3 ms |
| Daemon | Zipf | 128 | 55,415 | 11.1 ms |

On this VM the daemon reached its best measured throughput at 64 workers.
Doubling to 128 increased latency and reduced throughput. Sixteen workers
provided most of the uniform throughput with substantially lower tail latency.
These are co-located benchmark observations, not recommended production
concurrency limits or mail-system capacity guarantees.

The soak's p99 upper bound was 15.3 ms, with no histogram overflow. Its daemon
result mix included pass, fail, softfail, neutral, none, and permerror; every
wire response and logged result count matched expectations. All hot trials
had zero Unbound cache misses and exact expected client-query counts. No
rate-limit, overwritten-request, exceeded-request or timeout/drop counters
were observed in those trials.

Cold trials exercised the authority after a flush before each evaluation.
They establish correctness and cache-path coverage; a single observation per
case is insufficient for meaningful cold-latency percentiles. The two
large-answer fixtures each produced one UDP query plus one TCP retry, verified
by Unbound's query and TCP counters.

## Fault handling and operational checks

All library and daemon fault checks passed through Unbound:

- SERVFAIL returned SPF temperror / policy 451 4.7.24.
- Silent authority drops returned temperror / 451 in approximately two seconds,
  within the configured three-second evaluation budget. These are the two
  intentional histogram overflows; their percentile fields are null.
- The 100-ms delayed authority returned pass / DUNNO in approximately 201 ms
  end-to-end. The authority delay is not the whole resolver transaction latency.

A separate daemon with two evaluation slots produced 16 prompt 451 4.3.0
responses while both slots waited for DNS. After the timed-out checks finished,
a passing request succeeded, showing slot recovery. Partial requests hit the
500-ms read deadline, oversized lines were rejected, and connections above a
four-connection limit were closed. SIGTERM during an active DNS request exited
cleanly in approximately **114 ms** with a 100-ms shutdown grace.

These tests distinguish expected overload deferrals from throughput-test errors.
The sweep itself runs below the configured admission limits and requires zero
unexpected deferrals.

## Other validation

- `go test -race ./...` and `go vet ./...` passed on the Linux VM and macOS host.
- The Linux binary smoke suite passed monitor/enforce behavior, null senders,
  persistent connections, concurrent clients and SIGTERM shutdown.
- New harness tests verify nonzero exit status for incorrect SPF results,
  incorrect policy actions, and malformed response framing; expected permerror
  diagnostics remain valid corpus outcomes.
- Existing lexer and parser fuzz targets each ran for 20 seconds on the macOS
  host with four workers: 1,297,823 lexer executions and 1,065,414 parser
  executions, with no failures. This is bounded fuzz coverage, not exhaustive.
- NSD/Unbound configs and all generated zones passed the installed validation
  tools. The archived result set passed `summarize.py` completion checks.

The VM's prior Unbound service was restored after each run. NSD remains installed
but its packaged service is disabled; the runner starts its own private NSD.
Full process logs remain on the VM in `/var/lib/unbound/spf-bench-full`. The source
and binaries are under `/home/marek/spf-nsd-20260916`. Large per-request logs are
not committed; measurements and reproducible fixture/config data are committed.

## Remaining rollout checks

Before treating this as a production capacity estimate, test the intended
Postfix configuration and failure actions, actual sender-policy distribution,
resolver cache sizing, remote DNS latency/loss, and the planned logging/storage
backend. Use an offered-rate workload for arrival spikes and a multi-hour soak
with periodic RSS/FD sampling for leak investigation. This suite's before/after
RSS snapshots cannot establish peak memory or leak absence. Internet DNSSEC,
delegation behavior, and real SMTP delivery are outside this unsigned local
corpus. Existing RFC and resolver tests remain necessary alongside benchmarks.

A sensible next deployment step is monitor mode on a limited mail flow with
observability for SPF result distribution, timeout/overload rates, and latency,
then an enforcement rollout after those results match the site's policy.
