# SPF / spfd real-DNS benchmark suite

This suite provides a reproducible Linux benchmark using Unbound and NSD.
It tests the library and the **Postfix policy protocol**, not gRPC. See
[REPORT.md](REPORT.md) for the recorded VM results and readiness limits.

```text
spf / spfd -> 127.0.0.1:53 Unbound -> 127.0.0.1:15353 NSD
                                -> 127.0.0.1:15354 fault authority
```

No Python packages are required. The fixture generator, orchestration, fault
server and resilience checks use the standard library. The Go driver uses the
repository's existing dependencies. The old `benchmarks/unbound` and
`benchmarks/vm` artifacts remain historical baselines.

## Deploy on another VM

Use an isolated Linux benchmark VM with Python 3.9+, the Go version required by
`go.mod`, and these packages (Ubuntu/Debian):

```sh
sudo apt-get update
sudo apt-get install -y nsd unbound dnsutils
```

The packages may automatically start DNS services. The runner deliberately fails
if any benchmark port is occupied; it never stops or rewrites system services.
On a dedicated benchmark VM, stop packaged NSD/Unbound before running, then
restore whichever services were previously active afterward. Leave
systemd-resolved on its separate stub addresses. No `/etc/resolv.conf` change is
needed. Keep unrelated DNS clients off the benchmark resolver.

From a checkout of the repository:

```sh
mkdir -p /tmp/spf-bench-bin
go test -race ./...
go vet ./...
go build -trimpath -o /tmp/spf-bench-bin/bench ./benchmarks/nsd
go build -trimpath -o /tmp/spf-bench-bin/spfd ./cmd/spfd
python3 tools/smoke_spfd.py /tmp/spf-bench-bin/spfd

sudo env PATH="$PATH" GOMAXPROCS=4 \
  BENCH_REVISION="$(git rev-parse HEAD)" \
  BENCH_DIRTY="$(git status --porcelain)" \
  python3 benchmarks/nsd/run.py \
    --out /var/lib/unbound/spf-benchmark-001 \
    --bench /tmp/spf-bench-bin/bench \
    --spfd /tmp/spf-bench-bin/spfd
```

Every run needs a **new output directory**. `/var/lib/unbound/...` is compatible
with Ubuntu's packaged Unbound AppArmor policy; arbitrary home-directory paths
are not. Run directories are mode 0700. These dedicated loopback test processes
run under the invoking root account to bind port 53 and share the protected
control socket. These are test configs, not hardened production service units.
They do not replace `/etc/nsd/nsd.conf` or `/etc/unbound/unbound.conf`.

The runner validates configs and zones before starting its processes, verifies
readiness, and terminates its own processes on normal exit, failure, SIGINT, or
SIGTERM. A forced kill or VM crash may require manually stopping leftover
processes. Keep the run logs to diagnose failures. NSD and Unbound must support
the options in the templates; the recorded run identifies the tested versions.

Quick validation:

```sh
# Add these options to the run.py command above, with a fresh --out:
# --replicas 100 --workers 1,16 --seconds 1 --repeats 1 --soak-seconds 2
```

For a larger working set or longer pressure run, use `--replicas 10000`,
`--seconds 30`, and `--soak-seconds 1800`. A corpus larger than the configured
resolver cache can legitimately fail the strict hot-cache gate; that is a
working-set/cache-sizing experiment, not a valid hot-cache regression result.
There are no machine-independent throughput thresholds.

## Corpus and configuration

`generate.py` creates three zones, the case manifests, and runnable configs from
[nsd.conf.in](nsd.conf.in) and [unbound.conf.in](unbound.conf.in). Generate and
inspect them without root or launching services:

```sh
python3 benchmarks/nsd/generate.py --out /tmp/spf-fixtures --replicas 1000
```

The 34 base cases cover:

- pass, fail, softfail, neutral, none, and permerror;
- NXDOMAIN versus NODATA, invalid syntax, duplicate SPF TXT records;
- IPv4 and IPv6, A, MX, PTR and `%{p}`, including forward-confirmed IPv6 PTR;
- include and redirect, missing targets, recursion cycles, 9/10/11 includes;
- two versus three void lookups, five MX hosts with the matching preference
  last, and eleven MX hosts exceeding the limit;
- CNAMEs, TXT character-string concatenation, non-SPF TXT noise, long policies,
  ignored modifiers, explanations, and UDP truncation followed by TCP retry;
- a policy combining IP networks, A, MX, and include.

By default 1,000 additional tenant owners cycle through **all 34 fixture types**,
including their IP families and failure results. Their absolute dependency names
remain shared, modeling hosted-provider dependencies. This is a synthetic stress
corpus with explicit expected results, not a sampled distribution of Internet
mail traffic. `--replicas 0` uses just the base fixtures.

Uniform sampling gives each manifest entry equal probability. Zipf sampling
uses exponent 1.2 and the manifest order as popularity rank: simple policies
are deliberately more popular. Per-worker seeds are recorded. Scheduling and
total completed counts can vary even with the same seeds. Every request's
selected case is counted in the output.

Review decisions relative to the original design:

- Preserve `spf/spfd -> 127.0.0.1:53`; unsigned zones are domain-insecure.
- Configure private stub zones and a refusing root local-zone to prevent
  dependencies on public DNS. The isolated resolver has no public workload.
- Disable Unbound prefetch, expired-answer serving, and RRset rotation. NSD's
  rotation setting alone cannot guarantee the client's answer order. The MX
  last-match case uses distinct preferences rather than arbitrary RR order.
- Keep the authority running. A valid cold trial flushes immediately before
  **each** individual evaluation; an initially cold concurrent run soon becomes
  a hot run. Fault trials also clear Unbound's infrastructure cache.
- Use generated IPv6 nibble names. Keep faults in a separate subtree and server,
  outside NSD performance measurements.

Option semantics were checked against the upstream
[NSD configuration manual](https://nsd.docs.nlnetlabs.nl/en/latest/manpages/nsd.conf.html)
and [Unbound configuration manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html),
then validated with the installed checkconf/checkzone tools on the VM.

## Gates and measurements

The default run performs complete library warmup/correctness, daemon correctness,
serial cold checks of every base case, another complete warmup, three repeats
of both distributions at 1/16/64/128 workers for both modes, a 60-second daemon
soak, and separate DNS-fault and daemon-resilience checks.

Every mismatch fails the executable and the runner. Expected SPF diagnostics
for permerror/temperror are not confused with harness failures. Daemon trials
verify both wire actions and the distribution of actual SPF results in its JSON
logs, since `DUNNO` alone cannot distinguish pass from none or permerror.

Unbound counters are sampled outside each trial. Gates require exact client DNS
query totals, no hot-cache misses, at least one miss for each cold evaluation,
and no rate-limit or request-loss counters. Counts include TCP retries: the two
large-response fixtures produce two client queries per evaluation. Counts are
**client-to-Unbound packets**, not SPF's ten-term budget or upstream NSD queries.
Fault query counts are intentionally not fixed because retries are resolver
policy. Gauge/average/max snapshots are preserved; only counters are differenced.

The load driver uses bounded 100-microsecond histogram buckets and reports
p50/p95/p99 upper bounds, plus a 2-second overflow count. When any sample overflows,
percentiles are null rather than presenting a capped value as a measured bound.
QPS uses completed operations over elapsed wall time, including startup of policy
connections and the last in-flight operations. Latency includes a complete SPF
call or policy round trip; the first policy call includes connection setup.
Histogram updates, case counting, and selection also cost CPU. All load is
**closed-loop**, so it does not measure offered-rate queueing or coordinated
omission under an external arrival process.

The runner records CPU and RSS snapshots for DNS/daemon/fault processes and NSD
children before and after each trial. These are not peak RSS or a leak detector.
The load generator, Unbound, NSD, and daemon share the VM. Daemon JSON logging is
enabled to a file and its cost is included. Default daemon capacity is 256 active
checks and 512 connections for a maximum sweep of 128 workers. Raising workers
beyond those limits intentionally fails the no-overload performance gate.

The separate resilience phase uses two evaluation slots to verify immediate
451 overload responses, recovery after DNS timeouts, a 500-ms partial-request
read deadline, oversized-line rejection, four-connection capacity, and bounded
SIGTERM shutdown while DNS is active. The fault phase checks SERVFAIL, silent
packet drops, and a 100-ms delayed authority through the same Unbound interface.
Existing race and daemon smoke tests additionally cover monitor mode, null
senders, persistent connections, cancellation, protocol validation, and RFC
conformance fixtures.

Outputs include `metadata.json` (versions, options, revision, source/binary/config
hashes), generated zones and manifests, `results.jsonl`, `resilience.json`, and
process logs. Archive these together. A revision supplied for an exported source
tree identifies its base; source hashes and the dirty label identify uncommitted
benchmark development. Raw JSONL must be checked for validation errors before
using performance numbers.

Validate completion and print a comparison table:

```sh
sudo python3 benchmarks/nsd/summarize.py /var/lib/unbound/spf-benchmark-001
```
