# Cached Unbound benchmark

See [REPORT.md](REPORT.md) for results, limitations, and proposed follow-ups.
The harness benchmarks the unmodified SPF library and daemon plus two DNS
controls. No benchmark dependencies are added to the Go module.

## Fixtures and measurement

- `simple.benchmark.test`: one TXT lookup, matching `ip4`.
- `include.benchmark.test`: two TXT lookups, matching child include.
- `chain0.benchmark.test`: ten TXT lookups, nine nested includes, matching leaf.

`authority.py` serves deterministic TXT records on loopback port 15353 with
86400-second TTLs. `run.py` warms Unbound and stops the authority before timing.
Unbound statistics are sampled around each trial to verify actual cache hits,
query counts, and absence of rate-limit drops. The machine's system resolver
configuration is not used by the benchmark.

Modes in `main.go`:

- `memory`: SPF with immediate TXT callbacks; no DNS sockets.
- `spf`: complete library evaluation through `ServerResolver`.
- `dns`: `ServerResolver.LookupTXTContext`, without SPF evaluation.
- `reuse`: one persistent UDP connection per worker using miekg/dns directly.
  This control omits ServerResolver validation and cancellation handling; it is
  not a production replacement or a measured SPF optimization.
- `policy`: persistent loopback TCP connections to `spfd`, one outstanding
  Postfix protocol request per connection.

All timing is closed-loop. QPS counts completed operations over elapsed wall
time. Percentiles cover a complete library call, DNS call, or policy round trip
depending on mode. Worker creation and connection setup precede measurement.
Histograms have 1-microsecond buckets, rounded down, and a final overflow bucket
at 100 ms. Reported percentiles remain below that overflow bucket.
Histogram updates and loop timing contribute to measured throughput.

## Reproduction on the benchmark VM

The archived run used `/home/marek/spf-unbound-20260915`, with the repository in
`source/`. Python with dnspython and Go were reused from
`/home/marek/spf-benchmark-20260914/{venv,go}`. The Python scripts contain those
paths; adjust them for a different machine. Required apt packages are `unbound`,
`dnsutils`, `dnsperf`, and `sysstat`. `perf` was already available.

1. Use the report's exact repository revision to reproduce, or record the new
   revision when comparing a later version.
2. Install `unbound.conf` as
   `/etc/unbound/unbound.conf.d/spf-benchmark.conf`, validate with
   `sudo unbound-checkconf`, and restart Unbound. This assumes Ubuntu's packaged
   include-directory configuration and an available `127.0.0.1:53`.
3. From `source/`, build `go build -o ../bench ./benchmarks/unbound` and
   `go build -o ../spfd ./cmd/spfd`; run `go test ./...`.
4. From the parent run directory, run
   `python3 source/benchmarks/unbound/run.py`, then
   `python3 source/benchmarks/unbound/confirm.py`.

The first script sweeps 1, 4, 16, 64, and 128 workers at four Go processors,
plus one/two-processor controls. The second selects peak settings, repeats them
three times for ten seconds, and adds 16-worker simple SPF and policy controls.
It then collects separate Go CPU profiles, a daemon perf profile, and independent
dnsperf runs. Instrumented trials do not contribute to headline results.

The independent `dnsperf_ipv6.py` control uses `::1` because this VM's packaged
dnsperf failed to send to its IPv4-mapped target. It can also run separately from
the VM run directory. Unbound's archived configuration enables both loopback
families; all Go/SPF measurements use `127.0.0.1`. The original invalid dnsperf
runs are retained as diagnostic artifacts and excluded from results.

The daemon runs with `-max-checks 4096 -max-connections 4096`; logs are encoded
normally and written to `/dev/null`. Both scripts terminate their daemon when
finished. Unbound remains installed and running. Re-run the warmup before a new
series; the fixture authority does not remain running after cache priming.

Raw JSONL results, profile summaries, and dnsperf output accompany the report.
CPU percentages use 100% per core. Client CPU includes benchmark process startup
and teardown, while its denominator is the measured window, so it is approximate.
The three co-located processes share all four VM cores.

## pyspf comparison

`pyspf_bench.py` configures a dedicated dnspython resolver for `127.0.0.1:53`
instead of reading `/etc/resolv.conf`. `run_pyspf.py` sweeps threads and processes,
`run_pyspf_extra.py` checks process oversubscription, and
`confirm_pyspf_peak.py` repeats the selected eight-process peak. The scripts use
pyspf 2.0.14 and dnspython 2.8.0 from the existing VM virtual environment.

Each subprocess performs 100 untimed warm-up checks after the outer runner reads
Unbound's initial counters. Verification therefore expects `(n + 100)` times the
policy's one, two, or ten DNS queries. There is no dnspython answer cache.
