# mail-auth versus this SPF library

Completed measurements and interpretation: [REPORT.md](REPORT.md).

This benchmark calls both libraries directly for MAIL FROM identity evaluation.
Both resolve through `127.0.0.1:53`, with every answer already cached in Unbound.
The Rust driver disables Hickory's answer cache (`cache_size = 0`) and does not
supply mail-auth's optional parsed-record caches. The Go driver uses the current
`ServerResolver`. Neither implementation is modified.

The main matrix constructs one independent Rust resolver per worker, because
Hickory 0.26.3 shares concurrent identical requests even with `cache_size = 0`.
Cloning one shared authenticator produced far fewer DNS queries than evaluations
and failed the main runner's exact query-count check. Independent resolvers
prevent this sharing across workers; each worker has only one outstanding check.
The 100 warmup checks use a separate resolver before the worker resolvers start.
This tests the cost of one/two/ten DNS queries per evaluation, not mail-auth's
maximum throughput with its usual shared-resolver deployment pattern.

`shared.py` measures that shared-resolver pattern separately with 4/16/64 workers,
three two-second repetitions, and the same answer-cache/parsed-cache settings.
It records actual DNS queries per check instead of requiring one/two/ten. These
results apply to repeated checks of the same policy in a tight closed loop.

Inputs: IP `192.0.2.1`, sender `sender@<scenario>.benchmark.test`.
Scenarios: simple matching ip4 (one TXT lookup), include (two TXT lookups), and
nine nested includes (ten TXT lookups). Every timed result must be SPF pass.

Four Tokio runtime threads and `GOMAXPROCS=4`; 1/4/16/64 concurrent checks;
three repetitions of three seconds each, alternating implementation order.
Each worker has a histogram with one-microsecond buckets and overflow at 100 ms.
Reported throughput counts completed calls, including errors (which invalidate
the run). Elapsed time includes draining outstanding checks. Process launch is
excluded. Rust performs 100 untimed warmup calls before each trial. Per-call
latency includes asynchronous scheduling and DNS. Rust's final histogram merge
is included in throughput timing; Go's merge is excluded (small fixed overhead).

The runner checks exact Unbound query and cache-hit counts, accounting for Rust
warmup, zero cache misses, and zero recorded rate-limit/request-list drops. These
checks establish that neither library silently bypasses DNS in this experiment.
The shared four-vCPU VM also runs Unbound; these figures are not standalone CPU
parser benchmarks, cache-hit benchmarks within the application, or mail-server
capacity estimates. Connection reuse, runtime scheduling and DNS implementation
differences are included in the measured library paths.

## Layout on the VM

`/home/marek/spf-comparison-20260915/` contains:

- `mail-auth/`: upstream commit `fc60beec99e5ec12ea8abf26603f1aad0fbafef0`
  (manifest version 0.13.2), unmodified source.
- `spf-current/`: this repository at `4b2195ea06fb5d7510ea54001e4b02f0456e3e3d`.
- `mailauth/`: contents of this directory; the relative Cargo dependency assumes
  the upstream source is in its sibling `mail-auth/` directory.
- `go-current`: built with Go 1.27.1 from `spf-current/benchmarks/unbound`.

Rust uses the default mail-auth features, a Cargo release build, and Rust 1.93.1.
`Cargo.lock` records benchmark dependency versions. The separate upstream test
build has its own lockfile, archived as `upstream-tests.Cargo.lock`.

## Reproduction

1. Stage the exact upstream sources and driver in the layout above.
2. Prepare the deterministic Unbound fixture using
   `benchmarks/unbound/README.md`; warm all twelve fixture names. Stop unrelated
   benchmark services so their DNS requests do not contaminate counters.
3. Build `go-current` from the pinned Go source with
   `go build -o ../go-current ./benchmarks/unbound`.
4. In `mailauth/`, run `cargo build --release --locked`.
5. Run `python3 run.py`. This requires permission for
   `sudo -n unbound-control stats_noreset`. It creates `results.jsonl` exclusively
   and refuses to overwrite previous results. Retain each run separately.
6. Run `python3 shared.py` separately (after the main matrix completes).
7. Run `python3 summarize.py` beside the archived `results.jsonl` to validate and
   print both result tables (requires `shared.jsonl` as well).

Tests: `go test ./...` in the pinned Go source; `cargo test --release --lib spf::`
in the pinned mail-auth source. Their test corpora differ; passing both does not
establish equal RFC coverage. The performance scenarios exercise only successful
IPv4 ip4/include policies.
