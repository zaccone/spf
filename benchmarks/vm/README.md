# Ubuntu VM library benchmark

See [REPORT.md](REPORT.md) for findings and limitations. These are synthetic
resolver microbenchmarks, not SMTP/policy-daemon load tests.

Sources: `main.go` (Go goroutines), `bench.py` (Python threads or Linux forked
processes), `run.py` (concurrency sweep), `run_extended.py` (longer CPU trials
and four-process baseline). Every evaluation must return `pass` or the run fails.

To reproduce in an isolated parent directory on Linux:

1. Install Go 1.27.1 at `../go` and create a Python 3.14.4 venv at `../venv`.
2. Install `pyspf==2.0.14 dnspython==2.8.0` into that venv.
3. From the repository root, run:

```sh
../go/bin/go build -o spfbench ./benchmarks/vm
../go/bin/go test ./...
../venv/bin/python benchmarks/vm/run.py
../venv/bin/python benchmarks/vm/run_extended.py
```

The runners set `GOMAXPROCS=4`, run trials sequentially, and write
`results.jsonl` and `extended.jsonl` in the working directory. The archived
results alongside this README came from the user-provided Ubuntu VM.
The process mode uses Linux `fork`; do not run it on macOS.

Each trial warms up 100 evaluations before timing. Worker count means simultaneous
closed-loop evaluations, with no incoming request queue. Every worker records
per-evaluation latency. Python pool setup, shutdown, result gathering and (in
process mode) sample serialization are included in throughput timing; Go includes
goroutine creation and joining. Sorting is excluded. Interpreter/binary launch
and warmup are excluded. Percentiles measure evaluation time, not client latency.
No throughput or latency thresholds are suitable as CI gates on arbitrary hosts.
