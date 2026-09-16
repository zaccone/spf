"""Validate and summarize archived results; no VM access required."""
from collections import defaultdict
import json
from pathlib import Path
from statistics import median

rows = [json.loads(line) for line in Path(__file__).with_name("results.jsonl").read_text().splitlines()]
assert len(rows) == 72, len(rows)
groups = defaultdict(list)
for row in rows:
    assert row["n"] > 0 and row["errors"] == 0
    assert abs(row["qps"] - row["n"] / row["seconds"]) < 0.00001
    queries = (row["n"] + (100 if row["implementation"] == "mail-auth" else 0)) * {"simple": 1, "include": 2, "chain0": 10}[row["scenario"]]
    assert row["expected_dns_queries"] == queries
    assert row["dns_delta"]["total.num.queries"] == row["dns_delta"]["total.num.cachehits"] == queries
    assert all(value == 0 for key, value in row["dns_delta"].items() if key not in ["total.num.queries", "total.num.cachehits"])
    assert 0 <= row["p50_us"] <= row["p75_us"] <= row["p90_us"] <= row["p99_us"] < 100000
    groups[row["scenario"], row["workers"], row["implementation"]].append(row)
for group in groups.values():
    assert len(group) == 3 and {r["repeat"] for r in group} == {1, 2, 3}
print("| Policy | Concurrency | Go checks/s | mail-auth checks/s | Go / Rust | Go p99 µs | Rust p99 µs |")
print("|---|---:|---:|---:|---:|---:|---:|")
for scenario in ["simple", "include", "chain0"]:
    for workers in [1, 4, 16, 64]:
        go = groups[scenario, workers, "go"]
        rust = groups[scenario, workers, "mail-auth"]
        gq, rq = median(r["qps"] for r in go), median(r["qps"] for r in rust)
        print(f"| {scenario} | {workers} | {gq:,.0f} | {rq:,.0f} | {gq/rq:.2f}× | {median(r['p99_us'] for r in go)} | {median(r['p99_us'] for r in rust)} |")
print(f"Validated {len(rows)} trials, {sum(r['n'] for r in rows):,} measured checks.")

shared = [json.loads(line) for line in Path(__file__).with_name("shared.jsonl").read_text().splitlines()]
assert len(shared) == 27
shared_groups = defaultdict(list)
for row in shared:
    assert row["n"] > 0 and row["errors"] == 0
    assert row["resolver_sharing"] == "shared"
    assert abs(row["qps"] - row["n"] / row["seconds"]) < 0.00001
    counts = row["dns_delta"]
    assert counts["total.num.queries"] == counts["total.num.cachehits"] > 0
    assert all(value == 0 for key, value in counts.items() if key not in ["total.num.queries", "total.num.cachehits"])
    assert abs(row["dns_queries_per_check_including_warmup"] - counts["total.num.queries"] / (row["n"] + 100)) < 1e-12
    shared_groups[row["scenario"], row["workers"]].append(row)
print("\n| Policy | Concurrency | Shared Rust checks/s | DNS queries/check (including warmup) |")
print("|---|---:|---:|---:|")
for scenario in ["simple", "include", "chain0"]:
    for workers in [4, 16, 64]:
        group = shared_groups[scenario, workers]
        assert len(group) == 3 and {r["repeat"] for r in group} == {1, 2, 3}
        print(f"| {scenario} | {workers} | {median(r['qps'] for r in group):,.0f} | {median(r['dns_queries_per_check_including_warmup'] for r in group):.6f} |")
print(f"Validated {len(shared)} shared-resolver trials, {sum(r['n'] for r in shared):,} measured checks.")
