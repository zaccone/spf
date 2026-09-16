#!/usr/bin/env python3
"""Validate a completed run and print median throughput by workload."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import statistics


def summarize(path):
    metadata = json.loads((path / 'metadata.json').read_text())
    resilience = json.loads((path / 'resilience.json').read_text())
    rows = [json.loads(line) for line in (path / 'results.jsonl').read_text().splitlines()]
    options = metadata['options']
    cases = json.loads((path / 'cases.json').read_text())
    base_count = sum(not c['name'].startswith('tenant-') for c in cases)
    # Three whole-corpus correctness/warmup rows, serial cold base cases,
    # the two-mode/two-distribution sweep, optional soak, and six fault rows.
    expected_rows = (3 + base_count * options['cold'] * 2
                     + options['repeats'] * 4 * len(options['workers'].split(','))
                     + bool(options['soak_seconds']) + 6)
    if len(rows) != expected_rows:
        raise ValueError(f'incomplete run: {len(rows)} rows, expected {expected_rows}')
    if any(row['errors'] or row['validation_errors'] or row['n'] < 1 for row in rows):
        raise ValueError('run contains failed trials')
    required = ('recovery', 'partial_request_deadline', 'oversized_line', 'connection_limit')
    if not all(resilience.get(key) for key in required) or resilience.get('overload_rejections') != 16:
        raise ValueError('incomplete resilience checks')
    if not 0 <= resilience['active_dns_shutdown_seconds'] < 2:
        raise ValueError('shutdown deadline exceeded')
    groups = defaultdict(list)
    for row in rows:
        if row['cache'] == 'hot' and 'repeat' in row:
            groups[(row['mode'], row['distribution'], row['workers'])].append(row)
    for trials in groups.values():
        if {r['repeat'] for r in trials} != set(range(options['repeats'])) or len(trials) != options['repeats']:
            raise ValueError('missing or duplicated sweep repeats')
    print(f"Validated {len(rows)} trials, {sum(r['n'] for r in rows):,} evaluations; no mismatches.")
    print('| Mode | Distribution | Workers | Median ops/s | Min–max ops/s | Median p99 upper bound (ms) |')
    print('|---|---|---:|---:|---:|---:|')
    for (mode, distribution, workers), trials in sorted(groups.items()):
        qps = [r['qps'] for r in trials]
        p99 = [r['p99_us_upper'] for r in trials]
        latency = f'{statistics.median(p99)/1000:.1f}' if all(v is not None for v in p99) else 'overflow'
        print(f'| {mode} | {distribution} | {workers} | {statistics.median(qps):,.0f} | {min(qps):,.0f}–{max(qps):,.0f} | {latency} |')
    for row in rows:
        if row.get('soak'):
            print(f"Soak: {row['n']:,} evaluations in {row['seconds']:.2f}s; {row['qps']:,.0f} ops/s.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path)
    summarize(parser.parse_args().run)
