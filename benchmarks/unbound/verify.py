"""Validate archived measurements without rerunning load tests."""
import collections
import json
import math
import pathlib
import re

root = pathlib.Path(__file__).resolve().parent
count = 0
for filename, expected in [('sweep.jsonl', 67), ('confirm.jsonl', 33)]:
    rows = [json.loads(line) for line in (root / filename).read_text().splitlines()]
    assert len(rows) == expected
    groups = collections.defaultdict(list)
    for r in rows:
        assert r['n'] > 0 and r['errors'] == 0 and r['seconds'] > 0
        assert math.isclose(r['qps'], r['n'] / r['seconds'], rel_tol=1e-10)
        percentiles = [r[f'p{p}_us'] for p in [50, 75, 90, 99]]
        assert percentiles == sorted(percentiles) and percentiles[-1] < 100000
        queries = 0 if r['mode'] == 'memory' else {'simple': 1, 'include': 2, 'chain0': 10}[r['scenario']]
        delta = r['dns_delta']
        assert delta['total.num.queries'] == delta['total.num.cachehits'] == r['n'] * queries
        for key in ['total.num.cachemiss', 'total.num.queries_wait_limit',
                    'total.num.queries_timed_out', 'total.requestlist.exceeded',
                    'total.requestlist.overwritten', 'total.num.queries_ip_ratelimited',
                    'num.query.ratelimited']:
            assert delta[key] == 0, (filename, key, r)
        groups[(r['mode'], r['scenario'], r['workers'])].append(r)
    if filename == 'confirm.jsonl':
        assert all(len(v) == 3 and {r['repeat'] for r in v} == {1, 2, 3} for v in groups.values())
    count += len(rows)
for threads in [1, 2, 4]:
    raw = (root / 'results' / f'dnsperf-ipv6-{threads}.txt').read_text()
    sent = int(re.search(r'Queries sent:\s+(\d+)', raw)[1])
    completed = int(re.search(r'Queries completed:\s+(\d+)', raw)[1])
    lost = int(re.search(r'Queries lost:\s+(\d+)', raw)[1])
    delta = json.loads(raw.splitlines()[-1])['dns_delta']
    assert sent == completed == delta['total.num.queries'] == delta['total.num.cachehits']
    assert sent > 0 and lost == delta['total.num.cachemiss'] == delta['num.query.ratelimited'] == 0
for filename, expected in [('pyspf-thread-sweep.jsonl', 12),
                           ('pyspf-sweep.jsonl', 9),
                           ('pyspf-extra.jsonl', 6),
                           ('pyspf-confirm.jsonl', 18),
                           ('pyspf-peak.jsonl', 9)]:
    rows = [json.loads(line) for line in (root / filename).read_text().splitlines()]
    assert len(rows) == expected
    for r in rows:
        queries = {'simple': 1, 'include': 2, 'chain0': 10}[r['scenario']]
        delta = r['dns_delta']
        assert r['n'] > 0 and r['errors'] == 0
        assert delta['total.num.queries'] == delta['total.num.cachehits'] == (r['n'] + 100) * queries
        for key in ['total.num.cachemiss', 'total.num.queries_wait_limit',
                    'total.num.queries_timed_out', 'total.requestlist.exceeded',
                    'total.requestlist.overwritten', 'total.num.queries_ip_ratelimited',
                    'num.query.ratelimited']:
            assert delta[key] == 0, (filename, key, r)
    count += len(rows)
print(f'PASS: {count} Go/pyspf trials and 3 valid dnsperf controls; exact cached query counts, zero errors/drops.')
