"""Sweep and repeat pyspf against warmed local Unbound with counter checks."""
import json
import pathlib
import resource
import subprocess

root = pathlib.Path.cwd()
out = root / 'results'
out.mkdir(exist_ok=True)
python = '/home/marek/spf-benchmark-20260914/venv/bin/python'

def stats():
    raw = subprocess.check_output(['sudo', 'unbound-control', 'stats_noreset'], text=True)
    return {k: float(v) for k, v in (line.split('=', 1) for line in raw.splitlines())}

def run(mode, scenario, workers, duration):
    before = stats()
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    args = [python, 'source/benchmarks/unbound/pyspf_bench.py',
            '--scenario', scenario, '--workers', str(workers),
            '--duration', str(duration)]
    if mode == 'processes':
        args.append('--processes')
    result = json.loads(subprocess.check_output(args, text=True))
    after_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    result['client_cpu_pct'] = 100 * (
        after_usage.ru_utime + after_usage.ru_stime - usage.ru_utime - usage.ru_stime
    ) / result['seconds']
    after = stats()
    result['dns_delta'] = {k: after[k] - v for k, v in before.items()
                           if k.startswith('total.') or 'ratelimit' in k}
    return result

rows = []
with (out / 'pyspf-sweep.jsonl').open('w') as destination:
    for mode, workers in [('processes', 1), ('processes', 2),
                          ('processes', 4)]:
        for scenario in ('simple', 'include', 'chain0'):
            result = run(mode, scenario, workers, 3)
            rows.append(result)
            destination.write(json.dumps(result) + '\n')
            destination.flush()
            print(json.dumps(result), flush=True)

for line in (out / 'pyspf-thread-sweep.jsonl').read_text().splitlines():
    rows.append(json.loads(line))

best = {}
for result in rows:
    key = (result['implementation'], result['scenario'])
    if key not in best or result['qps'] > best[key]['qps']:
        best[key] = result
with (out / 'pyspf-confirm.jsonl').open('w') as destination:
    for repeat in range(1, 4):
        for result in best.values():
            confirmed = run('processes' if result['implementation'].endswith('processes') else 'threads',
                            result['scenario'], result['workers'], 10)
            confirmed['repeat'] = repeat
            destination.write(json.dumps(confirmed) + '\n')
            destination.flush()
            print(json.dumps(confirmed), flush=True)
