"""Repeat the peak pyspf process setting selected by the extended sweep."""
import json
import pathlib
import subprocess

out = pathlib.Path('results')
python = '/home/marek/spf-benchmark-20260914/venv/bin/python'

def stats():
    raw = subprocess.check_output(['sudo', 'unbound-control', 'stats_noreset'], text=True)
    return {k: float(v) for k, v in (line.split('=', 1) for line in raw.splitlines())}

with (out / 'pyspf-peak.jsonl').open('w') as destination:
    for repeat in range(1, 4):
        for scenario in ('simple', 'include', 'chain0'):
            before = stats()
            result = json.loads(subprocess.check_output([
                python, 'source/benchmarks/unbound/pyspf_bench.py', '--processes',
                '--scenario', scenario, '--workers', '8', '--duration', '10'], text=True))
            after = stats()
            result['repeat'] = repeat
            result['dns_delta'] = {k: after[k] - v for k, v in before.items()
                                   if k.startswith('total.') or 'ratelimit' in k}
            destination.write(json.dumps(result) + '\n')
            destination.flush()
            print(json.dumps(result), flush=True)
