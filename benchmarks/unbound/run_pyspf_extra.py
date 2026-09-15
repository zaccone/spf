"""Check whether oversubscribing the four-vCPU VM improves pyspf throughput."""
import json
import pathlib
import subprocess

out = pathlib.Path('results')
python = '/home/marek/spf-benchmark-20260914/venv/bin/python'

def stats():
    raw = subprocess.check_output(['sudo', 'unbound-control', 'stats_noreset'], text=True)
    return {k: float(v) for k, v in (line.split('=', 1) for line in raw.splitlines())}

with (out / 'pyspf-extra.jsonl').open('w') as destination:
    for workers in (8, 16):
        for scenario in ('simple', 'include', 'chain0'):
            before = stats()
            args = [python, 'source/benchmarks/unbound/pyspf_bench.py', '--processes',
                    '--scenario', scenario, '--workers', str(workers), '--duration', '5']
            result = json.loads(subprocess.check_output(args, text=True))
            after = stats()
            result['dns_delta'] = {k: after[k] - v for k, v in before.items()
                                   if k.startswith('total.') or 'ratelimit' in k}
            destination.write(json.dumps(result) + '\n')
            destination.flush()
            print(json.dumps(result), flush=True)
