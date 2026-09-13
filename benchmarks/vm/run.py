"""Run paired trials sequentially, alternating implementation order."""
import json, os, subprocess
os.environ['GOMAXPROCS'] = '4'
with open('results.jsonl', 'w', buffering=1) as out:
    for scenario in ('simple', 'include'):
        for delay in (0, 1000):
            for workers in (1, 4, 16, 64):
                for repeat in range(3):
                    for impl in (('go', 'pyspf') if repeat % 2 == 0 else ('pyspf', 'go')):
                        cmd = ['./spfbench'] if impl == 'go' else ['../venv/bin/python', 'benchmarks/vm/bench.py']
                        cmd += ['--scenario', scenario, '--delay', str(delay), '--workers', str(workers), '--n', str(20000 if delay == 0 else 1000)]
                        data = json.loads(subprocess.check_output(cmd))
                        data['repeat'] = repeat + 1
                        out.write(json.dumps(data) + '\n')
                        print(impl, scenario, delay, workers, repeat + 1, round(data['checks_per_second']), flush=True)
