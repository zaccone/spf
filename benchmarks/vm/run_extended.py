import json, os, subprocess
os.environ['GOMAXPROCS'] = '4'
with open('extended.jsonl', 'w', buffering=1) as out:
    for scenario in ('simple', 'include'):
        for delay in (0, 1000):
            for repeat in range(3):
                modes = [('go', 1), ('go', 4), ('pyspf', 1), ('pyspf', 4), ('pyspf-processes', 4)]
                if repeat % 2: modes.reverse()
                for impl, workers in modes:
                    cmd = ['./spfbench'] if impl == 'go' else [os.path.abspath('../venv/bin/python'), 'benchmarks/vm/bench.py']
                    if impl == 'pyspf-processes': cmd += ['--processes']
                    cmd += ['--scenario', scenario, '--delay', str(delay), '--workers', str(workers), '--n', str(200000 if delay == 0 else 1000)]
                    data = json.loads(subprocess.check_output(cmd))
                    data['repeat'] = repeat + 1
                    out.write(json.dumps(data) + '\n')
                    print(impl, scenario, delay, workers, repeat + 1, round(data['checks_per_second']), flush=True)
