"""Synthetic DNS benchmark. Thread workers share no SPF query state."""
import argparse, concurrent.futures, json, time, multiprocessing
import spf
p = argparse.ArgumentParser()
p.add_argument('--workers', type=int, default=1)
p.add_argument('--n', type=int, default=20000)
p.add_argument('--delay', type=int, default=0)
p.add_argument('--scenario', default='simple')
p.add_argument('--processes', action='store_true')
a = p.parse_args()
def lookup(name, qtype, *args):
    if qtype != 'TXT':
        raise AssertionError((name, qtype))
    if a.delay:
        time.sleep(a.delay / 1e6)
    policy = b'v=spf1 ip4:192.0.2.0/24 -all'
    if a.scenario == 'include' and name.rstrip('.') == 'example.com':
        policy = b'v=spf1 include:child.example.com -all'
    return [((name, 'TXT'), [policy])]
spf.DNSLookup = lookup
def check():
    result = spf.check2(i='192.0.2.1', s='sender@example.com', h='unknown')
    assert result[0] == 'pass', result
for _ in range(100):
    check()
def worker(w):
    samples = []
    for _ in range(w, a.n, a.workers):
        start = time.perf_counter_ns()
        check()
        samples.append((time.perf_counter_ns() - start) / 1000)
    return samples
start = time.perf_counter()
executor = concurrent.futures.ProcessPoolExecutor if a.processes else concurrent.futures.ThreadPoolExecutor
kwargs = {'mp_context': multiprocessing.get_context('fork')} if a.processes else {}
with executor(max_workers=a.workers, **kwargs) as pool:
    samples = [s for batch in pool.map(worker, range(a.workers)) for s in batch]
elapsed = time.perf_counter() - start
samples.sort()
print(json.dumps(dict(implementation='pyspf-processes' if a.processes else 'pyspf', workers=a.workers, n=a.n, delay_us=a.delay, scenario=a.scenario, seconds=elapsed, checks_per_second=a.n/elapsed, p50_us=samples[a.n//2], p95_us=samples[a.n*95//100], p99_us=samples[a.n*99//100])))
