"""pyspf benchmark using dnspython against the same local Unbound instance."""
import argparse
import collections
import concurrent.futures
import json
import multiprocessing
import threading
import time

import dns.exception
import dns.resolver
import spf

p = argparse.ArgumentParser()
p.add_argument('--workers', type=int, default=4)
p.add_argument('--duration', type=float, default=5)
p.add_argument('--scenario', choices=('simple', 'include', 'chain0'), default='simple')
p.add_argument('--processes', action='store_true')
a = p.parse_args()
if a.workers < 1 or a.duration <= 0:
    p.error('workers and duration must be positive')

worker_state = threading.local()

def initialize():
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['127.0.0.1']
    resolver.port = 53
    resolver.timeout = 2
    resolver.lifetime = 2
    resolver.cache = None
    worker_state.resolver = resolver

def lookup(name, qtype, tcpfallback=True, timeout=30):
    del tcpfallback
    result = []
    try:
        answers = worker_state.resolver.resolve(name, qtype, lifetime=min(timeout, 2), search=False)
        for rdata in answers:
            if qtype in ('A', 'AAAA'):
                value = rdata.address
            elif qtype == 'MX':
                value = (rdata.preference, rdata.exchange)
            elif qtype == 'PTR':
                value = rdata.target.to_text(True)
            elif qtype in ('TXT', 'SPF'):
                value = rdata.strings
            else:
                raise AssertionError(qtype)
            result.append(((name, qtype), value))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        raise spf.TempError('DNS ' + str(exc)) from exc
    return result

spf.DNSLookup = lookup
domain = a.scenario + '.benchmark.test'

def check():
    result = spf.check2(i='192.0.2.1', s='sender@' + domain, h='mail.benchmark.test')
    if result[0] != 'pass':
        raise AssertionError(result)

start_signal = None
deadline_shared = None

def worker():
    initialize()
    start_signal.wait()
    histogram = collections.Counter()
    count = errors = 0
    while time.perf_counter() < deadline_shared.value:
        before = time.perf_counter_ns()
        try:
            check()
        except Exception:
            errors += 1
        elapsed = min((time.perf_counter_ns() - before) // 1000, 100000)
        histogram[elapsed] += 1
        count += 1
    return count, errors, histogram

if __name__ == '__main__':
    for _ in range(100):
        initialize()
        check()
    executor_type = concurrent.futures.ProcessPoolExecutor if a.processes else concurrent.futures.ThreadPoolExecutor
    context = multiprocessing.get_context('fork')
    start_signal = context.Event() if a.processes else threading.Event()
    deadline_shared = context.Value('d', 0) if a.processes else type('Deadline', (), {'value': 0.0})()
    kwargs = {'mp_context': context} if a.processes else {}
    with executor_type(max_workers=a.workers, **kwargs) as pool:
        futures = [pool.submit(worker) for _ in range(a.workers)]
        time.sleep(.2)
        began = time.perf_counter()
        deadline_shared.value = began + a.duration
        start_signal.set()
        parts = [future.result() for future in futures]
        seconds = time.perf_counter() - began
    histogram = collections.Counter()
    count = errors = 0
    for n, e, h in parts:
        count += n
        errors += e
        histogram.update(h)
    output = {'implementation': 'pyspf-processes' if a.processes else 'pyspf-threads',
              'scenario': a.scenario, 'workers': a.workers, 'n': count,
              'errors': errors, 'seconds': seconds, 'qps': count / seconds}
    for percentile in (50, 75, 90, 99):
        target = (count * percentile + 99) // 100
        accumulated = 0
        for latency in sorted(histogram):
            accumulated += histogram[latency]
            if accumulated >= target:
                output[f'p{percentile}_us'] = latency
                break
    print(json.dumps(output))
