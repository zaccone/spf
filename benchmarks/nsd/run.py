#!/usr/bin/env python3
"""Run a private DNS stack, correctness gates and hot/cold load trials (Linux)."""
import argparse
from collections import Counter
import signal
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from generate import generate
from resilience import run as resilience


def command(*args):
    return subprocess.check_output([str(a) for a in args], text=True, stderr=subprocess.STDOUT)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True, help='new absolute run directory')
    p.add_argument('--bench', type=Path, required=True)
    p.add_argument('--spfd', type=Path, required=True)
    p.add_argument('--replicas', type=int, default=1000)
    p.add_argument('--seconds', type=float, default=5)
    p.add_argument('--workers', default='1,16,64,128')
    p.add_argument('--repeats', type=int, default=3)
    p.add_argument('--soak-seconds', type=float, default=60, help='additional hot policy soak; 0 disables')
    p.add_argument('--cold', type=int, default=1, help='cold repeats per named fixture (not tenants)')
    a = p.parse_args()
    workers = [int(x) for x in a.workers.split(',')]
    if a.soak_seconds < 0 or a.seconds <= 0 or a.repeats < 1 or a.cold < 0 or not 0 <= a.replicas <= 100000 or any(w < 1 or w > 4096 for w in workers):
        p.error('invalid trial settings')
    if os.geteuid() != 0: p.error('run with sudo to bind loopback port 53')
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    a.out = a.out.resolve(); a.bench = a.bench.resolve(); a.spfd = a.spfd.resolve()
    if a.out.exists(): p.error('output directory must be new; results are never overwritten')
    for port in (53,15353,15354,10023):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM) if port != 10023 else (socket.SOCK_STREAM,):
            with socket.socket(socket.AF_INET, kind) as s:
                s.bind(('127.0.0.1',port))
    a.out.mkdir(mode=0o700, parents=True)
    generate(a.out, a.replicas)
    metadata = dict(started_utc=datetime.now(timezone.utc).isoformat(), platform=platform.platform(), cpu_count=os.cpu_count(), options=vars(a).copy(),
                    revision=os.environ.get('BENCH_REVISION') or command('git','rev-parse','HEAD').strip(),
                    dirty=os.environ.get('BENCH_DIRTY', 'unknown'),
                    go=command('go','version').strip(),
                    unbound=command('unbound','-V'), nsd=command('nsd','-v'))
    metadata['sha256'] = {str(f.name):hashlib.sha256(f.read_bytes()).hexdigest() for f in [a.bench,a.spfd,*a.out.glob('*.zone'),a.out/'cases.json',a.out/'fault-cases.json',a.out/'unbound.conf',a.out/'nsd.conf',*Path(__file__).parent.glob('*.py'),*Path(__file__).parent.glob('*.go'),*Path(__file__).parent.glob('*.in')]}
    source_root=Path(__file__).resolve().parents[2]
    metadata['source_sha256']={str(f.relative_to(source_root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in source_root.rglob('*.go')}
    (a.out/'metadata.json').write_text(json.dumps(metadata,default=str,indent=2)+'\n')
    command('nsd-checkconf',a.out/'nsd.conf'); command('unbound-checkconf',a.out/'unbound.conf')
    for f in a.out.glob('*.zone'): command('nsd-checkzone',f.stem,f)
    processes=[]; logs=[]
    def launch(name, args):
        log=(a.out/(name+'.log')).open('w'); logs.append(log)
        proc=subprocess.Popen([str(v) for v in args],stdout=log,stderr=log);processes.append(proc);return proc
    def control(*args): return command('unbound-control','-c',a.out/'unbound.conf',*args)
    def flush():
        for zone in ('fault.spfbench.test.','spfbench.test.','2.0.192.in-addr.arpa.','8.b.d.0.1.0.0.2.ip6.arpa.'):
            control('flush_zone',zone)
    def stats(): return {k:float(v) for k,v in (line.split('=',1) for line in control('stats_noreset').splitlines())}
    def resources():
        result={}
        pids=[proc.pid for proc in processes]
        for pid in pids:
            children=Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
            pids.extend(int(child) for child in children)
            fields=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
            result[str(pid)]={'cpu_seconds':(int(fields[11])+int(fields[12]))/os.sysconf('SC_CLK_TCK'), 'rss_bytes':int(fields[21])*os.sysconf('SC_PAGE_SIZE')}
        return result
    cases=json.loads((a.out/'cases.json').read_text()); by_name={c['name']:c for c in cases}
    def trial(file, mode, cache, extra, manifest='cases.json', **labels):
        before=stats(); rb=resources()
        log_offset=(a.out/'spfd.log').stat().st_size
        proc=subprocess.run([str(a.bench),'-cases',str(a.out/manifest),'-mode',mode,*extra],text=True,capture_output=True)
        after=stats(); ra=resources()
        if not proc.stdout: raise RuntimeError(proc.stderr)
        row=json.loads(proc.stdout); row.update(cache=cache,**labels)
        row['dns_before']={k:v for k,v in before.items() if k.startswith('total.')}
        row['dns_after']={k:v for k,v in after.items() if k.startswith('total.')}
        row['dns_delta']={k:after[k]-v for k,v in before.items() if k.startswith(('total.num.', 'num.query.')) or k in ('total.requestlist.overwritten','total.requestlist.exceeded')}
        row['resources_before']=rb;row['resources_after']=ra
        expected=sum(by_name[n]['queries']*count for n,count in row['case_counts'].items())
        exact=all(by_name[n]['queries'] for n in row['case_counts'])
        row['expected_queries']=expected if exact else None
        failures=[]
        if proc.returncode: failures.append(proc.stderr)
        if exact and row['dns_delta']['total.num.queries'] != expected: failures.append('DNS query count mismatch')
        if mode=='policy':
            expected_results=Counter()
            for name,count in row['case_counts'].items(): expected_results[by_name[name]['expected']]+=count
            actual_results=Counter()
            with (a.out/'spfd.log').open() as log:
                log.seek(log_offset)
                for line in log:
                    entry=json.loads(line)
                    if entry.get('msg')=='SPF evaluation': actual_results[entry['result']]+=1
            row['daemon_results']=dict(actual_results)
            if actual_results != expected_results: failures.append('daemon result distribution mismatch')
        if cache=='fault' and row['seconds'] > 4: failures.append('fault exceeded evaluation deadline allowance')
        if cache=='cold' and row['dns_delta']['total.num.cachemiss'] < 1: failures.append('cold trial had no cache miss')
        if cache=='hot' and row['dns_delta']['total.num.cachemiss'] != 0: failures.append('hot cache miss')
        if any(v for k,v in row['dns_delta'].items() if any(token in k for token in ('ratelimit','overwritten','exceeded','discard_timeout','queries_timed_out','queries_wait_limit'))): failures.append('DNS rate limiting or request loss')
        row['validation_errors']=failures
        file.write(json.dumps(row)+'\n');file.flush()
        print(mode,cache,labels,'n=',row['n'],'errors=',row['errors'],'qps=',round(row['qps']),flush=True)
        if failures: raise RuntimeError('; '.join(failures))
    try:
        launch('faults',[sys.executable,Path(__file__).with_name('faults.py')])
        launch('nsd',['nsd','-d','-c',a.out/'nsd.conf'])
        launch('unbound',['unbound','-d','-c',a.out/'unbound.conf'])
        for _ in range(100):
            if any(p.poll() is not None for p in processes): raise RuntimeError('DNS process exited; inspect logs')
            try:
                if 'v=spf1' in command('dig','@127.0.0.1','simple-pass.spfbench.test','TXT','+short','+time=1','+tries=1'): break
            except subprocess.CalledProcessError: pass
            time.sleep(.1)
        else: raise RuntimeError('DNS readiness timed out')
        launch('spfd',[a.spfd,'serve','-enforce','-max-checks','256','-max-connections','512','-timeout','3s'])
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1',10023),.1): break
            except OSError: time.sleep(.1)
        else: raise RuntimeError('spfd readiness timed out')
        with (a.out/'results.jsonl').open('w') as file:
            flush()
            trial(file,'spf','warmup',['-once'])
            trial(file,'policy','hot',['-once'])
            for c in cases:
                if c['name'].startswith('tenant-'): continue
                for repeat in range(a.cold):
                    for mode in ('spf','policy'):
                        flush();trial(file,mode,'cold',['-once','-case',c['name']],case=c['name'],repeat=repeat)
            # Warm every case after the final cold flush, outside timing.
            trial(file,'spf','warmup',['-once'])
            for repeat in range(a.repeats):
                for distribution in ('uniform','zipf'):
                    for mode in ('spf','policy'):
                        for w in workers:
                            trial(file,mode,'hot',['-workers',str(w),'-duration',f'{a.seconds}s','-distribution',distribution,'-seed',str(repeat+1)],repeat=repeat)
            if a.soak_seconds:
                trial(file,'policy','hot',['-workers',str(max(workers)),'-duration',f'{a.soak_seconds}s','-distribution','uniform'],soak=True)
            faults=json.loads((a.out/'fault-cases.json').read_text())
            by_name.update({c['name']:c for c in faults})
            for c in faults:
                for mode in ('spf','policy'):
                    flush()
                    control('flush_infra','all')
                    trial(file,mode,'fault',['-once','-case',c['name']],manifest='fault-cases.json',case=c['name'])
        resilience(a.spfd,a.out,a.out/'unbound.conf')
    finally:
        for proc in reversed(processes):
            proc.terminate()
            try: proc.wait(timeout=8)
            except subprocess.TimeoutExpired: proc.kill();proc.wait()
        for log in logs: log.close()

if __name__=='__main__': main()
