"""Run on VM from /home/marek/spf-unbound-20260915; writes measurement artifacts."""
import json, os, pathlib, subprocess, time, resource

root = pathlib.Path.cwd()
out = root / 'results'
out.mkdir(exist_ok=True)
def stats():
    raw = subprocess.check_output(['sudo','unbound-control','stats_noreset'],text=True)
    return {k:float(v) for k,v in (l.split('=',1) for l in raw.splitlines())}
def cpu(pid):
    s=pathlib.Path(f'/proc/{pid}/stat').read_text().split()
    return (int(s[13])+int(s[14]))/os.sysconf('SC_CLK_TCK')
def warm():
    authority=subprocess.Popen(['/home/marek/spf-benchmark-20260914/venv/bin/python','source/benchmarks/unbound/authority.py'])
    time.sleep(.3)
    try:
        for name in ['simple','include']+[f'chain{i}' for i in range(10)]:
            answer=subprocess.check_output(['dig','@127.0.0.1',name+'.benchmark.test','TXT','+short'],text=True)
            assert 'v=spf1' in answer, answer
    finally:
        authority.terminate();authority.wait()
warm()
unbound=int(subprocess.check_output(['pgrep','-x','unbound']))
daemon=subprocess.Popen(['./spfd','serve','-max-checks','4096','-max-connections','4096'],stderr=subprocess.DEVNULL)
time.sleep(.3)
try:
    with (out/'sweep.jsonl').open('w') as f:
        cases=[]
        for mode in ['memory','dns','reuse','spf','policy']:
            scenarios=['simple','include','chain0'] if mode in ['memory','spf','policy'] else ['simple']
            for scenario in scenarios:
                for w in [1,4,16,64,128]:
                    cases.append((mode,scenario,w,4))
        for p in [1,2]:
            for mode in ['memory','spf']:
                for w in [1,16,64]:cases.append((mode,'simple',w,p))
        for mode,scenario,w,p in cases:
            a=stats();uc=cpu(unbound);dc=cpu(daemon.pid)
            usage=resource.getrusage(resource.RUSAGE_CHILDREN)
            raw=subprocess.check_output(['./bench','-mode',mode,'-scenario',scenario,'-workers',str(w),'-duration','3s'],env=dict(os.environ,GOMAXPROCS=str(p)),text=True)
            after=resource.getrusage(resource.RUSAGE_CHILDREN)
            r=json.loads(raw);elapsed=r['seconds']
            r['client_cpu_pct']=100*((after.ru_utime+after.ru_stime)-(usage.ru_utime+usage.ru_stime))/elapsed
            r['unbound_cpu_pct']=100*(cpu(unbound)-uc)/elapsed
            r['daemon_cpu_pct']=100*(cpu(daemon.pid)-dc)/elapsed
            b=stats();r['dns_delta']={k:b[k]-v for k,v in a.items() if k.startswith('total.') or 'ratelimit' in k}
            f.write(json.dumps(r)+'\n');f.flush();print(raw.strip(),flush=True)
finally:
    daemon.terminate();daemon.wait()
