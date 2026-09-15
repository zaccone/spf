"""Repeat selected sweep peaks; capture CPU profiles and independent DNS capacity."""
import json, os, pathlib, subprocess, time, resource
root=pathlib.Path.cwd();out=root/'results'
def stats():
    return {k:float(v) for k,v in (l.split('=',1) for l in subprocess.check_output(['sudo','unbound-control','stats_noreset'],text=True).splitlines())}
def cpu(pid):
    s=pathlib.Path(f'/proc/{pid}/stat').read_text().split();return (int(s[13])+int(s[14]))/os.sysconf('SC_CLK_TCK')
rows=[json.loads(l) for l in (out/'sweep.jsonl').read_text().splitlines()]
groups={}
for r in rows:
    if r['gomaxprocs']==4:
        key=(r['mode'],r['scenario'])
        if key not in groups or r['qps']>groups[key]['qps']:groups[key]=r
unbound=int(subprocess.check_output(['pgrep','-x','unbound']))
selected=list(groups.items())
for mode in ['spf','policy']:
    if groups[(mode,'simple')]['workers']!=16:
        selected.append(((mode,'simple'),{'workers':16}))
daemon=subprocess.Popen(['./spfd','serve','-max-checks','4096','-max-connections','4096'],stderr=subprocess.DEVNULL)
time.sleep(.3)
try:
    with (out/'confirm.jsonl').open('w') as f:
        for repeat in range(3):
            for (mode,scenario),best in selected:
                if mode=='memory' and scenario!='simple':continue
                a=stats();uc=cpu(unbound);dc=cpu(daemon.pid);usage=resource.getrusage(resource.RUSAGE_CHILDREN)
                raw=subprocess.check_output(['./bench','-mode',mode,'-scenario',scenario,'-workers',str(best['workers']),'-duration','10s'],env=dict(os.environ,GOMAXPROCS='4'),text=True)
                after=resource.getrusage(resource.RUSAGE_CHILDREN);r=json.loads(raw);r['repeat']=repeat+1;t=r['seconds']
                r['client_cpu_pct']=100*((after.ru_utime+after.ru_stime)-(usage.ru_utime+usage.ru_stime))/t
                r['unbound_cpu_pct']=100*(cpu(unbound)-uc)/t;r['daemon_cpu_pct']=100*(cpu(daemon.pid)-dc)/t
                b=stats();r['dns_delta']={k:b[k]-v for k,v in a.items() if k.startswith('total.') or 'ratelimit' in k}
                f.write(json.dumps(r)+'\n');f.flush();print(raw.strip(),flush=True)
    for mode in ['spf','dns','reuse','memory']:
        best=groups[(mode,'simple')]
        subprocess.run(['./bench','-mode',mode,'-workers',str(best['workers']),'-duration','15s','-profile',str(out/(mode+'.pprof'))],check=True)
        with (out/(mode+'-profile.txt')).open('w') as f:
            subprocess.run(['/home/marek/spf-benchmark-20260914/go/bin/go','tool','pprof','-top','-nodecount=40','./bench',str(out/(mode+'.pprof'))],stdout=f,check=True)
    with (out/'daemon-perf-status.txt').open('w') as status:
        perf=subprocess.Popen(['sudo','perf','record','-F','99','-g','-p',str(daemon.pid),'-o',str(out/'daemon.perf'),'--','sleep','16'],stdout=status,stderr=status)
        time.sleep(.3)
        subprocess.run(['./bench','-mode','policy','-workers','16','-duration','15s'],check=True)
        code=perf.wait()
        if code==0:
            with (out/'daemon-perf.txt').open('w') as f:
                subprocess.run(['sudo','perf','report','--stdio','--no-children','--percent-limit','1','-i',str(out/'daemon.perf')],stdout=f,stderr=status)
    (out/'dnsperf-queries.txt').write_text('simple.benchmark.test TXT\n')
    subprocess.run(['python3','source/benchmarks/unbound/dnsperf_ipv6.py'],check=True)
finally:
    daemon.terminate();daemon.wait()
