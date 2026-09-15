"""Native IPv6 loopback control for an IPv6-only VM's packaged dnsperf."""
import json, os, pathlib, subprocess, time
out=pathlib.Path('results')
out.mkdir(exist_ok=True)
(out/'dnsperf-queries.txt').write_text('simple.benchmark.test TXT\n')
def stats():
    return {k:float(v) for k,v in (l.split('=',1) for l in subprocess.check_output(['sudo','unbound-control','stats_noreset'],text=True).splitlines())}
def cpu(pid):
    s=pathlib.Path(f'/proc/{pid}/stat').read_text().split();return (int(s[13])+int(s[14]))/os.sysconf('SC_CLK_TCK')
authority=subprocess.Popen(['/home/marek/spf-benchmark-20260914/venv/bin/python','source/benchmarks/unbound/authority.py'])
time.sleep(.3)
try:
    for name in ['simple','include']+[f'chain{i}' for i in range(10)]:
        answer=subprocess.check_output(['dig','@127.0.0.1',name+'.benchmark.test','TXT','+short'],text=True)
        assert 'v=spf1' in answer
finally:
    authority.terminate();authority.wait()
pid=int(subprocess.check_output(['pgrep','-x','unbound']))
for threads in [1,2,4]:
    a=stats();uc=cpu(pid);t=time.monotonic()
    raw=subprocess.check_output(['dnsperf','-f','inet6','-s','::1','-a','::1','-d',str(out/'dnsperf-queries.txt'),'-l','15','-c','64','-T',str(threads),'-q','256'],text=True,stderr=subprocess.STDOUT)
    b=stats();delta={k:b[k]-v for k,v in a.items() if k.startswith('total.') or 'ratelimit' in k}
    (out/f'dnsperf-ipv6-{threads}.txt').write_text(raw+'\n'+json.dumps({'unbound_cpu_pct':100*(cpu(pid)-uc)/(time.monotonic()-t),'dns_delta':delta}))
    print(raw,flush=True)
    assert b['total.num.queries']>a['total.num.queries'], 'dnsperf sent no queries'
