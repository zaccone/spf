#!/usr/bin/env python3
"""Bounded overload, slow-client, recovery and shutdown checks through Unbound."""
import argparse
import contextlib
import json
from pathlib import Path
import socket
import subprocess
import time

WIRE = (b'request=smtpd_access_policy\nprotocol_state=RCPT\nclient_address=192.0.2.1\n'
        b'sender=sender@drop.fault.spfbench.test\nhelo_name=mail.spfbench.test\n\n')
UNAVAILABLE = b'action=451 4.3.0 SPF policy service unavailable\n\n'
TEMPERROR = b'action=451 4.7.24 SPF evaluation temporarily unavailable\n\n'


def require(condition, message):
    if not condition: raise RuntimeError(message)


def response(conn):
    data = b''
    while not data.endswith(b'\n\n'):
        part = conn.recv(4096)
        if not part: break
        data += part
        require(len(data) <= 4096, 'oversized policy reply')
    return data


@contextlib.contextmanager
def daemon(binary, out, name, connections=128):
    path = out/(name+'.log')
    with path.open('w') as log:
        proc = subprocess.Popen([str(binary),'serve','-enforce','-listen','127.0.0.1:0',
                                 '-dns','127.0.0.1:53','-max-checks','2',
                                 '-max-connections',str(connections),'-timeout','3s',
                                 '-io-timeout','500ms','-shutdown-timeout','100ms'],stderr=log)
        try:
            for _ in range(200):
                lines = path.read_text().splitlines()
                if lines:
                    entry=json.loads(lines[0])
                    require(entry.get('msg')=='policy service listening',str(entry))
                    host, port = entry['address'].rsplit(':',1)
                    yield proc,(host,int(port))
                    break
                require(proc.poll() is None,'daemon startup failed')
                time.sleep(.01)
            else: raise RuntimeError('daemon startup timeout')
        finally:
            if proc.poll() is None: proc.terminate()
            try: code=proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill();proc.wait();raise
            require(code==0, f'daemon exit {code}')


def run(binary, out, config):
    def control(*args):
        return subprocess.check_output(['unbound-control','-c',str(config),*args],text=True)
    def flush():
        control('flush_zone','fault.spfbench.test.');control('flush_infra','all')
    def queries():
        return float(dict(line.split('=',1) for line in control('stats_noreset').splitlines())['total.num.queries'])
    def connect(endpoint): return socket.create_connection(endpoint,timeout=4)
    def await_queries(before, count):
        deadline=time.monotonic()+1
        while queries()-before < count:
            require(time.monotonic()<deadline,'active DNS requests not observed')
            time.sleep(.005)
    results={}
    with daemon(binary,out,'resilience-overload') as (_,endpoint):
        flush();before=queries()
        with connect(endpoint) as first, connect(endpoint) as second:
            first.sendall(WIRE);second.sendall(WIRE);await_queries(before,2)
            start=time.monotonic()
            for _ in range(16):
                with connect(endpoint) as extra:
                    extra.sendall(WIRE)
                    require(response(extra)==UNAVAILABLE,'capacity exhaustion did not defer')
            require(time.monotonic()-start<1,'overload rejection was not prompt')
            require(response(first)==TEMPERROR,'first dropped-DNS check did not defer')
            require(response(second)==TEMPERROR,'second dropped-DNS check did not defer')
        with connect(endpoint) as recovery:
            recovery.sendall(WIRE.replace(b'drop.fault.spfbench.test',b'simple-pass.spfbench.test'))
            require(response(recovery)==b'action=DUNNO\n\n','evaluation slots failed to recover')
        with connect(endpoint) as slow:
            slow.sendall(b'request=smtpd_access_policy\n')
            started=time.monotonic()
            require(response(slow)==UNAVAILABLE,'partial request not bounded')
            require(time.monotonic()-started<1.5,'partial request deadline exceeded')
        with connect(endpoint) as malformed:
            malformed.sendall(b'x='+b'x'*5000+b'\n\n')
            require(response(malformed)==UNAVAILABLE,'oversized line not rejected')
        results.update(overload_rejections=16,recovery=True,partial_request_deadline=True,oversized_line=True)
    with daemon(binary,out,'resilience-connections',connections=4) as (_,endpoint):
        with contextlib.ExitStack() as stack:
            for _ in range(4): stack.enter_context(connect(endpoint))
            with connect(endpoint) as excess:
                excess.settimeout(.3)
                try: closed=excess.recv(1)==b''
                except ConnectionResetError: closed=True
                require(closed,'excess connection not closed')
        results['connection_limit']=True
    with daemon(binary,out,'resilience-shutdown') as (proc,endpoint):
        flush();before=queries()
        with connect(endpoint) as active:
            active.sendall(WIRE);await_queries(before,1)
            started=time.monotonic();proc.terminate()
            require(proc.wait(timeout=2)==0,'shutdown failed')
            results['active_dns_shutdown_seconds']=time.monotonic()-started
    (out/'resilience.json').write_text(json.dumps(results,indent=2)+'\n')
    print('PASS resilience:',json.dumps(results),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--spfd',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--unbound-config',type=Path,required=True)
    a=p.parse_args();run(a.spfd.resolve(),a.out.resolve(),a.unbound_config.resolve())
