#!/usr/bin/env python3
"""Exercise the deployment's Unbound profile and spfd without Internet DNS."""
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from smoke_spfd import daemon, exchange


def main():
    binary = str(Path(sys.argv[1]).resolve())
    unbound = shutil.which('unbound')
    checkconf = shutil.which('unbound-checkconf')
    if not unbound or not checkconf:
        raise SystemExit('Install unbound and unbound-checkconf to run this test')
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix='spf-unbound-') as tmp:
        work = Path(tmp)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        config = work / 'unbound.conf'
        # Keep the deployed DNS/cache/validation settings. Override only runtime
        # paths, privileges, and port for an isolated unprivileged test process.
        # Embed the profiles so AppArmor-confined Unbound only needs to read
        # the temporary directory, not files in the repository checkout.
        profile = (root / 'deploy/unbound/spfd.conf').read_text()
        fixture = (root / 'deploy/unbound/smoke-test.conf.example').read_text()
        config.write_text(profile + '\n' + fixture + f'''
server:
    port: {port}
    username: ""
    chroot: ""
    directory: "{work}"
    pidfile: ""
    use-syslog: no
    logfile: ""
    local-zone: "example.test." static
    local-data: 'pass.example.test. 60 IN TXT "v=spf1 ip4:192.0.2.0/24 -all"'
    local-data: 'fail.example.test. 60 IN TXT "v=spf1 -all"'
remote-control:
    control-enable: no
''')
        subprocess.run([checkconf, str(config)], check=True)
        with (work / 'unbound.log').open('w+') as log:
            process = subprocess.Popen([unbound, '-d', '-c', str(config)], stderr=log, stdout=log)
            try:
                deadline = time.monotonic() + 10
                while True:
                    if process.poll() is not None:
                        raise RuntimeError((work / 'unbound.log').read_text())
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError('Unbound startup timed out')
                        time.sleep(0.05)
                address = f'127.0.0.1:{port}'
                for domain, expected in [('pass.example.test', 'pass'),
                                         ('fail.example.test', 'fail'),
                                         ('none.example.test', 'none'),
                                         ('pass.spf-deploy.test', 'pass'),
                                         ('fail.spf-deploy.test', 'fail')]:
                    result = json.loads(subprocess.check_output([
                        binary, 'check', '-dns', address, '-ip', '192.0.2.1',
                        '-sender', 'sender@' + domain], timeout=5))
                    assert result['result'] == expected, result
                for enforce in (False, True):
                    with daemon(binary, address, enforce) as endpoint:
                        with socket.create_connection(endpoint, timeout=5) as conn, conn.makefile('rwb') as stream:
                            assert exchange(stream, 'sender@pass.example.test') == 'action=DUNNO'
                            expected = 'action=550 5.7.23 SPF validation failed' if enforce else 'action=DUNNO'
                            assert exchange(stream, 'sender@fail.example.test') == expected
                            assert exchange(stream, '') == 'action=DUNNO'
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise
    print('PASS: deployment Unbound profile, SPF pass/fail/none, monitor/enforce and null sender')


if __name__ == '__main__':
    main()
