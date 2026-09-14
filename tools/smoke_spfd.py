#!/usr/bin/env python3
"""Exercise a built spfd binary with local UDP DNS and policy clients (stdlib only)."""
import concurrent.futures
import contextlib
import json
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        offset, labels = 12, []
        while query[offset]:
            length = query[offset]
            labels.append(query[offset + 1:offset + 1 + length].decode('ascii'))
            offset += length + 1
        offset += 1
        kind, _ = struct.unpack('!HH', query[offset:offset + 4])
        question = query[12:offset + 4]
        name = '.'.join(labels)
        answer = b''
        if kind == 16 and name in ('pass.example.test', 'fail.example.test'):
            policy = b'v=spf1 ip4:192.0.2.0/24 -all' if name.startswith('pass.') else b'v=spf1 -all'
            data = bytes([len(policy)]) + policy
            answer = b'\xc0\x0c' + struct.pack('!HHIH', 16, 1, 60, len(data)) + data
        header = struct.pack('!HHHHHH', struct.unpack('!H', query[:2])[0], 0x8180, 1, bool(answer), 0, 0)
        sock.sendto(header + question + answer, self.client_address)


@contextlib.contextmanager
def daemon(binary, dns, enforce):
    with tempfile.TemporaryDirectory() as tmp, open(Path(tmp) / 'daemon.log', 'w+') as log:
        args = [binary, 'serve', '-dns', dns, '-listen', '127.0.0.1:0', '-shutdown-timeout', '100ms']
        if enforce:
            args.append('-enforce')
        process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while True:
                # A separate descriptor avoids moving the daemon's write offset.
                with open(log.name) as reader:
                    line = reader.readline()
                if line.endswith('\n'):
                    startup = json.loads(line)
                    assert startup['msg'] == 'policy service listening', startup
                    break
                assert process.poll() is None, 'daemon exited before listening'
                assert time.monotonic() < deadline, 'daemon startup timed out'
                time.sleep(0.01)
            host, port = startup['address'].rsplit(':', 1)
            yield host, int(port)
        finally:
            process.terminate()
            try:
                assert process.wait(timeout=5) == 0, 'unclean shutdown'
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise
            entries = [json.loads(line) for line in Path(log.name).read_text().splitlines()]
            assert entries[0]['msg'] == 'policy service listening', 'startup log overwritten'
            assert entries[-1]['msg'] == 'policy service stopped', 'missing shutdown log'


def exchange(stream, sender):
    request = ('request=smtpd_access_policy\nprotocol_state=RCPT\n'
               'client_address=192.0.2.1\nhelo_name=pass.example.test\n'
               f'sender={sender}\n\n').encode()
    stream.write(request)
    stream.flush()
    action = stream.readline().decode().strip()
    assert stream.readline() == b'\n'
    return action


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with socketserver.UDPServer(('127.0.0.1', 0), DNS) as dns:
        thread = threading.Thread(target=dns.serve_forever, daemon=True)
        thread.start()
        address = f'127.0.0.1:{dns.server_address[1]}'
        try:
            for domain, expected in [('pass.example.test', 'pass'), ('fail.example.test', 'fail'), ('none.example.test', 'none')]:
                result = json.loads(subprocess.check_output([binary, 'check', '-dns', address, '-ip', '192.0.2.1', '-sender', 'sender@' + domain], timeout=5))
                assert result['result'] == expected, result
            for enforce in (False, True):
                with daemon(binary, address, enforce) as endpoint:
                    def client(_):
                        with socket.create_connection(endpoint, timeout=5) as conn, conn.makefile('rwb') as stream:
                            assert exchange(stream, 'sender@pass.example.test') == 'action=DUNNO'
                            expected = 'action=550 5.7.23 SPF validation failed' if enforce else 'action=DUNNO'
                            assert exchange(stream, 'sender@fail.example.test') == expected
                            assert exchange(stream, '') == 'action=DUNNO'
                    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                        list(pool.map(client, range(32)))
        finally:
            dns.shutdown()
            thread.join()
    print('PASS: JSON checks, monitor/enforce policy, null senders, persistent connections, concurrent clients and SIGTERM shutdown')


if __name__ == '__main__':
    main()
