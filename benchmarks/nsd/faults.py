#!/usr/bin/env python3
"""Separate loopback fault authority. Deliberately never used for NSD timings."""
import socketserver
import struct
import threading
import time


class Authority(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        try:
            offset, labels = 12, []
            while query[offset]:
                length = query[offset]
                if length > 63: return
                labels.append(query[offset+1:offset+1+length].decode('ascii'))
                offset += length+1
            offset += 1
            kind, _ = struct.unpack('!HH', query[offset:offset+4])
            question = query[12:offset+4]
            name = '.'.join(labels)
        except (IndexError, UnicodeError, struct.error):
            return
        self.server.seen.set()
        if name.startswith('drop.'): return
        answer = b''
        flags = 0x8402  # authoritative SERVFAIL
        if name.startswith('slow.'):
            time.sleep(.1)
            flags = 0x8400
            if kind == 16:
                policy = b'v=spf1 ip4:192.0.2.1 -all'
                data = bytes([len(policy)]) + policy
                answer = b'\xc0\x0c'+struct.pack('!HHIH',16,1,0,len(data))+data
        header = struct.pack('!HHHHHH',struct.unpack('!H',query[:2])[0],flags,1,bool(answer),0,0)
        sock.sendto(header+question+answer,self.client_address)


class FaultServer(socketserver.ThreadingUDPServer):
    daemon_threads = True
    def __init__(self, address=('127.0.0.1',15354)):
        self.seen = threading.Event()
        super().__init__(address, Authority)


if __name__ == '__main__':
    with FaultServer() as server:
        server.serve_forever()
