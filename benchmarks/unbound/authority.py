import socket
import dns.message
import dns.rrset

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 15353))
while True:
    data, peer = s.recvfrom(4096)
    q = dns.message.from_wire(data)
    r = dns.message.make_response(q)
    name = str(q.question[0].name)
    policy = 'v=spf1 ip4:192.0.2.0/24 -all'
    if name.startswith('include.'):
        policy = 'v=spf1 include:simple.benchmark.test -all'
    elif name.startswith('chain'):
        i = int(name.split('.')[0][5:])
        if i < 9:
            policy = f'v=spf1 include:chain{i+1}.benchmark.test -all'
    r.answer.append(dns.rrset.from_text(name, 86400, 'IN', 'TXT', '"' + policy + '"'))
    s.sendto(r.to_wire(), peer)
