#!/usr/bin/env python3
"""Generate deterministic zones, manifest and standalone DNS configurations."""
import argparse
import ipaddress
import json
from pathlib import Path


def generate(out, replicas):
    out.mkdir(parents=True, exist_ok=True)
    zone = 'spfbench.test'
    records = []
    cases = []
    def rr(name, kind, value):
        records.append(f'{name} IN {kind} {value}')
    def case(name, policy, expected='pass', ip='192.0.2.1', queries=0):
        if policy is not None:
            rr(name, 'TXT', json.dumps(policy))
        cases.append(dict(name=name, domain=f'{name}.{zone}', ip=ip,
                          expected=expected, queries=queries))
    case('simple-pass', 'v=spf1 ip4:192.0.2.0/24 -all', queries=1)
    case('simple-fail', 'v=spf1 ip4:198.51.100.0/24 -all', 'fail', queries=1)
    case('softfail', 'v=spf1 ~all', 'softfail', queries=1)
    case('neutral', 'v=spf1 ?all', 'neutral', queries=1)
    case('missing', None, 'none', queries=1)
    case('nodata', None, 'none', queries=1)
    rr('nodata', 'A', '192.0.2.2')
    case('invalid', 'v=spf1 invalid -all', 'permerror', queries=1)
    case('duplicate', 'v=spf1 +all', 'permerror', queries=1)
    rr('duplicate', 'TXT', '"v=spf1 -all"')
    case('ipv6', 'v=spf1 ip6:2001:db8::/32 -all', ip='2001:db8::1', queries=1)
    case('include-one', 'v=spf1 include:simple-pass.spfbench.test -all', queries=2)
    case('redirect', 'v=spf1 redirect=simple-pass.spfbench.test', queries=2)
    case('include-missing', 'v=spf1 include:missing.spfbench.test -all', 'permerror', queries=2)
    for count in (9, 10, 11):
        name = f'include-depth-{count}'
        case(name, f'v=spf1 include:{name}-1.{zone} -all', 'pass' if count <= 10 else 'permerror', queries=min(count+1, 11))
        for i in range(1, count+1):
            rr(f'{name}-{i}', 'TXT', json.dumps('v=spf1 ip4:192.0.2.1 -all' if i == count else f'v=spf1 include:{name}-{i+1}.{zone} -all'))
    case('void-limit', 'v=spf1 exists:missing1.spfbench.test exists:missing2.spfbench.test exists:missing3.spfbench.test -all', 'permerror', queries=4)
    for suffix, ip in (('v4','192.0.2.1'), ('v6','2001:db8::1')):
        case('a-'+suffix, 'v=spf1 a:target.spfbench.test -all', ip=ip, queries=2)
        case('ptr-'+suffix, 'v=spf1 ptr:spfbench.test -all', ip=ip, queries=3)
        case('macro-p-'+suffix, 'v=spf1 exists:%{p} -all', ip=ip, queries=4)
    rr('target','A','192.0.2.1'); rr('target','AAAA','2001:db8::1')
    rr('ptr1','A','192.0.2.1'); rr('ptr1','AAAA','2001:db8::1')
    case('mx-five-last-match', 'v=spf1 mx -all', queries=7)
    for i in range(1,6):
        rr('mx-five-last-match','MX',f'{i*10} mx{i}.{zone}.')
        rr(f'mx{i}','A', '192.0.2.1' if i == 5 else f'198.51.100.{i}')
    case('cname', None, queries=1)
    rr('cname','CNAME',f'simple-pass.{zone}.')
    case('split-txt', None, queries=1)
    rr('split-txt','TXT','"v=spf1 ip4:" "192.0.2.1 -all"')
    case('large-txt', 'v=spf1 ip4:192.0.2.1 -all', queries=2)
    for i in range(20): rr('large-txt', 'TXT', json.dumps(f'non-spf-{i}-' + 'x'*220))
    case('complex', 'v=spf1 ip4:198.51.100.0/24 a:nomatch.spfbench.test mx:mx-five-last-match.spfbench.test include:simple-pass.spfbench.test ~all', queries=8)
    rr('nomatch','A','198.51.100.2')
    case('void-two', 'v=spf1 exists:missing1.spfbench.test exists:missing2.spfbench.test -all', 'fail', queries=3)
    case('include-cycle', 'v=spf1 include:include-cycle.spfbench.test -all', 'permerror', queries=11)
    case('redirect-missing', 'v=spf1 redirect=missing.spfbench.test', 'permerror', queries=2)
    # exp is a modifier, not a mechanism.
    case('fail-exp', 'v=spf1 -all exp=explanation-text.spfbench.test', 'fail', queries=2)
    rr('explanation-text', 'TXT', '"Denied %{i} for %{d}"')
    case('unknown-modifier', 'v=spf1 extension=ignored ip4:192.0.2.1 -all', queries=1)
    case('mx-eleven', 'v=spf1 mx -all', 'permerror', queries=2)
    for i in range(11): rr('mx-eleven', 'MX', f'{i} mx1.{zone}.')
    case('long-policy', None, queries=2)
    policy = 'v=spf1 ' + ' '.join(f'ip4:198.51.100.{i}' for i in range(100)) + ' ip4:192.0.2.1 -all'
    rr('long-policy', 'TXT', ' '.join(json.dumps(policy[i:i+200]) for i in range(0, len(policy), 200)))
    # Replicate the complete fixture distribution across distinct initial owners.
    # Absolute include/redirect dependencies remain shared, as at hosted providers.
    templates = list(cases)
    template_records = list(records)
    for i in range(replicas):
        template = templates[i % len(templates)]
        name = f'tenant-{i:05}'
        cases.append(dict(template, name=name, domain=f'{name}.{zone}'))
        for record in template_records:
            owner, rest = record.split(' ', 1)
            if owner == template['name']: records.append(name + ' ' + rest)
    zones = {zone: records}
    for ip, reverse_zone in [('192.0.2.1','2.0.192.in-addr.arpa'), ('2001:db8::1','8.b.d.0.1.0.0.2.ip6.arpa')]:
        owner = ipaddress.ip_address(ip).reverse_pointer.removesuffix('.'+reverse_zone)
        zones[reverse_zone] = [f'{owner} IN PTR ptr1.{zone}.']
    for name, rows in zones.items():
        (out / (name+'.zone')).write_text(f'$ORIGIN {name}.\n$TTL 86400\n@ IN SOA ns.{zone}. hostmaster.{zone}. (1 3600 600 604800 86400)\n@ IN NS ns.{zone}.\n' + ('ns IN A 127.0.0.1\n' if name == zone else '') + '\n'.join(rows)+'\n')
    (out/'cases.json').write_text(json.dumps(cases, indent=2)+'\n')
    # Dedicated processes: never replace distro service configuration.
    templates_dir = Path(__file__).resolve().parent
    nsd = (templates_dir/'nsd.conf.in').read_text().replace('@RUN_DIR@', str(out))
    unbound = (templates_dir/'unbound.conf.in').read_text().replace('@RUN_DIR@', str(out))
    for name in zones:
        nsd += f'zone:\n    name: "{name}"\n    zonefile: "{name}.zone"\n'
        unbound += f'server:\n    local-zone: "{name}." transparent\n    domain-insecure: "{name}."\nstub-zone:\n    name: "{name}."\n    stub-addr: 127.0.0.1@15353\n    stub-first: no\n'
    unbound += 'server:\n    local-zone: "fault.spfbench.test." transparent\n    domain-insecure: "fault.spfbench.test."\nstub-zone:\n    name: "fault.spfbench.test."\n    stub-addr: 127.0.0.1@15354\n    stub-first: no\n'
    faults = [dict(name=name, domain=name+'.fault.spfbench.test', ip='192.0.2.1', expected=expected, queries=0)
              for name,expected in [('servfail','temperror'),('drop','temperror'),('slow','pass')]]
    (out/'fault-cases.json').write_text(json.dumps(faults,indent=2)+'\n')
    (out/'nsd.conf').write_text(nsd)
    (out/'unbound.conf').write_text(unbound)

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--replicas', type=int, default=1000)
    a = p.parse_args()
    if not 0 <= a.replicas <= 100000: p.error('replicas must be 0..100000')
    generate(a.out.resolve(), a.replicas)
