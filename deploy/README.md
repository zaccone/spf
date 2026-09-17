# Deploy Postfix, spfd, and Unbound

This recipe adds SPF checking to an existing inbound Postfix mail server on
Debian/Ubuntu with systemd. It provides a local validating recursive DNS cache
and a bounded SPF policy service. Start in monitor mode, verify mail flow, then
choose whether to reject SPF failures. Postfix still handles SMTP, relay control,
TLS, authentication, queues, and delivery; SPF alone does not provide DKIM/DMARC
or a complete spam filter.

```text
Internet SMTP client
        |
        v
Postfix (RCPT restrictions)
        | TCP 127.0.0.1:10023, Postfix policy protocol
        v
spfd (monitor initially; optional enforcement)
        | UDP/TCP 127.0.0.1:5335
        v
Unbound (DNSSEC validation + shared cache)
        | outbound UDP/TCP 53
        v
DNS root, TLD, and authoritative servers
```

Both local listeners stay on loopback. Port 5335 avoids the host's existing
port-53 stub resolver; this setup requires no change to `/etc/resolv.conf`. Unbound uses direct
recursion, so the host needs outbound UDP **and TCP** port 53 and a correct clock.
Use this profile for a new, dedicated Unbound installation. If Unbound already
serves other applications, merge deliberately or use that resolver's endpoint
in `SPFD_DNS`; included `interface` entries accumulate and `port` changes affect
the instance. Do not install this fragment blindly over an existing DNS service.

The configuration files are:

| Repository file | Install path |
| --- | --- |
| [Unbound profile](unbound/spfd.conf) | `/etc/unbound/unbound.conf.d/spfd.conf` |
| [spfd settings](spfd.env) | `/etc/default/spfd` |
| [systemd unit](spfd.service) | `/etc/systemd/system/spfd.service` |
| [Postfix fragment](postfix/main.cf.example) | Merge into `/etc/postfix/main.cf` |

The Unbound profile replaces the repository's old `_etc/unbound/unbound.conf`
example. Its dedicated port is 5335; CLI defaults remain port 53, so use the
explicit `-dns` address shown here for manual commands.

## 1. Install and build

On the mail host, install the distribution-maintained packages. This assumes
Postfix is already configured for your domains and receiving mail correctly:

```sh
sudo apt-get update
sudo apt-get install unbound dnsutils python3
```

Build from a reviewed checkout of this repository using Go 1.27 or later:

```sh
CGO_ENABLED=0 go build -trimpath -o /tmp/spfd ./cmd/spfd
sudo install -m 0755 /tmp/spfd /usr/local/bin/spfd
```

Build on Linux for the native architecture, or use the [cross-build commands](../cmd/spfd/README.md#build-and-basic-usage).
Record the installed source revision (`git rev-parse HEAD`) with your deployment.
Back up existing configuration and the previous binary before upgrades.
All following repository paths are relative to the checkout root.

## 2. Configure and verify Unbound

```sh
sudo install -m 0644 deploy/unbound/spfd.conf /etc/unbound/unbound.conf.d/spfd.conf
sudo unbound-checkconf /etc/unbound/unbound.conf
sudo unbound-checkconf -o auto-trust-anchor-file /etc/unbound/unbound.conf
```

The package's main config must include `/etc/unbound/unbound.conf.d/*.conf`.
Keep its DNSSEC trust-anchor fragment, normally `root-auto-trust-anchor-file.conf`,
and its writable `/var/lib/unbound/root.key`. The last command must print the
configured anchor path; verify that it exists and is readable by Unbound.
Do not add a duplicate trust-anchor directive or disable validation to bypass
startup failures. Package startup manages the anchor; if it is missing, repair
the package setup before continuing. See the [Unbound configuration reference](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)
for trust-anchor ownership and include behavior.

```sh
sudo systemctl enable unbound
sudo systemctl restart unbound
sudo systemctl --no-pager status unbound
sudo ss -luntp | grep ':5335'
dig @127.0.0.1 -p 5335 . SOA +dnssec
dig @127.0.0.1 -p 5335 . SOA +dnssec +tcp
```

Expect only `127.0.0.1:5335` listeners, successful UDP and TCP answers, and `ad`
in the flags for the signed root answer. Check the clock, network, and anchor
if validation fails. The distribution's trusted resolver validates DNSSEC;
`spfd` itself does not validate signatures. DNSSEC-bogus answers become DNS errors,
not SPF passes. Unsigned domains can still be evaluated normally.

The profile uses 32 MiB message and 64 MiB RRset caches, plus Unbound's other
memory overhead. These are starting values, not a process memory cap. Prefetch
refreshes popular entries; expired authorization data is not served. Local test
answers below verify wiring but do not prove Internet recursion or DNSSEC.

## 3. Configure and start spfd

```sh
sudo install -m 0644 deploy/spfd.env /etc/default/spfd
sudoedit /etc/default/spfd
sudo install -m 0644 deploy/spfd.service /etc/systemd/system/spfd.service
sudo systemd-analyze verify /etc/systemd/system/spfd.service
sudo systemctl daemon-reload
sudo systemctl enable --now spfd
sudo systemctl --no-pager status spfd
sudo journalctl -u spfd -n 20 --no-pager
```

Set `SPFD_RECEIVER` to the receiving MTA's fully qualified hostname (check
`postconf -h myhostname`). Keep `SPFD_ENFORCE=` empty initially. This is a systemd
environment file, not shell syntax; do not use `export` or command substitution.
The unit runs as a dynamic unprivileged user. After changing the environment
file, run `sudo systemctl restart spfd`; `daemon-reload` is needed only for unit
changes. Existing users of the older sample unit must install the environment
file before replacing/restarting the unit.

Unbound starts before `spfd`, but startup ordering is not a DNS readiness check.
The dependency intentionally does not stop `spfd` when Unbound restarts; new
checks recover as DNS becomes available. Confirm both services after a reboot.

## 4. Run deterministic acceptance checks

Temporarily install the reserved `.test` fixture:

```sh
sudo install -m 0644 deploy/unbound/smoke-test.conf.example /etc/unbound/unbound.conf.d/spfd-smoke-test.conf
sudo unbound-checkconf
sudo systemctl reload unbound
/usr/local/bin/spfd check -dns 127.0.0.1:5335 -ip 192.0.2.1 -sender sender@pass.spf-deploy.test
/usr/local/bin/spfd check -dns 127.0.0.1:5335 -ip 192.0.2.1 -sender sender@fail.spf-deploy.test
```

Expect JSON results `pass` and `fail`. The `check` command exits successfully for
both: its exit status reports command execution, not SPF acceptance.
Probe the running daemon with a real policy-protocol request:

```sh
python3 - <<'PY'
import socket
for domain in ('pass.spf-deploy.test', 'fail.spf-deploy.test'):
    request = ('request=smtpd_access_policy\nprotocol_state=RCPT\n'
               'client_address=192.0.2.1\nhelo_name=pass.spf-deploy.test\n'
               f'sender=sender@{domain}\nrecipient=postmaster@example.com\n\n')
    with socket.create_connection(('127.0.0.1', 10023), timeout=35) as conn:
        conn.sendall(request.encode())
        with conn.makefile('rb') as response:
            print(domain, response.readline().decode().strip())
            assert response.readline() == b'\n'
PY
```

Monitor mode returns `action=DUNNO` for both; the journal must show distinct
`pass` and `fail` results. After enabling enforcement, repeat: pass stays `DUNNO`
and fail becomes `550 5.7.23`. Once verification is complete:

```sh
sudo rm /etc/unbound/unbound.conf.d/spfd-smoke-test.conf
sudo unbound-checkconf
sudo systemctl reload unbound
```

## 5. Connect Postfix

Back up `/etc/postfix/main.cf`. Merge [the Postfix fragment](postfix/main.cf.example)
into the existing recipient restrictions **after relay protection**, preserving
site restrictions. Keep `smtpd_relay_restrictions`, `mynetworks`, TLS, SASL, and
recipient validation intact. Do not replace the whole file or expand trusted
networks. A preceding unconditional permit can skip SPF; review restriction
ordering and any `master.cf` service overrides.

The fragment uses a 30-second policy timeout, above `spfd`'s 20-second evaluation
deadline, and a temporary failure when the service is unavailable. The timeout
and default-action settings are global to Postfix policy services; reconcile
them with any other policy daemons. Follow the [Postfix policy delegation guide](https://www.postfix.org/SMTPD_POLICY_README.html)
and [relay/access control guide](https://www.postfix.org/SMTPD_ACCESS_README.html).

```sh
sudo postfix check
sudo postconf smtpd_recipient_restrictions smtpd_relay_restrictions smtpd_policy_service_timeout smtpd_policy_service_default_action
sudo systemctl reload postfix
```

Send a test message from a host outside `mynetworks`, unauthenticated, to a valid
local recipient. Confirm an SPF result in `journalctl -u spfd` and normal delivery
in the mail logs. Also verify that an external sender cannot relay to a nonlocal
domain. A loopback or authenticated SMTP test normally bypasses the policy check;
the direct probe above does not test Postfix restriction ordering.

## 6. Choose enforcement and understand failures

Review monitor logs over representative mail traffic, including forwarded mail.
Forwarding often breaks SPF; account for your forwarding arrangements before
rejecting failures. To enforce, set `SPFD_ENFORCE=-enforce` in `/etc/default/spfd`,
restart `spfd`, and repeat the acceptance tests. The complete behavior is:

| Condition | Monitor | Enforce |
| --- | --- | --- |
| SPF pass, none, neutral, softfail, permerror | DUNNO | DUNNO |
| SPF fail | DUNNO | 550 5.7.23 |
| SPF temperror, including DNS timeout/SERVFAIL | DUNNO | 451 4.7.24 |
| Malformed request or exhausted check slots | 451 4.3.0 | 451 4.3.0 |
| Service unavailable/excess connection closed | Postfix temporary failure | Postfix temporary failure |

Monitor mode is not a promise of failure-free delivery: an unavailable policy
service still defers mail. SPF pass never bypasses later Postfix restrictions.
Authenticated requests and non-RCPT states return `DUNNO`. Null envelope senders
use HELO. This adapter adds no Received-SPF or Authentication-Results headers.

## Operation, sizing, and rollback

Use `journalctl -u spfd -u unbound --since '1 hour ago'` and Postfix mail logs to
investigate deferrals, DNS errors, and latency. `spfd` logs JSON result, action,
and duration without sender addresses or DNS explanation text. Apply the site's
journal retention limits; avoid enabling Unbound query logging routinely.

The defaults allow 64 concurrent SPF checks and 256 connections with no check
queue. Size against concurrent inbound SMTP sessions and observed DNS latency;
watch overload logs before increasing limits. Warm-cache [benchmarks](../benchmarks/nsd/REPORT.md)
do not establish Internet cold-cache capacity. Keep TCP DNS permitted for large
answers. `spfd` drains for five seconds at shutdown, then cancels remaining work;
restarts may briefly defer requests, which sending MTAs can retry.

| Symptom | Check |
| --- | --- |
| No SPF logs for inbound mail | Trusted/authenticated bypass, restriction ordering, Postfix service overrides |
| `spfd` fails at startup | Missing environment file, invalid flags, occupied port; inspect journal |
| DNS errors or persistent temperror | `dig` UDP/TCP tests, Unbound logs, time synchronization, trust anchor, outbound port 53 |
| Unexpected listening addresses | Other included Unbound interfaces; inspect full config and `ss` |
| 451 under load | Active checks/connections and DNS latency; reduce load or size limits |

To undo enforcement, empty `SPFD_ENFORCE` and restart `spfd`. To bypass the SPF
service entirely, remove only its `check_policy_service` entry, run `postfix check`,
and reload Postfix **before** stopping `spfd`. Preserve relay protection. Restore
backed-up configs/binary for an upgrade rollback; stop Unbound only if no other
application uses it. Local rollback copies belong outside version control.

For repository validation with Unbound installed, run
`python3 tools/smoke_spfd_unbound.py /tmp/spfd`. On Ubuntu with Unbound's AppArmor
profile, use a temporary directory under its permitted `/var/lib/unbound` tree:

```sh
sudo install -d -m 0700 -o "$(id -un)" -g "$(id -gn)" /var/lib/unbound/spfd-smoke
TMPDIR=/var/lib/unbound/spfd-smoke python3 tools/smoke_spfd_unbound.py /tmp/spfd
```

The smoke test runs unprivileged and removes its temporary files. It exercises the supplied resolver
profile with offline fixtures and both daemon modes; live DNSSEC, service startup,
and actual Postfix delivery still require the host checks above.
