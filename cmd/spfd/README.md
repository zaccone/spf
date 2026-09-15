# spfd: runnable SPF checks and Postfix policy service

`spfd` wraps this repository's library. It has two subcommands: `check` prints
one SPF result as JSON; `serve` handles concurrent Postfix access-policy requests.
It uses the miekg resolver with an explicitly configured recursive DNS server.

## Build and basic usage

From the repository root, with Go 1.27.1 or a later Go 1.27 patch release:

```sh
go build -o /tmp/spfd ./cmd/spfd
/tmp/spfd check -dns 127.0.0.53:53 -ip 192.0.2.1 \
  -sender sender@example.com -helo mail.example.com
/tmp/spfd serve -dns 127.0.0.53:53 -listen 127.0.0.1:10023
```

Replace the client identity and DNS address with your deployment's values.
`127.0.0.53:53` is an example systemd-resolved stub, not a dependency or an
assumption that it is installed. The default DNS address is `127.0.0.1:53`.
Use a local caching recursive resolver for production.

`check -domain example.com` overrides the inferred sender domain. An empty sender
uses the HELO identity. The output contains `result`, optional `explanation` and
optional diagnostic `error`. Exit status 0 means JSON was produced, including
SPF fail/temperror/permerror; scripts must inspect `result`. Invalid command-line
configuration exits 1. `check -h` and `serve -h` list the flags.

For standalone Linux artifacts, from any supported Go build host:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /tmp/spfd-linux-amd64 ./cmd/spfd
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o /tmp/spfd-linux-arm64 ./cmd/spfd
```

## Policy behavior

The service defaults to **monitor mode**: it evaluates and logs SPF and returns
`DUNNO`, letting Postfix continue its restrictions. Add `-enforce` to reject SPF
fail and temporarily defer SPF temperror. The response table is:

| SPF result | Monitor mode | `-enforce` |
|---|---|---|
| pass, none, neutral, softfail, permerror | DUNNO | DUNNO |
| fail | DUNNO | 550 5.7.23 |
| temperror | DUNNO | 451 4.7.24 |

Malformed requests (including invalid client IPs, malformed sender mailboxes,
or a null sender without HELO) and exhausted evaluation capacity produce
451 4.3.0 in both modes. Domains unsuitable for SPF, including HELO address
literals, produce `none` and return `DUNNO` in both modes. Excess connections are
closed immediately; Postfix then uses its policy-service failure action.
DNS explanation strings are never copied
into protocol responses. SPF pass never returns `OK`, so it cannot bypass other
restrictions. Permerror is logged and left to other policy, rather than rejecting
mail for a sender's broken SPF configuration.

Evaluation runs at the `RCPT` state and uses the envelope sender domain. For a
null reverse path, it uses HELO and the library's postmaster identity. Other
protocol states and authenticated requests (`sasl_username` present and nonempty)
return `DUNNO`. Non-null senders do not get an additional independent HELO check.
This initial adapter does not add Received-SPF/Authentication-Results headers,
perform DKIM/DMARC, or support SMTPUTF8/IDNA identities beyond the library's limits.
It is a Postfix protocol adapter, not a qmail integration.

## Postfix integration

The listener defaults to loopback TCP port 10023. TCP binding requires a literal
loopback IP. For a Unix socket use `-network unix -listen /run/spfd/policy.sock`;
its parent must exist and allow the daemon to create files. Socket permissions
are 0660; arrange the service group and Postfix access explicitly. Existing socket
paths are never unlinked on startup. Loopback TCP avoids Unix socket ownership
and Postfix chroot path complications.

Following the [Postfix policy delegation protocol](https://www.postfix.org/SMTPD_POLICY_README.html),
append the policy check to your existing recipient restrictions **after relay
protection**. For example, integrate these entries without discarding existing
site restrictions:

```text
smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    check_policy_service inet:127.0.0.1:10023
```

Keep your existing `smtpd_relay_restrictions` in place. This fragment does not
configure trusted networks, authentication, TLS, or the rest of your mail policy.
See [Postfix relay and access control](https://www.postfix.org/SMTPD_ACCESS_README.html).
Keep Postfix's temporary-failure behavior when the policy service is unreachable;
do not configure a failure action of `OK`. Start in monitor mode and review logs
before enabling rejection. Validate changes with `postfix check` before reload.

Protocol requests are `name=value` lines followed by a blank line. Connections
can carry multiple requests in order. Unknown attributes are tolerated; repeated attributes use their last value,
as permitted by the Postfix protocol. Malformed framing is rejected. Requests are limited to 64 KiB,
256 attributes, and lines that fit the 4096-byte read buffer.

## Concurrency, deadlines and shutdown

Each accepted connection has one goroutine and processes requests sequentially.
Different connections evaluate concurrently, up to `-max-checks` (default 64).
There is no application waiting queue. `-max-connections` (default 256) also bounds
idle client goroutines. Limits are independent of the SPF per-evaluation DNS
budget; increasing concurrency does not increase the work allowed for one SPF
record. The OS listener backlog is separate from these application limits.

`-timeout` defaults to 20s and must be positive and at most 20s. `-io-timeout`
(default 30s) bounds each whole request read, including slow partial requests,
and each response write. SIGINT/SIGTERM stops acceptance and allows existing
connections to drain for `-shutdown-timeout` (default 5s), then cancels outstanding
DNS work and closes remaining sockets. Idle connections can consume the drain
period. DNS callbacks must honor cancellation, as the built-in resolver does.

JSON logs on stderr contain result, action and elapsed milliseconds. They omit
sender addresses and DNS explanation text. Startup, overload and shutdown are
logged too. Journald collects these under systemd. A metrics endpoint, parsed
policy cache and rate limiting beyond concurrency bounds are future work.

## Linux service

A sample [systemd unit](../../deploy/spfd.service) runs in monitor mode, uses a
dynamic unprivileged user, and expects the native Linux binary at
`/usr/local/bin/spfd`. Review the DNS address and flags for your host:

```sh
sudo install -m 0755 /tmp/spfd-linux-amd64 /usr/local/bin/spfd
sudo install -m 0644 deploy/spfd.service /etc/systemd/system/spfd.service
sudo systemctl daemon-reload
sudo systemctl enable --now spfd
journalctl -u spfd
```

Use the arm64 binary on an arm64 host. Add a systemd override to change flags;
when overriding `ExecStart`, clear the original `ExecStart=` first. The example
unit does not install or reconfigure Postfix or a DNS resolver.

## Validation and scope

Run `go test -race ./...` and `go vet ./...`. Command tests exercise results,
null senders, protocol framing, persistent connections, concurrent evaluations,
overload, deadlines and shutdown without public DNS. Linux binary smoke checks
use a local DNS fixture: `python3 tools/smoke_spfd.py /tmp/spfd` (Python standard
library only). Production Postfix delivery and qmail integration still
need deployment-specific validation; library microbenchmarks do not establish
this daemon's end-to-end capacity.
