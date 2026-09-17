# Sender Policy Framework

`spf` is a comprehensive solution for Sender Policy Framework (SPF) evaluation,
implementing [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208.html). It checks
whether an SMTP client's IP address is authorized to send mail for the envelope
sender's domain. Use it as a library within your application, or deploy the
included `spfd` binary as a standalone SPF checking service. The project provides
the evaluator, DNS resolution, command-line tools, and deployment configuration.

[![CI](https://github.com/zaccone/spf/actions/workflows/go.yml/badge.svg?branch=master)](https://github.com/zaccone/spf/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/zaccone/spf.svg)](https://pkg.go.dev/github.com/zaccone/spf)
[![Go Version](https://img.shields.io/github/go-mod/go-version/zaccone/spf/master)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Built for high-throughput, concurrent mail processing, `spfd` handles independent
connections in parallel, with bounded active checks, cancellation, and graceful
shutdown. [Benchmarks](#performance-and-benchmarks) measure both interfaces under simple
and mixed-policy workloads, with separate checks for DNS failures and recovery.

## SPF evaluation and correctness

The evaluator supports all RFC 7208 mechanisms (`all`, `ip4`, `ip6`, `a`, `mx`,
`include`, `exists`, and `ptr`), redirects, macro expansion, and failure
explanations. IPv4 and IPv6 clients are supported. Context-aware evaluation
limits each check to ten DNS-causing terms and two void lookups, with a
20-second deadline shared across includes and redirects. An earlier caller
deadline takes precedence.

All 203 cases in the pinned RFC 7208 suite pass, alongside 14 applicable
development cases. Injectable resolvers make application tests repeatable
without network access; separate loopback DNS tests exercise the
actual UDP/TCP resolver paths. The [conformance guide](CONFORMANCE.md) records
tested behavior, corpus adaptations, and backend limitations, including legal
DNS labels that require the explicit-server resolver.

## Run the standalone service

`spfd check` evaluates one sender and prints JSON. `spfd serve` runs a persistent
SPF policy service with structured result logs and configurable limits on
connections and concurrent evaluations.
Build from this repository with Go 1.27 or later:

```sh
go build -o spfd ./cmd/spfd

# Check a sender using your local recursive DNS cache.
./spfd check -dns 127.0.0.1:5335 -ip 192.0.2.1 -sender sender@example.com

# Start the policy service in monitor mode.
./spfd serve -dns 127.0.0.1:5335 -listen 127.0.0.1:10023
```

Replace the example client and sender with real SMTP identities, and set `-dns`
to your recursive resolver. By default the service allows 64 active evaluations
and 256 connections; each evaluation retains its own DNS limits. See the
[command guide](cmd/spfd/README.md) for flags, timeouts, and shutdown behavior.

## Integration with MTA

`spfd` currently supports the Postfix access-policy protocol over loopback TCP
or a Unix socket. Connect it to your mail transfer agent (MTA) through that
protocol; for Postfix, add the policy check after existing relay protection.
Monitor mode logs SPF results while leaving the mail decision to the MTA.
Add `-enforce` to reject SPF fail and temporarily defer SPF temperror. See the
[Postfix integration instructions](cmd/spfd/README.md#postfix-integration) for
configuration and response behavior.

A gRPC API layer is planned to support integrations beyond the current policy
protocol. It is not available yet.

## Performance and benchmarks

The 16 September 2026 mixed-policy benchmark completed **13.9 million
evaluations across 126 trials with zero result/action mismatches**, using
Unbound and an NSD test authority on a shared four-vCPU Ubuntu VM. Selected
warm-cache medians were:

| Interface / workload | Concurrent workers | Checks/s | p99 latency upper bound |
| --- | ---: | ---: | ---: |
| Library / uniform | 128 | 64,768 | 9.1 ms |
| Library / frequently repeated domains (Zipf) | 128 | 99,373 | 8.1 ms |
| Service / uniform | 64 | 40,629 | 6.9 ms |
| Service / frequently repeated domains (Zipf) | 64 | 57,115 | 5.3 ms |

A separate simple-policy fixture reached **232,517 library checks/s** and
**98,860 service requests/s** with cached local DNS. These are controlled
measurements, not production capacity guarantees: policy mix, cache misses,
concurrency, and logging affect throughput and latency.

- [Mixed-policy and resilience report](benchmarks/nsd/REPORT.md): throughput,
  latency, overload recovery, DNS faults, and shutdown checks;
  [reproduction guide](benchmarks/nsd/README.md).
- [Cached-DNS performance report](benchmarks/unbound/REPORT.md): simple/include
  policies, concurrency sweeps, and CPU profiles;
  [reproduction guide](benchmarks/unbound/README.md).
- [Stalwart mail-auth comparison](benchmarks/comparison/mailauth/REPORT.md):
  throughput, tail latency, and the effect of resolver response sharing.
- [Rspamd benchmark configuration](benchmarks/comparison/rspamd-local-options.inc)
  and [wttw/spf Go benchmark harness](benchmarks/comparison/wttw_bench/main.go):
  retained comparison artifacts; this repository does not include their result
  reports. The Go harness uses in-memory DNS fixtures.

## Embed as a Go library

Applications can use the same evaluator directly, with system DNS, a configured
recursive server, or a custom context-aware resolver. Each call owns its
evaluation state, so independent checks can run concurrently; a shared custom
resolver must also be safe for concurrent use. Requires Go 1.27 or later:

```sh
go get github.com/zaccone/spf
```

```go
package main

import (
	"context"
	"fmt"
	"net"

	"github.com/zaccone/spf"
)

func main() {
	resolver, err := spf.NewServerResolver("127.0.0.1:5335")
	if err != nil {
		panic(err)
	}
	result, explanation, err := spf.CheckHostWithOptions(
		context.Background(),
		net.ParseIP("192.0.2.1"),
		"example.com",
		"sender@example.com",
		spf.Options{Resolver: resolver, HELO: "mail.example.com"},
	)
	fmt.Println(result, explanation, err)
}
```

The call returns the SPF result, an optional explanation, and a diagnostic
error. Inspect `result` when deciding how to handle mail: SPF `fail` normally
has no Go error. An empty `Options{}` selects system DNS. See the
[API reference](https://pkg.go.dev/github.com/zaccone/spf) and
[runnable examples](example_test.go) for resolver injection and cancellation.

## Development

```sh
go test -count=1 -timeout=60s ./...
go test -race -count=1 -timeout=60s ./...
go vet ./...
```

The conformance corpus uses in-memory DNS fixtures; resolver integration tests
use ephemeral loopback ports. Neither requires public DNS access. See the
[test case inventory](testdata/pyspf/CASES.md) and
[fixture documentation](testdata/pyspf/README.md) for coverage and regeneration.

## End-to-end deployment

Deploy `spfd` with your MTA and a local recursive DNS cache to provide SPF
checking from incoming SMTP requests through DNS evaluation and policy
responses. We recommend Unbound and provide a ready-to-use
[configuration](deploy/unbound/spfd.conf), but any caching DNS server will work.
The supplied Debian/Ubuntu recipe combines Postfix, `spfd`, and Unbound, with
systemd services and configuration for the stack.

Configure and validate your DNS cache first, then point `spfd serve -dns` at its
address and port and connect the MTA to `127.0.0.1:10023`. Our Unbound profile
listens on `127.0.0.1:5335`, enables DNSSEC validation and prefetch, respects DNS
TTLs, and does not serve expired records. Start in monitor mode, verify mail
flow and SPF results, then choose whether to enable enforcement.

The [end-to-end deployment guide](deploy/README.md) covers installation,
configuration, acceptance checks, operation, and rollback. The MTA remains
responsible for SMTP and delivery; DKIM/DMARC and broader spam filtering are
separate from this SPF deployment.

Licensed under [MIT](LICENSE). Issues and pull requests are welcome.
