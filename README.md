# Sender Policy Framework

An implementation of Sender Policy Framework (SPF), defined in RFC 7208.
It evaluates a domain’s DNS-published policy against an SMTP client’s IP address
and envelope sender to determine whether that client is authorized to send mail
for the domain.

[![CI](https://github.com/zaccone/spf/actions/workflows/go.yml/badge.svg?branch=master)](https://github.com/zaccone/spf/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/zaccone/spf.svg)](https://pkg.go.dev/github.com/zaccone/spf)
[![Go Version](https://img.shields.io/github/go-mod/go-version/zaccone/spf/master)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Use `spf` directly as a library in your application, or run the included `spfd`
binary as a standalone service.

The evaluator implements the RFC 7208 mechanisms (`all`, `ip4`, `ip6`, `a`,
`mx`, `include`, `exists`, and `ptr`), redirects, macro expansion, and failure
explanations. Context-aware evaluation shares a ten-term DNS budget, a two-void
lookup limit, and a 20-second deadline across nested policies; an earlier caller
deadline takes precedence.

All 203 cases in the pinned RFC 7208 test suite pass, alongside 14 applicable
pySPF development cases. See [conformance evidence](CONFORMANCE.md) for assertion
scope, adaptations, and known resolver limitations. Custom DNS resolvers can be
injected for deterministic tests without network access.

## Use the standalone binary

Build from this repository with Go 1.27 or later:

```sh
go build -o spfd ./cmd/spfd
./spfd check -dns 127.0.0.1:53 -ip 192.0.2.1 -sender sender@example.com
./spfd serve -dns 127.0.0.1:53 -listen 127.0.0.1:10023
```

Set `-dns` to your recursive DNS server. `check` prints a JSON result; `serve`
runs a Postfix policy service in monitor mode by default. Add `-enforce` to
reject SPF fail and defer temporary errors. See the
[deployment guide](cmd/spfd/README.md) for Postfix configuration and service setup.

## Use the Go library

Requires Go 1.27 or later. The library returns an SPF result, an optional
explanation, and a diagnostic error; your application decides how to handle mail.

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
    result, explanation, err := spf.CheckHostWithOptions(
        context.Background(),
        net.ParseIP("192.0.2.1"), // connecting client's IP
        "example.com",         // envelope sender's domain
        "sender@example.com",  // envelope sender
        spf.Options{},         // use system DNS
    )
    fmt.Println(result, explanation, err)
}
```

Replace the example IP and sender with the SMTP client's values. Inspect
`result` when deciding how to handle mail: an SPF `fail` normally has no Go error.
To select a DNS server, create a resolver with `spf.NewServerResolver("127.0.0.1:53")`
and pass it through `Options.Resolver`.

See the [API reference](https://pkg.go.dev/github.com/zaccone/spf)
and [runnable examples](example_test.go).

## Performance

On a shared four-vCPU Ubuntu VM with warmed local Unbound DNS, the archived
15 September 2026 run measured these simple-policy results (one DNS query per check):

| Interface | Throughput | p99 latency |
| --- | ---: | ---: |
| Library | 232,517 checks/s | 1.69 ms |
| Standalone `spfd` | 98,860 requests/s | 3.46 ms |

Values are medians of three ten-second trials with 64 workers/connections.
The daemon used persistent loopback TCP connections and JSON logging to
`/dev/null`. These cache-hit fixtures exclude public DNS misses and production
log backpressure. See the [benchmark report](benchmarks/unbound/REPORT.md) for
other policies, concurrency settings, and latency measurements, and the
[reproduction guide](benchmarks/unbound/README.md) for scripts and raw results.

## Development

```sh
go test -count=1 -timeout=60s ./...
go vet ./...
```

The conformance corpus uses deterministic in-memory DNS fixtures. Resolver
integration tests use local DNS servers on ephemeral loopback ports; neither
requires public DNS access. See the [test case inventory](testdata/pyspf/CASES.md)
and [fixture documentation](testdata/pyspf/README.md). Run `go test -race -count=1 -timeout=60s ./...` to check for races.

Licensed under [MIT](LICENSE). Issues and pull requests are welcome.
