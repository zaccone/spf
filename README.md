# Sender Policy Framework

SPF policy evaluation in Go, with explicit conformance evidence and resolver limits.

[![CI](https://github.com/zaccone/spf/actions/workflows/go.yml/badge.svg?branch=master)](https://github.com/zaccone/spf/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/zaccone/spf.svg)](https://pkg.go.dev/github.com/zaccone/spf)
[![Go Version](https://img.shields.io/github/go-mod/go-version/zaccone/spf/master)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## About
This library evaluates Sender Policy Framework policies using its own lexer,
parser, and macro implementation. It returns the SPF result, optional explanation,
and diagnostic error; SMTP disposition and header generation belong to the caller.

## Current status

The local conformance runner covers all 203 cases in the pinned RFC 7208 suite
and 14 applicable pySPF development cases. Two pySPF-only compatibility modes
are explicitly excluded. This is not a full-conformance or stability claim:
see the [conformance matrix and known limits](CONFORMANCE.md),
[migration notes](MIGRATION.md), and [runnable examples](example_test.go).
Release readiness requires owner review and green hosted CI for the final commit.

## Runnable binary

Build `spfd` with `go build -o /tmp/spfd ./cmd/spfd`. Use `spfd check` for a
single JSON result, or `spfd serve` for a bounded concurrent Postfix policy
service over loopback TCP or a Unix socket. The service logs SPF results by
default; `-enforce` enables fail rejection and temporary-error deferral. See
[the binary usage and deployment guide](cmd/spfd/README.md) for flags, Postfix
configuration, Linux builds and a systemd unit.

## Building and testing

Go 1.27 or later is required. Use the latest patch release of Go 1.27;
this build setup was verified with Go 1.27.1.

From the repository root:

```sh
go mod download
go mod verify
go build ./...
go test -count=1 -timeout=60s ./...
go vet ./...
```

DNS tests each own servers on ephemeral UDP/TCP ports on loopback. They require
local socket access, but no public DNS or installed resolver. For deployments,
`_etc/unbound` contains a loopback-only recursive cache configuration. Install
it as `/etc/unbound/unbound.conf`, validate it with `unbound-checkconf`, and
point `NewServerResolver` or `spfd -dns` at `127.0.0.1:53`.

To check for races:

```sh
go test -race -count=1 -timeout=60s ./...
```

GitHub Actions runs ordinary tests on Linux, macOS, and Windows, plus race
tests, vet, formatting, and module consistency checks on Linux. Resolver
callbacks finish before a lookup returns. Passing these checks does not
establish complete RFC 7208 conformance; see [CONFORMANCE.md](CONFORMANCE.md)
for evidence and limitations. CI also runs bounded fuzz smoke tests and pinned
`govulncheck` v1.8.0. The corpus runs offline as part of ordinary `go test`;
Python is needed only to regenerate the vendored JSON fixtures.

## Benchmarks

On a four-vCPU Ubuntu VM, the Go evaluator achieved about 5.4× the throughput
of four pyspf processes on two CPU-bound synthetic policies. With simulated
DNS delay, both implementations benefited from concurrent evaluations and
performed similarly at low concurrency. These are library microbenchmarks,
not production SMTP capacity measurements. See the [benchmark report](benchmarks/vm/REPORT.md)
for methodology, results and limitations, and the [reproduction instructions](benchmarks/vm/README.md)
for scripts and raw measurements.

## Dependencies
The library uses [miekg/dns](https://github.com/miekg/dns) for its configurable
DNS resolver. The SPF lexer, parser, and macro implementation remain part of
this project. Dependency versions and checksums are recorded in `go.mod` and
`go.sum`; normal builds do not need `go get` or a GOPATH checkout.

## Pull requests & code review
If you have any comments about code structure feel free to reach out or simply make a Pull Request

## Evaluation options and DNS limits

Existing `CheckHost` and `CheckHostWithResolver` calls remain available. For
cancellation or a custom context-aware resolver, use the additive API:

```go
resolver, err := spf.NewServerResolver("127.0.0.1:53")
if err != nil {
    return err
}
result, explanation, err := spf.CheckHostWithOptions(
    ctx, net.ParseIP("192.0.2.1"), "example.com", "sender@example.com",
    spf.Options{Resolver: resolver},
)
```

A nil `Options.Resolver` selects `DNSResolver`. A supplied resolver is the sole
DNS source: missing capabilities never trigger a fallback to public DNS.
`ContextResolver` provides context-aware TXT, family-specific IP, MX, and
reverse lookups. TXT results contain one string per resource record, joining
only that record's component strings. MX and reverse results are returned
before forward address resolution, so the evaluator can bound that work.

Each evaluation shares a 20-second deadline, shortened by an earlier caller
deadline, through includes and redirects. It permits ten evaluated
DNS-causing terms and two void logical lookups. A non-matching address answer
is not a void lookup; a missing requested RRset is. The initial TXT lookup
and explanation retrieval consume no terms. Explanation retrieval happens
after the SPF decision and cannot replace a Fail result with a DNS error.
More than ten MX exchanges produces Permerror before any address dispatch;
multiple addresses returned for one exchange do not consume extra terms.
Address matching queries the client's family; `exists` always queries A.

`DNSResolver` uses system DNS; `ServerResolver` uses the configured DNS server.
Both implement `Resolver` and `ContextResolver`. The `NewServerResolver` constructor
returns a concrete pointer usable with either interface. The former `MiekgDNSResolver`
type and constructors remain available as deprecated compatibility entrypoints.

The configured server backend follows at most ten CNAME hops, detects cycles, and retries truncated UDP once over
TCP. The system backend uses Go's resolver and configured system DNS servers
(or the configured `net.DefaultResolver.Dial`). It uses the Go DNS path so
connections can be canceled; platform-native resolver behavior, including
native split-DNS routing, may differ. It relies on the recursive DNS server
for complete alias answers instead of issuing its own CNAME follow-up queries.
For explicit server selection, client-side alias traversal, and utility labels
containing punctuation/spaces rejected by Go's system resolver, use `ServerResolver`.
Neither interface exposes intermediate wire responses or retries: void limits
count logical lookups after alias processing, not individual DNS packets.

Errors retain their underlying causes. Use `errors.Is` for
`ErrDNSTemperror`, `ErrDNSPermerror`, `ErrDNSLimitExceeded`,
`context.Canceled`, and `context.DeadlineExceeded`, and `errors.As` for typed
DNS/transport errors. Direct equality against a wrapped sentinel is insufficient.

`CheckHostWithResolver` automatically uses the context-aware path when its
resolver implements both interfaces. Legacy-only custom resolvers retain
synchronous callbacks and shared term limits, but cannot guarantee
cancellation inside a call, family-specific dispatch, full void accounting,
or pre-dispatch MX/PTR limits. Wrapping a built-in resolver in
`LimitedResolver` selects this legacy path: that wrapper limits method calls
and MX matcher callbacks, not SPF terms. Its configured limit is inclusive.

## Macros and PTR

Domain-specs in `a`, `mx`, `include`, `exists`, `ptr`, `redirect`, and `exp`
are expanded before use. Macro transformations support IPv6 nibbles, multiple
delimiters (including empty parts), reversal, rightmost-part selection, and
uppercase URL escaping. Names exceeding 253 characters lose complete labels
from the left. Expanded labels may contain punctuation and spaces; dots separate labels and
backslashes are literal. Empty/oversized labels and non-printable/non-ASCII
output produce Permerror, or the empty explanation fallback for `exp`. Initial
identity domains retain the stricter hostname checks.

Pass SMTP identities through `Options.HELO` and `Options.Receiver`. They remain
unchanged through includes and redirects; `%{d}` follows the current policy
domain. Missing identities expand to `unknown`. `Options.Time` supplies the
explanation timestamp; a zero value captures the time once at entry. The
`c`, `r`, and `t` macros are accepted only in fetched explanation text.

`ptr` and `%{p}` validate reverse names through same-family forward lookups,
processing at most the first ten PTR candidates. Matching uses DNS label
boundaries and ignores case. Completed reverse validation is reused within
one evaluation; `%{p}` prefers the current domain, then its subdomains, then
another validated name. Each evaluated `%{p}` counts toward the shared ten-term
budget in addition to its containing mechanism or redirect; explanation work
has no term charge and uses a separate void allowance. Ordinary reverse DNS
errors make `ptr` a non-match; forward DNS errors skip that candidate. For
`%{p}`, DNS errors or no validated names produce `unknown`. Cancellation and
exhausted budgets still stop evaluation, while explanation failures leave
Fail unchanged.

Legacy-only resolvers cannot perform reverse validation: `ptr` returns
Permerror with `ErrUnsupportedResolver`, and `%{p}` expands to `unknown`.
No other DNS source is consulted. PTR is supported for existing policies,
though RFC 7208 discourages publishing it. See [CONFORMANCE.md](CONFORMANCE.md)
for the corpus results, explicit exceptions, and release gate.
