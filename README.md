# Sender Policy Framework

A comprehensive RFC7208 implementation

[![Build Status](https://github.com/zaccone/spf/actions/workflows/go.yml/badge.svg?branch=master)](https://github.com/zaccone/spf/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/zaccone/spf)](https://goreportcard.com/report/github.com/zaccone/spf)
[![GoDoc](https://godoc.org/github.com/zaccone/spf?status.svg)](https://godoc.org/github.com/zaccone/spf)

## About
The SPF Library implements Sender Policy Framework described in RFC 7208. It aims to cover all rough edge cases from RFC 7208.
Hence, the library does not operate on strings only, rather "understands" SPF records and reacts properly to valid and invalid 
input. Wherever I found it useful, I added comments with RFC sections and quotes directly in the source code, so the readers can follow 
implemented logic.

## Current status
The library is still under development. API may change, including function/methods names and signatures. I will consider it correct and stable once it passess all tests described in the most popular SPF implementation - pyspf.

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
local socket access, but no public DNS or installed BIND server. The `_etc/bind`
files are historical fixtures.

To check for races:

```sh
go test -race -count=1 -timeout=60s ./...
```

GitHub Actions runs ordinary tests on Linux, macOS, and Windows, plus race
tests, vet, formatting, and module consistency checks on Linux. Resolver
callbacks finish before a lookup returns. Passing these checks does not
establish complete RFC 7208 conformance; see the modernization plan for the
remaining correctness work.

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
resolver, err := spf.NewMiekgDNSResolverContext("127.0.0.1:53")
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

Both built-in resolvers support `ContextResolver`. The miekg backend follows
at most ten CNAME hops, detects cycles, and retries truncated UDP once over
TCP. The system backend uses Go's resolver and configured system DNS servers
(or the configured `net.DefaultResolver.Dial`). It uses the Go DNS path so
connections can be canceled; platform-native resolver behavior, including
native split-DNS routing, may differ. It relies on the recursive DNS server
for complete alias answers instead of issuing its own CNAME follow-up queries.
For explicit server selection and client-side alias traversal, use miekg.
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

Step 5 adds reverse lookup and bounded forward-validation infrastructure.
PTR mechanism evaluation and the remaining macro work are still step 6.
`Options.HELO`, `Receiver`, and `Time` are reserved for that macro work and do
not yet change expansion; identities and a single evaluation timestamp are
retained through recursion. Missing identities use `unknown`, and zero Time
captures the entry time. These changes do not establish full RFC conformance.
