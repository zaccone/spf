# DNS dependency and public API migration plan

Assessed 2026-09-15 against SPF commit `8d17653`, using the source archive of
`codeberg.org/miekg/dns v0.6.109` (2026-09-04,
`3543e6e5dc72f729965f75405b6c27a564e5b118`). This is a plan, not an implemented port.

## Recommendation

**Prepare the migration, but gate shipping on preserving DNS label boundaries.**
Renaming the public resolver API can proceed independently. Migration has a good
maintenance rationale and a small production footprint, but it is not an import
path replacement. The inspected decoder presents a concrete compatibility risk.

- The [GitHub library's maintenance notice](https://github.com/miekg/dns#readme)
  says it will receive only specific fixes and will eventually be archived.
- The [Codeberg README](https://codeberg.org/miekg/dns/src/tag/v0.6.109/README.md)
  explicitly permits incompatible changes before a future 1.0 release. Pin a
  reviewed tag; treat upgrades as code changes requiring regression checks.
- Its Go minimum is 1.27.0, matching this repository. Its BSD-3-Clause license is
  compatible with the current dependency's license.
- Upstream reports performance improvements, but we have not measured SPF gains.
  Network latency and connection setup may dominate this client's workload.
  Maintenance is the primary reason to migrate.
- The new module includes server applications and a substantially larger module
  graph. That does not mean every dependency is linked into SPF. Inspect actual
  package dependencies and binary size before accepting the change.

Staying on `github.com/miekg/dns v1.1.73` is the short-term fallback while the
label issue is unresolved. Replacing the configurable backend with `net.Resolver`
would lose this project's supported utility-label behavior and transport control.

## Scope in this repository

Production imports are confined to `resolver_miekg.go`; another 11 Go test files
import the old library, including `cmd/spfd/main_test.go`. The public interfaces
use standard Go values rather than DNS-library types. The evaluator, parser,
macro logic, and SPF accounting therefore need no dependency-driven redesign.

Primary affected areas:

- `resolver_miekg.go`: transport, response validation, aliases, record conversion,
  and literal/presentation name conversion.
- `main_test.go`, `resolver_context_test.go`, `cmd/spfd/main_test.go`: DNS server
  fixtures, lifecycle, cancellation, and UDP/TCP handling.
- Remaining DNS tests: question fields, record creation/copying, and imports.
- `go.mod`, `go.sum`, `README.md`, `MIGRATION.md`, examples, and resolver constructor
  call sites, including the policy service.

Baseline validation: `go test -count=1 -timeout=60s ./...` passed on Go 1.27.0,
macOS arm64. No port, upstream execution test, or performance comparison has yet
been performed; the upstream findings below are from tagged source inspection.

## Public API: remove the implementation author's name

`MiekgDNSResolver` describes a dependency rather than the caller's choice. Use
`ServerResolver` to describe a resolver directed at one configured DNS server.
Avoid `RecursiveResolver`: this client sends queries to a recursive server but
does not implement recursive resolution itself.

Proposed preferred API:

```go
type ServerResolver struct { /* private implementation */ }

func NewServerResolver(addr string) (*ServerResolver, error)
```

The concrete pointer implements both existing `Resolver` and `ContextResolver`.
One constructor can serve legacy callers and `Options.Resolver`; no separate
`NewServerResolverContext` is necessary. Preserve `IP:port`/`host:port` validation
and current constructor behavior. The command's stricter literal-IP restriction
remains a command-level policy.

Keep the existing system-backed `DNSResolver` in this migration. Renaming it to
`SystemResolver` is a possible later cleanup, but unnecessary for replacing this
dependency. Document the distinction explicitly: `DNSResolver` uses system DNS;
`ServerResolver` uses the configured server.

Compatibility path:

```go
// Deprecated: Use ServerResolver.
type MiekgDNSResolver = ServerResolver

// Deprecated: Use NewServerResolver.
func NewMiekgDNSResolver(addr string) (Resolver, error)

// Deprecated: Use NewServerResolver.
func NewMiekgDNSResolverContext(addr string) (ContextResolver, error)
```

Both wrappers delegate to the new constructor and retain their exact signatures.
On failure, explicitly return `nil, err` before converting a concrete pointer to
an interface, so the new delegation does not introduce a typed-nil interface.
Retain all exported lookup methods. Rename the implementation file to
`resolver_server.go` and use the neutral constructor in documentation and the CLI.
Add interface assertions and a small external-package compatibility test covering
both old and new entrypoints. Type aliases preserve source identity, though the
printed/reflected concrete type name changes; document that diagnostic difference.

This additive approach allows a normal compatible release. Removing the old
names is a separate breaking API decision for a future major release. Keep
`net.IP` and `net.MX` in the public interfaces; adapt `netip.Addr` internally.

## Release blockers and design requirements

### 1. DNS label boundaries: resolve before porting the fixtures

The new library deliberately removes presentation escapes. More importantly,
its [name decoder](https://codeberg.org/miekg/dns/src/tag/v0.6.109/internal/unpack/unpack.go)
copies label bytes into a string and appends dots without distinguishing embedded
dot bytes. Wire labels `[attacker.example, test]` and
`[attacker, example, test]` consequently produce the same decoded name.

Our existing `dnsLiteralName` rejects an embedded dot; see
`TestDNSLiteralNameCannotForgeBoundary`. Removing that helper mechanically would
lose this safeguard. The ambiguity also matters for question/answer owner checks
and CNAME targets, in addition to MX/PTR names and PTR suffix validation.

First create raw-wire cases for embedded dots in questions, owners, CNAME, MX,
and PTR targets, including compressed names. Preserve separate tests for literal
backslashes, `\\032` text, spaces, punctuation, root, and length limits. Current
helper-level tests alone do not prove the new transport is safe.

Preferred resolution: adopt an upstream change that exposes label boundaries or
rejects unrepresentable labels. An independently reviewed validator over `Msg.Data`
could be an alternative, but would require careful compression, record-boundary,
and malformed-packet handling. Treat that as additional scope with its own tests,
not a quick string check. Do not try to recover lost boundaries from decoded
strings or normalize these names into acceptance. If neither approach is
available, defer the dependency switch and ship only the neutral API.

### 2. Context does not automatically interrupt socket reads

The tagged [client implementation](https://codeberg.org/miekg/dns/src/tag/v0.6.109/client.go)
checks context around I/O, but sets its own read deadline and does not install a
cancellation callback that closes an in-flight connection. A direct replacement
with `Client.Exchange(ctx, ...)` would therefore lose our prompt cancellation.

Retain per-query connection ownership: dial with `net.Dialer.DialContext`, use
`ExchangeWithConn(ctx, req, conn)`, and retain the synchronized
`context.AfterFunc` close/join pattern. Initialize transport eagerly with
`dns.NewClient()` and configure it before concurrent use. Audit read/write/dial
timeouts against the old behavior and the remaining evaluation deadline; the new
default dial timeout is 5 seconds. Ensure cancellation/deadline closes the socket
even where the library resets its read deadline. Do not mutate shared transport
settings during lookups. Confirm UDP/TCP framing with real socket tests.

### 3. Preserve validation, errors, and SPF semantics

Keep response ID/QR, opcode, exactly-one-question, name/type/class validation;
the library's ID and response-bit checks do not replace the rest. Keep IN-class
owner filtering, CNAME cycles/conflicts and ten-hop bounds, UDP truncation retry
once over TCP, and rejection of truncated TCP responses. Keep NXDOMAIN/NODATA
separate from temporary failures, with underlying causes accessible through
`errors.Is`/`errors.As` and `wrapDNSError`.

Preserve one string per TXT RR, requested IP family only, MX/PTR candidate order,
evaluation-wide deadlines, and logical lookup budgets. Migration must not change
Pass/Fail/Temperror/Permerror decisions or introduce fallback to another DNS source.

## Mechanical API mapping

Mappings checked against the tagged source and
[upstream porting guide](https://codeberg.org/miekg/dns/src/tag/v0.6.109/_doc/README-v1-to-v2.md):

| Current usage | Target approach |
| --- | --- |
| `Msg.SetQuestion` | `dnsutil.SetQuestion`; preserve RD and IN class |
| Question `Name/Qtype/Qclass` | RR `Header().Name`, `dns.RRToType`, `Header().Class` |
| `Header().Rrtype`, `Ttl` | `dns.RRToType(rr)`, `Header().TTL` |
| `dns.NewRR`, `dns.Copy(rr)` | `dns.New`, `rr.Clone()` |
| A/AAAA `net.IP` fields | `Addr` (`netip.Addr`); convert to owned `net.IP` at boundary |
| Composite RR literals | `dns.Header` plus embedded `rdata` structures |
| `dns.ReverseAddr(string)` | Parse with `netip.ParseAddr`, then `dnsutil.ReverseAddr`; test mapped IPv4 and invalid input |
| `PackDomainName` / `UnpackDomainName` helpers | Redesign after resolving label-boundary gate; no blind substitution |
| `Client.Net`, `dns.Conn`, `ExchangeWithConnContext` | Explicit network and `net.Conn`, `ExchangeWithConn` plus cancellation ownership |
| `SetReply`, `SetRcode` | `dnsutil.SetReply` followed by explicit Rcode assignment |
| `HandlerFunc(w, req)` | `HandlerFunc(ctx, w, req)` |
| `WriteMsg` | Pack and write with `io.Copy`; check errors and avoid stale `Data` |
| `ActivateAndServe`, `ShutdownContext` | `ListenAndServe` with supplied listener/packet conn; `Shutdown(ctx)` and explicit completion checks |
| `NotifyStartedFunc()` | `NotifyStartedFunc(context.Context)` |

Audit message buffer ownership: exchanges reuse `Msg.Data`, and message copying
can be shallow. Build fresh requests for fallback, retain response data until
validation/conversion completes, and clone reusable fixture records. Adapt fixture
write deadlines; `Server.WriteTimeout` is not a direct field replacement.

## Delivery sequence

1. **Neutral public API, old backend retained.** Implement the constructor,
   aliases, wrappers, file rename, documentation, CLI call sites, and compatibility
   checks. This is independently shippable.
2. **Compatibility spike and go/no-go.** Reproduce label ambiguity with raw-wire
   tests against the pinned tag; choose and verify the resolution. Record baseline
   behavior and inspect actual dependency growth. Stop the port here if the gate
   cannot be met without unreasonable maintenance burden.
3. **Production adapter.** Add the pinned Codeberg dependency and port the single
   resolver implementation, keeping old-library test servers temporarily. This
   provides useful independent client/server interoperability coverage. Implement
   cancellation, validation, record conversion, and buffer ownership explicitly.
4. **Fixture migration and dependency cleanup.** Port shared DNS helpers first,
   then individual tests and command fixtures. Keep raw-wire edge cases independent
   of the new encoder so client and test server cannot hide the same decoding bug.
   Remove all direct old imports and tidy modules. No permanent dual backend is
   needed.
5. **Verification and release.** Run the gates below, review docs and dependency
   changes, release with the pinned tag, and retain a straightforward revert of
   the backend change. The neutral API remains usable with either backend.

Indicative effort: 0.5–1 engineer-day for the API cleanup, 1–2 days for the spike,
and 2–4 days for adapter/fixtures/verification if the name issue has a simple
resolution. These are planning estimates; upstream work or a wire validator is
additional, unbounded work until the spike defines it.

## Acceptance and rollout gates

- All existing conformance, corpus, lifecycle, CLI, cancellation, and alias tests
  pass; preserve `FuzzDNSLiteralNames` with its updated internal contract.
- New raw-wire boundary tests pass, including compressed names; malformed names
  cannot be accepted as a different owner or PTR suffix.
- Cancellation before dial and during UDP/TCP reads, shorter caller deadlines,
  TCP fallback, response mismatches, EOF, and concurrent resolver reuse pass.
- Run existing CI: build, full tests on Linux/macOS/Windows, race detector, vet,
  policy-service smoke test, formatting, module verification/tidy, govulncheck,
  and all five existing bounded fuzz targets.
- Inspect `go list -deps ./...`, `go list -m all`, and `go mod why -m
  github.com/miekg/dns`. Upstream's module still lists the old library indirectly;
  distinguish module-graph presence from a package linked into our binaries.
- Compare repeated local DNS benchmarks for TXT, A/AAAA, CNAME, and TCP fallback,
  plus concurrent SPF checks: latency, allocations, timeouts, and binary size.
  Agree a regression threshold before using results as a release decision.
- Trial the policy service in its existing non-enforcing mode and compare decisions
  against a fixed DNS dataset/baseline. Investigate changed decisions before enabling
  enforcement. Roll back the dependency adapter if correctness or resource behavior
  regresses; do not fall back silently at runtime.

## Evidence and limits

Release identity came from the [Go module proxy metadata](https://proxy.golang.org/codeberg.org/miekg/dns/@v/v0.6.109.info).
The exact [source archive](https://proxy.golang.org/codeberg.org/miekg/dns/@v/v0.6.109.zip)
was inspected, including `client.go`, `transport.go`, `internal/unpack/unpack.go`,
`dnsutil/compat.go`, `rdata/rdata.go`, `server.go`, `response.go`, `go.mod`, and
`LICENSE`. The migration guide is useful for orientation, but tagged code is the
authority for exact signatures. Label ambiguity and cancellation behavior were
identified statically and still require executable regression cases in the spike.
