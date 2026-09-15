# DNS v2 migration execution plan

This document tracks the remaining move from `github.com/miekg/dns` to
`codeberg.org/miekg/dns`. The dependency-neutral `ServerResolver` API and the
isolated compatibility probes are already on `master`. Production remains on
`github.com/miekg/dns v1.1.73` until the compatibility gate passes.

## Current decision

**Status: blocked before the production adapter.** In Codeberg DNS v0.6.109,
distinct wire names such as labels `[attacker.example, test]` and
`[attacker, example, test]` both decode to `attacker.example.test.`. This affects
questions, record owners, and CNAME, MX, and PTR targets, including compressed
names. See [`tools/dnscompat`](tools/dnscompat/README.md) for executable evidence.

The production switch must also retain the current connection close-and-join
pattern because canceling the context passed to `ExchangeWithConn` does not by
itself interrupt an in-flight read.

## Delivery map

Each checked item is independently reviewable. Do not combine the production
adapter and old-dependency removal into one change.

### 1. Resolve the upstream name representation

- [x] Reproduce the collision with raw DNS packets independent of both encoders.
- [x] Cover question, owner, CNAME, MX, and PTR names, with compression cases.
- [x] Search the upstream tracker for an existing report.
- [ ] File a concise upstream issue with the raw-wire reproducer and the SPF use
  case. Link it below.
- [ ] Agree with upstream on a representation or API that lets a caller preserve
  label boundaries for selected records. A packet-wide rejection is insufficient:
  SPF must ignore PTR candidates after the first ten and unrelated answer records.
- [ ] Pin an upstream release or commit containing the resolution.
- [ ] Update `tools/dnscompat` and make `-require-compatible` pass without
  weakening or deleting a boundary case.

Upstream issue: pending.

Exit criterion: all strict compatibility probes pass, and the chosen behavior
preserves selection-before-conversion semantics for PTR and unrelated records.

### 2. Port the production client

- [ ] Add the reviewed Codeberg version to the root module while temporarily
  retaining v1 for independent test servers.
- [ ] Convert message questions and record headers to the v2 API.
- [ ] Convert A/AAAA `netip.Addr` values to owned `net.IP` values at the public
  boundary; preserve requested-family behavior.
- [ ] Port TXT, MX, PTR, and CNAME access through the v2 RDATA structures.
- [ ] Preserve response ID/QR, opcode, one-question, name/type/class, IN-class
  owner, CNAME conflict/cycle, and ten-hop validation.
- [ ] Preserve UDP truncation retry over TCP and rejection of truncated TCP.
- [ ] Dial each query with context, own its connection, close it through
  `context.AfterFunc`, and join the callback before returning.
- [ ] Preserve NXDOMAIN/NODATA versus temporary errors and wrapped causes.
- [ ] Audit `Msg.Data` ownership and create a fresh request for TCP fallback.

Exit criterion: all current resolver tests pass while v1 servers exercise the
v2 client, including cancellation, malformed responses, aliases, and TCP fallback.

### 3. Port fixtures and remove v1

- [ ] Port shared DNS test helpers to v2 handlers, message builders, RDATA, and
  server lifecycle APIs.
- [ ] Keep raw-wire boundary fixtures independent of the v2 encoder.
- [ ] Port the remaining test imports in small batches.
- [ ] Remove every root-module import and requirement for `github.com/miekg/dns`.
- [ ] Rename remaining implementation-specific test labels and comments.
- [ ] Run `go mod tidy` and explain any indirect appearance of v1 through the
  Codeberg module separately from code linked into SPF.

Exit criterion: `rg 'github.com/miekg/dns' --glob '*.go'` is empty outside the
isolated comparison module, and the root dependency graph is tidy and reviewed.

### 4. Validate and release

- [ ] Run build, unit/integration tests, race detector, vet, formatting, module
  verification/tidy, vulnerability scan, service smoke test, and bounded fuzzing.
- [ ] Pass Linux, macOS, and Windows CI.
- [ ] Compare v1/v2 TXT, A/AAAA, CNAME, and TCP fallback behavior on a fixed
  dataset; investigate every SPF decision change.
- [ ] Measure resolver latency, allocations, concurrent checks, and `spfd` binary
  size. Record results without assuming upstream server benchmarks apply here.
- [ ] Update README, migration notes, dependency references, and license notices.
- [ ] Trial `spfd` in its default non-enforcing mode before enabling enforcement.
- [ ] Merge only with the strict compatibility gate enabled and passing.

Rollback is a normal backend revert: the public `ServerResolver` API remains
stable, so callers do not need to change when the implementation changes back.

## Planned pull requests

1. **Upstream resolution and gate:** this execution plan, upstream issue link,
   candidate pin, and a passing strict compatibility suite.
2. **Production adapter:** v2 client behind `ServerResolver`, with v1 test servers
   retained for independent interoperability coverage.
3. **Fixture and dependency cleanup:** v2 test servers and removal of the direct
   v1 dependency.
4. **Release evidence:** benchmarks, decision comparison, documentation, and
   rollout record. This may be folded into PR 3 if it remains small.

If upstream declines to expose sufficient information, stop after PR 1 and make
an explicit maintain-or-local-parser decision. A local validator is acceptable
only after review as security-sensitive DNS parsing code and must preserve record
selection semantics; decoded strings cannot recover boundaries already lost.
