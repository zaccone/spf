# DNS migration compatibility checks

**Decision (2026-09-15): defer the production backend switch.** The pinned
`codeberg.org/miekg/dns v0.6.109` loses DNS label boundaries in all nine
embedded-dot cases below. The neutral `ServerResolver` API can ship independently.

This directory is a separate Go module. SPF's root `go.mod` and production
imports remain unchanged. Run these checks explicitly; root `go test ./...`
does not traverse nested modules.

## Run

From the repository root, with Go 1.27:

```sh
# Diagnostics: logs BLOCKER findings without treating them as test failures.
go -C tools/dnscompat test -v -count=1 -timeout=60s ./...
go -C tools/dnscompat test -race -count=1 -timeout=60s ./...
go -C tools/dnscompat vet ./...

# Release gate: must pass before considering the Codeberg adapter for release.
go -C tools/dnscompat test -v -count=1 -timeout=60s -args -require-compatible
```

The final command currently **exits 1**, with nine failed label-boundary cases.
An ordinary diagnostic PASS means the probes ran successfully; it does **not**
mean the backend is compatible. The GitHub Actions workflow runs diagnostics
on changes here and offers a strict gate through its manual-run input.
Even a future strict PASS is necessary but insufficient: the full resolver
integration suite and remaining migration-plan gates must pass too.

## Findings

| Probe | Observed result |
| --- | --- |
| Embedded dot in question | Label boundary lost |
| Embedded dot in answer owner, plain/compressed | Label boundary lost |
| Embedded dot in CNAME target, plain/compressed | Label boundary lost |
| Embedded dot in MX target, plain/compressed | Label boundary lost |
| Embedded dot in PTR target, plain/compressed | Label boundary lost |
| Nine valid literal-name controls, incoming and outgoing | Passed |
| Oversized labels/names, truncated labels, invalid pointers | Rejected as expected |
| Cancel an in-flight native `ExchangeWithConn` read | Still blocked after 250 ms |
| Cancel with an owned connection and synchronized close callback | Read interrupted; joined cleanup passed |

For example, raw labels `[attacker.example, test]` and
`[attacker, example, test]` both decode as `attacker.example.test.` in v0.6.109.
The current library retains the embedded dot as `attacker\.example.test.` so
SPF can reject an unrepresentable MX/PTR name and avoid a forged suffix boundary.
The same ambiguity would affect question matching, owner filtering, and aliases.

Fixtures construct DNS bytes directly, independently of both encoders, and compare
both decoders. Compressed fixtures point backwards to an earlier answer owner.
A single question has no earlier name to reference, so it has only the plain case.
Controls cover punctuation, spaces, literal backslashes, the text `\032`, root,
63-byte labels, and a 255-byte wire name. Invalid-name controls are representative,
not a comprehensive DNS parser fuzz suite.

The cancellation probe uses `net.Pipe` and observes entry into the response read
before canceling. It is evidence about an in-flight read, not a full UDP/TCP
adapter implementation. The managed case demonstrates the close-and-join pattern
needed in the eventual adapter; transport framing, dial/write deadlines, and error
wrapping still need the existing integration tests when that adapter is built.

## Dependency cost

On Go 1.27.0 / macOS arm64, `go list -m all` reports 10 entries for the root
module and 49 for this comparison module (each count includes its main module).
The comparison module intentionally includes both DNS implementations; this is
not the exact graph of a future migrated SPF release.

`go list -deps` for the Codeberg root package and `dnsutil` includes packages from
`golang.org/x/crypto`, `golang.org/x/net`, and `golang.org/x/sys`. Its application
dependencies such as SQLite, Prometheus, and CertMagic are not in that package
closure. The root's current DNS package closure uses `golang.org/x/sys`.
Module-graph growth and linked-code growth are different measurements.

Reproduce with:

```sh
go list -m all
go -C tools/dnscompat list -m all
go -C tools/dnscompat list -deps codeberg.org/miekg/dns codeberg.org/miekg/dns/dnsutil
go -C tools/dnscompat mod why -m github.com/miekg/dns
```

## Unblocking the port

1. Prefer an upstream API that retains label boundaries, or a rejection policy
   that is compatible with SPF's existing behavior. Re-run these probes on an
   explicitly pinned candidate version.
2. If considering a local wire validator, review it as additional production DNS
   parsing code. Validate compressed names and relevant record fields using wire
   boundaries; decoded string checks cannot recover the missing information.
3. Preserve candidate selection semantics. The current resolver ignores PTR
   candidates after the first ten **before name conversion**. A packet-wide
   rejection of every embedded dot could reject an irrelevant eleventh candidate
   and regress the fix in `TestServerPTRCandidateLimit`. Likewise, unrelated
   records must not dictate whether usable answers succeed.
4. Then port the production client against the existing independent v1 test
   servers, preserve cancellation and validation, migrate fixtures, and complete
   the integration/race/fuzz/performance gates in
   [the migration plan](../../codex/DNS_MIGRATION_PLAN.md).

No upstream issue or message has been sent as part of this spike. No production
wire validator, dependency switch, or performance claim is included.
