# SPF baseline audit

Date: 2026-09-10. Source baseline: `76747b8658d9b8686ce812a0e3a2d3be904c980e`.

Read RFC 7208, all production Go files, all Go tests, README, Travis configuration, and BIND fixtures. Examined GitHub repository metadata, recent commits, open issues/PR descriptions, commit status, and Actions/check-run inventories. Local and remote master matched; working tree was initially clean. No production implementation was changed.

Protocol reference: https://datatracker.ietf.org/doc/html/rfc7208
Errata reviewed: https://www.rfc-editor.org/errata_search.php?rfc=7208

Verified errata 5436 and 6721 concern header/SMTP formatting, outside the current evaluator. Reported PTR errata remain reported, not approved normative replacements. PTR tests should follow the consistent prose/example about validated names within the target domain and document the conflicting bullet. RFC updates 7372, 8553, and 8616 are listed by the RFC Editor; full SMTPUTF8 expansion is a scope decision, not an implicit modernization requirement.

## Executed checks

- In the original checkout, `go test ./...` fails before compilation: no main module. Installed Go is 1.25.7.
- `gofmt -l *.go` lists `resolver_miekg.go`.
- A temporary copy of the unchanged Go files was given a module and DNS dependency v1.1.73, with x/net v0.57.0 and x/sys v0.47.0. This is an audit environment, not a reproduction of unpinned 2017 dependencies.
- On Go 1.25.7, `go test -race -cover -count=1 -timeout=60s ./...` failed on a race; coverage reported 86.9%. `go vet ./...` completed without diagnostics.
- The race connects the write to `p.IP` in `parser_test.go:549` with the callback read in `parser.go:245`, through `resolver_miekg.go:125,154,198`. A lookup returns before all callback work ends.
- A temporary observation test reproduced the results below. Its PASS means observations completed, not that the SPF behavior is correct.
- On Go 1.27.1, the unchanged source plus temporary observation test compiled and ran. The race-enabled suite reproduced the same TestParseMX race (test exit 1); vet passed (exit 0). Coverage was 88.1% with the additional diagnostic paths, not directly comparable with the 86.9% unmodified-test baseline.

Temporary work directory: `/tmp/spf-audit.3t3Vrt`. Cache/toolchain directories: `/tmp/spf-audit-build` and `/tmp/spf-audit-modcache`. No changes to the system Go installation. These temporary files may disappear; all material findings are recorded here.

## Reproduced behavior

Unless specified otherwise, client IP is 192.0.2.1, domain example.com, sender sender@example.com. A deterministic resolver supplies the indicated TXT record and returns ErrDNSTemperror for a/mx/exists.

| Input/operation | Observed | Required correction |
| --- | --- | --- |
| `v=spf1 a +all` | pass, nil error | Preserve DNS exception |
| `v=spf1 mx +all` | pass, nil error | Preserve DNS exception |
| `v=spf1 exists:other.example +all` | pass, nil error | Preserve DNS exception |
| `v=spf1 +all ip4:garbage` | pass, nil error | Validate malformed syntax before evaluating |
| `v=spf1 IP4:192.0.2.1 -all` | permerror | Accept mechanism case variations |
| `v=spf1 x-test=value +all` | permerror | Recognize and ignore valid unknown modifiers |
| `v=spf1 a/24 -all` | permerror | Support CIDR without explicit domain |
| `v=spf1 ip6:192.0.2.0/24 -all` | pass | Reject IPv4 network under ip6 |
| LimitedResolver with limit 10 | permits 9 calls | Fix boundary and separate SPF accounting |
| `isDomainName("localhost")` | true | Apply initial multi-label validation |
| `parseAddrSpec("example.com", "example.com")` | slice bounds panic `[:-1]` | Handle sender without @ |

## Code findings and proposed ownership

### Evaluation and syntax (steps 3–4)

- `parser.go:74–106` only returns on matches; a/mx errors and exists exceptions with false matches can be overwritten by later mechanisms or default handling.
- `parser.go:330–343` converts any redirect error to Permerror, including temporary failures, and discards the returned explanation.
- `parser.go:109–142` checks token categories but not full mechanism payload syntax before evaluation. Prefix matches can hide invalid later CIDRs or domain/macro payloads.
- `spf.go:174–207` is case-sensitive and accepts a tab after the version. `lexer.go:90–132` allows repeated/misplaced qualifiers and treats tab/newline as whitespace. `token.go` rejects unknown modifiers and treats `explanation` as an alias for `exp`.
- `lexer.go` does not split bare a/mx CIDR syntax. `parser.go:387–417` accepts malformed dual-CIDR forms; legacy tests intentionally expect some of them to pass.
- `parser.go:189–193` uses To16 to validate ip6 CIDR, which also accepts IPv4 addresses.
- `mail.go:23–32` slices at -1 for sender without @. Sender normalization is not performed once at the public entrypoint.
- `spf.go:214–259` is a historical copied hostname validator; it neither enforces multiple labels nor correctly distinguishes DNS wire/presentation length limits. Check provenance/license attribution while editing copied helpers.
- `parser.go:346–366` concatenates separate explanation TXT records, not just strings belonging to a single record. Explanation errors escape through the result error; includes perform child explanation work even though it is discarded.

### Resolver/resource model (steps 2 and 5)

- `resolver_limited.go:28–29,96–100` has off-by-one counters. LookupTXTStrict charges the initial record fetch; LookupTXT charges explanation retrieval. The abstraction counts method calls and matcher results instead of the required categories of work.
- MX limits count addresses returned to callbacks after requests were already launched, so they cannot bound DNS fan-out. There is no void-response counter.
- Both MatchMX implementations launch work for all MX records and may return while callbacks remain active. The Miekg resolver also launches both address families then serializes exchanges with a mutex, adding concurrency without the intended benefit.
- `resolver_std.go:76–82` uses LookupIP for exists, allowing AAAA-only matches. `resolver_miekg.go:104–113` treats any answer as existence, including CNAME-only responses.
- `resolver_miekg.go:116–128` invokes the matcher with nil for unrelated RR types. Address lookups ask for both families; parser mask selection relies on slice length rather than normalized address family.
- `resolver_std.go:27,51` detects missing hosts by English message text. Error causes are discarded. Modern structured error handling is preferable.
- No end-to-end context/deadline, explicit TCP retry for truncated UDP, or deliberate bounded CNAME-chain handling exists in the Miekg wrapper. Its default DNS client timeout is not a whole-evaluation deadline.
- Current exported Resolver cannot expose enough information for complete work accounting, family selection, cancellation, and PTR. Keep this API limitation visible during design.

### Incomplete protocol features (step 6)

- PTR is tokenized but absent from the evaluator switch; there is no reverse lookup operation in Resolver.
- Macros expand only for exists/exp. a/mx/include/redirect use their literal values.
- `%{p}` is deliberately omitted; c/r/t and uppercase escaping are absent. Unknown macro letters can fall through to empty output.
- `%{h}` incorrectly shares the current domain value, including during recursion; the public API cannot receive an independent HELO value.
- IPv6 `%{i}` uses colon formatting, only one delimiter is accepted, zero transformers are not rejected, and expanded domain length is not bounded by label removal.

### Test quality (steps 2–7)

- `main_test.go:25–31`: deferred server cleanup is bypassed by os.Exit. Setup errors are ignored in places; fixtures use the global DNS mux and prefix-based owner matching.
- `parser_test.go:1202` removes many-records instead of mixed-records. Tests change parser state while callbacks can still run.
- Redirect-loop coverage uses `redirect:` and `-all`, so it exercises syntax rejection rather than a genuine redirect cycle.
- Many tests call internal functions and discard errors; public-entrypoint assertions are needed. Split TXT tests check count but not concatenated content.
- Legacy expectations include incorrect CIDRs, single-label initial domains, off-by-one limits, and explanation error behavior. Revise with explicit rationale, not mechanically to match new code.

## Interpretation

The code is small enough to preserve its overall shape, but the correctness work is substantial enough for staged PRs. High coverage and vet do not detect the result-propagation problems. Start with a reproducible build and trustworthy test lifecycle, then fix behavior with focused tests. See MODERNIZATION_PLAN.md for approval state, sequencing, and resume instructions.
