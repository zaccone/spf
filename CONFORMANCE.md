# Conformance evidence

Status: step 7 working-tree implementation, verified locally on 2026-09-14.
This document describes tested behavior, not a declaration of complete RFC
conformance or release stability. Hosted CI must run on the published change.

## Corpus scope and results

The pinned upstream is [pySPF commit 1042e9e15dd29047dc9b0a1bb77437e2fd81e775](https://github.com/sdgathman/pyspf/tree/1042e9e15dd29047dc9b0a1bb77437e2fd81e775/test).
The full RFC 7208 suite and development suite are vendored, with their licenses,
and converted to JSON for dependency-free Go tests. See [provenance and regeneration](testdata/pyspf/README.md).

| Source | Source cases | Evaluated | Excluded |
| --- | ---: | ---: | ---: |
| `rfc7208-tests.yml` | 203 | 203 | 0 |
| `test.yml` | 16 | 14 | 2 |
| Total | 219 | 217 | 2 |

All 217 applicable result assertions pass. The 22 RFC explanation assertions
also pass with the documented adaptations below. Every source case and its
assertion scope is listed in the [case inventory](testdata/pyspf/CASES.md).
Tests reject stale dispositions, duplicate case IDs, changed fixture checksums,
and unexpected case counts. No failing SPF case is silently skipped.

| Area in RFC suite | Cases | Evidence |
| --- | ---: | --- |
| Initial processing | 16 | Input boundaries and identity normalization |
| Record lookup / selection | 17 | Missing records, timeouts, versions, multiple TXT RRs |
| Record evaluation | 12 | Qualifiers, modifiers, invalid domains |
| `all` | 5 | Syntax and qualifiers |
| `ptr` | 8 | Reverse validation, family and label matching, CNAME failures |
| `a` | 29 | CIDRs, address families, literal domain-specs |
| `include` | 9 | Recursive results and syntax |
| `mx` | 21 | Exchanges, address families, CIDRs |
| `exists` | 7 | A-only existence checks and macros |
| `ip4` / `ip6` | 18 | Address syntax and networks |
| Explanation and modifiers | 24 | Cardinality, redirect, fallback, syntax |
| Macros | 24 | Transformations, IPv6, escaping, names and identities |
| Processing limits | 11 | Recursive term limits, MX/PTR limits, void limits |
| Implementation regressions | 2 | IPv6 MX and CNAME aliasing |

## Explicit adaptations and exclusions

The machine-readable [dispositions](testdata/pyspf/dispositions.json) are used by
the runner, rather than maintained as a disconnected list of ignored tests.

- `test/default-modifier` and `test/default-modifier-harsh` exercise pySPF lax/harsh
  modes and its non-SPF `ambiguous` result. Those two cases are excluded. The RFC
  suite separately tests that obsolete `default=` is ignored.
- Three development cases contain exact Received-SPF header strings. Their SPF
  results are tested; header serialization is outside this library's API.
- `rfc7208-tests/bytes-bug` permits ignoring pySPF's `strict=2` flag. Its SPF
  result remains asserted.
- `rfc7208-tests/v-macro-ip6` expects uppercase IPv6 nibbles inside explanation
  text. Our implementation uses lowercase hexadecimal. Only that exact
  explanation spelling is adapted; the result and all other bytes are checked.
- The upstream driver's configurable `DEFAULT` explanation maps to this API's
  documented empty fallback. Other explanation strings are compared exactly.
- Where the suite lists multiple acceptable results, the runner accepts that
  list without enforcing the upstream author's preference.

Upstream `rfc4408-tests.yml` (191 cases) is not imported: it is the superseded
RFC 4408 suite, including obsolete type-99 selection behavior. Its maintained
RFC 7208 successor is imported in full. `doctest.yml` contains DNS data but no
standalone cases; Python implementation doctests are outside this Go API.

[RFC 7208](https://www.rfc-editor.org/rfc/rfc7208.html) and
[reviewed errata](https://www.rfc-editor.org/errata_search.php?rfc=7208) take
precedence over corpus preferences. The two verified errata concern SMTP/header
formatting, outside this evaluator. PTR matching follows section 5.5's prose and
example: a validated name equals the target or is below it on a label boundary.
The later reversed bullet is not used to authorize a parent domain.

## Runner and transport boundaries

`TestConformanceCorpus` calls `CheckHostWithOptions` with a deterministic,
in-memory `ContextResolver`. No public DNS is used. Each scenario owns its zone;
lookup names are case-insensitive and absolute. The fixture supports A, AAAA,
MX, PTR, CNAME, split TXT strings, empty answers, and timeout markers. CNAME
cycles/hops are bounded. Following the source fixture convention, `SPF` records
are shorthand for TXT only when that owner has no explicit TXT entry; `TXT:
NONE` disables that shorthand. A TIMEOUT marker after a matching record does
not invalidate that answer. Missing `error.*` names simulate DNS timeouts.

These are logical-answer tests, not wire-protocol or system-DNS conformance.
Separate tests exercise both built-in resolvers on loopback UDP/TCP: cancellation,
truncation, errors, family selection, split TXT, and PTR. The configured server
backend also has alias-bound and literal-label tests. Corpus-driven fixes permit DNS labels
containing punctuation/spaces, preserve literal backslashes on the wire, and
prevent re-expansion of inherited policy names in recursive checks.

Known limits remain explicit:

- Go's system resolver rejects some legal utility labels, such as spaces or
  colons, before DNS dispatch. `TestSystemResolverUtilityLabelLimit` records this
  restriction. Use `NewServerResolver` for these policies. Passing the
  logical corpus is not a claim that the default system backend supports them.
- Initial SMTP identity domains retain ASCII hostname checks. SMTPUTF8/IDNA
  conversion and arbitrary binary DNS labels are not implemented.
- The literal name interface uses dots as label separators. Returned MX/PTR
  names with a dot embedded inside one wire label are rejected to prevent a
  false PTR subdomain match.
- Legacy-only resolvers cannot expose full void/MX/PTR accounting, select the
  address family, or enforce cancellation inside a custom call. PTR is explicitly
  unsupported and the p macro falls back to `unknown` on that path.
- System alias processing depends on the recursive server supplying complete
  answers. Native split-DNS behavior can differ from the forced Go resolver.
- Received-SPF / Authentication-Results formatting, SMTP policy decisions,
  DNSSEC validation, and release publication are outside the evaluator.

## Validation and release gate

The final local ordinary/race suites, executable examples, build, vet, module
verification/tidy, formatting, corpus regeneration, and actionlint v1.7.12 passed.
New corpus, recursion, and wire-label regressions fail against step 6 commit
`adc8c10` and pass with this diff.

| Bounded fuzz target | Executions | Outcome |
| --- | ---: | --- |
| `FuzzLexer` | 327,193 | Pass |
| `FuzzParserSyntax` | 288,330 | Pass |
| `FuzzMacroExpansion` | 341,348 | Pass |
| `FuzzStep6Evaluation` | 325,955 | Pass |
| `FuzzDNSLiteralNames` | 220,513 | Pass |

Local validation uses Go 1.27.1 on macOS arm64. Ordinary/race suites, examples,
build, vet, module verification/tidy, formatting, fixture regeneration, and
bounded fuzz targets are required. `govulncheck` v1.8.0 queries the Go vulnerability
database; the local scan found no reachable vulnerabilities. That observation
is dated and must be refreshed before a release.

GitHub Actions runs tests on Linux, macOS, and Windows, plus Linux race/quality,
a pinned vulnerability scanner, and five bounded fuzz smoke targets. Each fuzz
run is limited to 10 seconds with two workers and a 60-second process timeout.
The scan fails on findings or database/network errors; failures are not hidden.

Before an owner approves a release: obtain green hosted CI for the actual final
commit, review these scope limits and migration notes, ensure the intended
branch stack has reached the release base, refresh vulnerability results, and
review the public API/versioning decision. Corpus counts or coverage percentages
alone do not establish release readiness. Publishing a release is a separate
owner-authorized action.
