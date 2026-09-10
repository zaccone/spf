# SPF modernization plan

Status: step 1 implemented and verified; stop here pending owner review. Steps 2–7 are not authorized to proceed.
Updated: 2026-09-10 (Europe/Warsaw).
Repository: https://github.com/zaccone/spf
Reviewed baseline: `76747b8658d9b8686ce812a0e3a2d3be904c980e`, local and remote `master`.

## Scope and working agreement

Modernize conservatively, prioritizing correctness, readable Go, bounded resource use, and reproducible tests. Keep the project's own lexer, parser, and macro implementation. Retain `github.com/miekg/dns` for DNS transport; do not replace the SPF engine with a library. Avoid unrelated rewrites, new frameworks, caching systems, or performance work without evidence.

The owner approved starting step 1 and explicitly instructed stopping after it. Deliver this diff for review; do not begin step 2 without a new instruction. Do not automatically merge. Preserve existing exported functions and numeric Result values where practical. Any incompatible API change needs an explicit proposal.

## Recommended Go target

Use Go 1.27, initially verifying with 1.27.1. The official release history lists 1.27.0 on August 19, 2026 and 1.27.1 on September 1, 2026. The installed system compiler is 1.25.7; a temporary 1.27.1 toolchain was downloaded for the audit without replacing it.

Recommended default: `go 1.27.0` as the module minimum, latest patched `1.27.x` in CI. If existing consumers need Go 1.26, choose `go 1.26.0` and test both 1.26.x and 1.27.x instead. There is no identified need for novel Go 1.27 syntax.

Source: https://go.dev/doc/devel/release

## Proposed progression

Each numbered step is a review boundary. Split further when a diff becomes difficult to review. Every behavior fix includes a reproducer that fails beforehand and passes afterward. A toolchain upgrade alone is not evidence of RFC conformance.

### 1. Reproducible build

Implemented branch: `codex/go127-modules`.

Completed: Go 1.27.0 module minimum; DNS v1.1.73 with x/net v0.57.0 and x/sys v0.47.0; generated checksums; resolver import grouping/gofmt; README build and test instructions. No SPF evaluation or API changes. Keyed-literal conversion was unnecessary for this focused build diff.

Validation on Go 1.27.1, macOS arm64: `go mod download`, `go mod verify`, `go build ./...`, `go test -count=1 -timeout=60s ./...`, `go vet ./...`, `go mod tidy -diff`, gofmt, and `git diff --check` passed. `govulncheck` v1.8.0 reported no vulnerabilities. The known race from the baseline audit remains; race testing was not repeated for formatting/module-only edits. CI migration has not started.

- Add `go.mod` with module path `github.com/zaccone/spf`, plus `go.sum`.
- Pin the existing DNS dependency and transitive versions after compatibility/vulnerability review. DNS v1.1.73 was selected after the checks recorded above.
- Apply gofmt and fix import grouping; use keyed struct literals where they improve maintainability.
- Document build/test commands and the supported Go floor. Avoid changing evaluation semantics.

Acceptance: build, ordinary tests, and vet on Go 1.27.1; reproducible dependency resolution. Record the known race rather than claiming a clean race baseline. No CI green claim until step 2 resolves it.

### 2. Reliable test lifecycle and GitHub Actions

Proposed branch: `codex/ci-and-test-lifecycle`.

- Fix outstanding resolver callbacks after a method returns. Prefer straightforward sequential/bounded lookup processing over the current goroutine fan-out; verify matcher/error semantics and regression coverage.
- Give DNS tests owned fixtures, exact question matching, reliable startup, error reporting, and cleanup that executes before `os.Exit`. Fix the wrong handler removal in `TestSelectingRecord`.
- Keep tests independent of public DNS and system resolver configuration. Add loopback fixtures for the standard resolver when needed in step 5.
- Add Actions for pull requests and pushes to `master`, plus manual dispatch. Use Go 1.27.x, Linux/macOS/Windows ordinary tests, and Linux race tests. Include vet, gofmt checking, and module consistency checks.
- Use read-only workflow permissions, bounded job/test timeouts, dependency caching, and pinned action revisions with version comments. Use `pull_request`, not privileged execution of fork code.
- Replace the Travis badge/config once the new workflow is established; keep any temporary dual-run migration explicit.

Acceptance: ordinary tests on all three operating systems; race tests pass; shutdown completes and callbacks do not outlive the operation. Do not suppress races or disable failing tests to get green CI.

### 3. Complete syntax validation in our lexer/parser

Proposed branch: `codex/spf-syntax-validation`.

- Separate syntax validation from evaluation within the existing implementation. A valid early match must not conceal malformed syntax elsewhere.
- Correct version selection, case handling, whitespace, qualifiers, unknown modifiers, domain-spec syntax, and modifier cardinality.
- Support bare `a/24` and `mx//64`; fix dual CIDR grammar, empty/leading-zero masks, and IP-family validation.
- Add public-entrypoint tests alongside lexer/parser unit tests. Replace incorrect legacy expectations with documented corrections.

Acceptance: table-driven valid/invalid records, including malformed tails, unknown modifiers, mixed case, IPv4/IPv6 boundaries, and RFC examples. Fuzz lexer/parser for termination and panic freedom.

### 4. Evaluation results and explanations

Proposed branch: `codex/spf-evaluation-results`.

- Propagate resolver failures even when the mechanism did not match. Distinguish temporary errors, missing records, and resource limits consistently; use `errors.Is`/`errors.As` and preserve causes.
- Correct redirect error propagation and carry the redirected explanation to the caller.
- Suppress child `exp` lookup during include evaluation; handle explanation RR cardinality and invalid/unavailable text without replacing the SPF decision.
- Fix sender normalization and bare-sender panic; validate initial domains and invalid IP arguments. Keep normalized sender identity unchanged during recursion.
- Add error unwrapping to `SyntaxError`; consider exporting the existing multiple-record sentinel as an additive change, taking open PR #33 into account.

Acceptance: deterministic error injection across a/mx/exists/include/redirect; full include result table; explanation provenance and fallback; empty sender and bare HELO cases.

### 5. DNS interface, budgets, and cancellation

Proposed branch: `codex/dns-budgets-and-context`.

- Introduce per-evaluation state shared by recursive checks. Count evaluated DNS-causing terms separately from DNS transport calls; initial TXT and explanation lookups must not consume the term budget.
- Fix the LimitedResolver off-by-one behavior, but do not confuse that wrapper with complete SPF accounting.
- Track void responses and enforce MX/PTR work limits before dispatch, rather than counting returned IP matcher callbacks.
- Select the client address family for address matching; make `exists` require an A answer, including CNAME-only and AAAA-only negative cases.
- Add context/deadline-aware DNS operations and bounded CNAME/TCP-fallback handling to both built-in resolvers. Use structured DNS errors instead of matching English messages.

API review checkpoint: the current Resolver hides DNS answer details, has no PTR operation or address-family/context input, and the entrypoint has no separate HELO/receiver identity. Propose an additive evaluation API/options type and DNS interface, keeping legacy entrypoints and Resolver compatibility explicitly documented. Never silently use public DNS to fill a custom resolver's missing capabilities. Do not claim full conformance for a legacy adapter that cannot expose the required information. Present exact signatures before this diff is implemented.

Acceptance: 10/11 term boundaries, 2/3 void boundaries, recursive/shared budgets, cycles, MX/PTR fan-out limits, cancellation, same-family queries, transport failures, NXDOMAIN/NODATA, and multi-string TXT answers. Check both resolver implementations with controlled local DNS.

### 6. Finish macros and PTR

Proposed branch: `codex/macros-and-ptr`.

- Consolidate repeated macro handling while retaining the handwritten scanner.
- Expand every supported domain-spec, not just exists/exp.
- Implement IPv6 nibble expansion, uppercase escaping, multiple delimiters, transformer validation, and expanded-name length handling.
- Implement PTR and `%{p}` validation with bounded work and domain-label boundaries.
- Carry actual HELO and receiver information through recursion; implement explanation-only macros with deterministic time input for tests.

Acceptance: RFC macro examples for both IP families, reverse/forward DNS validation and errors, HELO distinct from sender domain, uppercase and malformed macros, and fuzzing with no panic/unbounded work.

### 7. Conformance evidence and release documentation

Proposed branch: `codex/conformance-and-docs`.

- Incorporate a pinned, license-reviewed selection of the pySPF test corpus, expanding to the full applicable corpus. Keep it test-only; the RFC and reviewed errata take precedence over conflicting corpus expectations.
- Maintain a readable conformance matrix; any excluded case needs an explicit reason. Do not advertise stability merely from a coverage percentage.
- Update examples, resolver documentation, migration notes, pkg.go.dev links, known limitations, and supported Go versions.
- Add bounded fuzz smoke tests and dependency vulnerability checks where they remain maintainable. Record versions and outcomes.

Acceptance: all agreed gates pass; applicable corpus cases accounted for; no unexplained exclusions, races, or known panic paths. Owner reviews release readiness; publishing a release is a separate action.

## CI strategy

Recommend GitHub Actions. The repository already lives on GitHub, needs only Go and local DNS fixtures, and has no special Travis integration worth preserving. GitHub's Go workflow supports version setup, caching, build/test jobs, and PR reporting directly.

The current `.travis.yml` targets Go 1.7, 1.8, and development `master`, installs an unpinned dependency with `go get`, and runs tests/vet without race detection. The README badge points to travis-ci.org. Travis documents that `.org` was disabled in June 2021. Editing the Go version or badge alone cannot restore that service.

Keeping Travis is possible by migrating/activating on travis-ci.com, confirming the account's build access, and modernizing the build/dependency configuration. No Travis account settings or historical build logs were available in this audit, so its exact account-side state is unverified. Actions is the simpler recommendation here.

GitHub API checks on September 10 found zero Actions workflows, zero check runs for baseline HEAD, and no commit status entries returned by the connector. This does not establish that the project never built historically.

After the replacement workflow passes, update any required status checks that still refer to Travis. Inspect settings first and present that concrete configuration change separately; do not leave merges blocked on a retired check.

Sources:

- https://docs.travis-ci.com/user/migrate/open-source-repository-migration/
- https://docs.github.com/en/actions/tutorials/build-and-test-code/go
- https://api.github.com/repos/zaccone/spf/actions/workflows

## Existing GitHub work to preserve

Open items reviewed: #11 corpus tests; #13 macro duplication; #14 DNS fixtures; #17 DNS helper reuse; #21 resolver docs; #24 race testing; #28 coverage; #32 Windows split TXT behavior; PR #29 historical Windows DNS error handling; PR #33 exported multiple-record error.

Modern structured DNS errors should supersede the old platform-specific string approach in #29. Reproduce #32 on the selected modern toolchain rather than assuming the historical Go bug persists. Avoid duplicating or silently superseding contributors' work; reference the relevant items in future PRs. No issues/comments/PRs were changed during this review.

## Resume checklist

1. Read this file and `MODERNIZATION_AUDIT.md`.
2. Inspect `git status`, branch, and remote HEAD; preserve any new owner changes.
3. Read the latest task messages for approval and constraints. Current state is **step 1 complete; stopped for review**.
4. Do not begin step 2 until explicitly instructed. Follow applicable repository instructions and the PR skill when creating a PR.
5. Update these documents after each diff with commit/PR links, checks, decisions, and next action.

The files persist on disk when the app closes. No automatic 20:30 wakeup or background schedule was created. Reopen this task and send a message, or start a task that reads these files. Temporary audit files under `/tmp` are disposable and are not required to resume.
