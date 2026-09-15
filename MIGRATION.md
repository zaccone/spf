# Migration notes

These notes describe the modernization changes under review, not a tagged
release. The module path remains `github.com/zaccone/spf`. Go 1.27 or later is
required; use the latest Go 1.27 patch release. Existing exported entrypoints,
resolver constructors, and numeric Result values are retained.

## Choosing an entrypoint

| Need | Entry point |
| --- | --- |
| Existing simple integration using system DNS | `CheckHost` |
| Existing custom `Resolver` | `CheckHostWithResolver` |
| Cancellation, SMTP identities, explicit DNS source, full evaluator accounting | `CheckHostWithOptions` |

`CheckHost` now uses the context-capable system resolver and evaluation-wide
limits. `CheckHostWithResolver` selects that path if its resolver implements
`ContextResolver`; otherwise it uses the legacy adapter. A nil legacy resolver
returns `None` with `ErrUnsupportedResolver`. A nil `Options.Resolver` explicitly
selects the system resolver. A supplied custom resolver is never supplemented
with another DNS source.

[Runnable examples](example_test.go) demonstrate options and cancellation
without public DNS. In production, select an explicit DNS server with
`NewServerResolver("192.0.2.53:53")`, using your actual DNS server address.
This backend supports utility labels that Go's system resolver rejects.

## Resolver names

Use `NewServerResolver(addr)` to query a configured DNS server. It returns a
`*ServerResolver` that implements both `Resolver` and `ContextResolver`, so one
constructor serves both entrypoints. `DNSResolver` continues to use system DNS.

`MiekgDNSResolver` is a deprecated type alias for `ServerResolver`.
`NewMiekgDNSResolver` and `NewMiekgDNSResolverContext` remain available with their
original signatures; both delegate to `NewServerResolver`. Existing type
assertions continue to work, but diagnostic output such as `%T` and reflection
now reports the concrete name `ServerResolver`. Invalid constructor addresses
return a nil resolver and an error, including through the deprecated interfaces.
The underlying DNS dependency is unchanged in this API migration.

## Implementing ContextResolver

Provide TXT, family-specific IP (`ip4` or `ip6`), MX, and reverse lookups. Names
are absolute, literal dot-separated ASCII labels, including punctuation/spaces;
backslashes are literal bytes rather than DNS presentation escapes. TXT returns
one string per RR, joining its component strings. MX and PTR return candidates
before forward validation. Empty results or wrapped `*net.DNSError` values with
`IsNotFound` set denote missing requested answers. Honor the context and finish
all work before returning; the resolver must be safe for concurrent checks.

Each evaluation shares a 20-second deadline, shortened by the caller's deadline,
through recursion. Ten DNS-causing terms and two void logical answers are allowed.
The initial TXT lookup is outside the term limit; explanation work cannot change
a Fail decision. MX fan-out is bounded before address dispatch; PTR examines at
most ten candidates. The p macro uses shared accounting and per-evaluation reverse
validation. These are logical limits, not counts of retransmitted DNS packets.

`LimitedResolver` remains a legacy method/callback limiter. Its configured limit
is now inclusive; it is not full SPF accounting. Wrapping a context-capable
resolver in it selects the legacy path and loses the newer capabilities.

## Result and error handling

Inspect the SPF `Result` first and retain `error` for diagnosis. A valid Fail,
Softfail, or Neutral is normally not a Go error. Missing policy and invalid
input can return None with a cause. Invalid IP input returns `ErrInvalidIP`;
invalid initial domains return `ErrInvalidDomain`, before any DNS work.

Use `errors.Is` and `errors.As`, rather than equality against wrapped errors.
DNS transport causes and cancellation/deadline causes are retained. Limit errors
produce Permerror; temporary DNS/cancellation errors produce Temperror. Missing
records are interpreted according to their mechanism/recursive context.

Complete SPF syntax is validated before evaluation, so an early match no longer
conceals a malformed trailing term. Include and redirect results/errors propagate
correctly. Includes suppress child explanations; redirect preserves the selected
policy's explanation. Invalid/unavailable explanation text leaves Fail unchanged
with an empty explanation. Treat returned explanation text as untrusted data.

## Identity and macro behavior

Normalize SMTP input before calling the library: pass the identity domain
separately from the envelope sender. An empty sender becomes `postmaster@domain`;
a bare HELO identity receives the `postmaster` local-part. Pass actual HELO and
receiver values in `Options`; absent values expand to `unknown`. A zero `Time`
captures the evaluation time once, and explicit `Time` enables deterministic tests.

Sender/HELO/receiver/time remain unchanged through recursion; the d macro follows
the currently evaluated policy domain. Every supported domain-spec is expanded.
IPv6 nibble form, uppercase URL escaping, multiple delimiters, PTR, and the p/c/r/t
macros are implemented; c/r/t are explanation-text only.

DNS labels are broader than hostnames: expanded names can contain punctuation
and spaces. Names over 253 characters are shortened by removing complete labels
from the left. Empty/oversized labels and non-printable/non-ASCII output produce
Permerror during evaluation, or empty explanation fallback. Initial identity
domains still use the stricter hostname checks. See [conformance scope](CONFORMANCE.md)
for backend and binary-label limits.
