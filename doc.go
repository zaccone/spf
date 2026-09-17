// Package spf evaluates Sender Policy Framework policies as defined by RFC 7208.
//
// CheckHostWithOptions accepts cancellation, a ContextResolver, and independent
// SMTP HELO/receiver identities. CheckHost uses the system resolver;
// CheckHostWithResolver preserves the legacy Resolver interface. Each call owns
// its evaluation state, including recursion, DNS budgets, and macro values.
//
// Inspect Result as well as error: None can accompany invalid input or a missing
// policy, and Fail normally has no error. Explanation text is untrusted policy
// data. Missing or invalid explanation text produces an empty string without
// changing Fail. Use errors.Is/errors.As to inspect wrapped DNS and context errors.
//
// The evaluator does not serialize Received-SPF or Authentication-Results
// headers, perform SMTP transactions, or decide whether to reject a message.
// The system resolver cannot query every legal utility label; select the configured server
// resolver for those names. Legacy resolvers cannot provide complete DNS
// accounting or PTR validation. See CONFORMANCE.md in the
// repository for the tested scope, evidence, and compatibility details.
package spf
