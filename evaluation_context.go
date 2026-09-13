package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// ContextResolver supplies DNS records before the evaluator performs address
// matching or MX/PTR fan-out. Implementations must honor ctx, return only the
// requested family (network is "ip4" or "ip6"), and join strings within each
// TXT RR, never across RRs. Names are absolute. Empty results or errors wrapping
// a net.DNSError with IsNotFound set denote a void logical lookup. Intermediate
// CNAME responses and transport retries are not exposed by this interface.
// Implementations must be safe for concurrent evaluations.
type ContextResolver interface {
	LookupTXTContext(ctx context.Context, name string) ([]string, error)
	LookupIPContext(ctx context.Context, network, name string) ([]net.IP, error)
	LookupMXContext(ctx context.Context, name string) ([]*net.MX, error)
	LookupAddrContext(ctx context.Context, addr string) ([]string, error)
}

// Options configures one evaluation. A nil Resolver selects DNSResolver.
// HELO, Receiver and Time are retained across recursion for macro support;
// their macro expansion is not yet implemented. Missing identities use
// "unknown" and a zero Time captures the time at entry.
type Options struct {
	Resolver ContextResolver
	HELO     string
	Receiver string
	Time     time.Time
}

const evaluationTimeout = 20 * time.Second

// ErrUnsupportedResolver indicates that a legacy resolver lacks a required
// capability. A custom resolver is never supplemented with public DNS.
var ErrUnsupportedResolver = errors.New("resolver lacks required DNS capability")

// CheckHostWithOptions evaluates SPF with a shared 20-second deadline (or an
// earlier caller deadline), ten DNS-causing terms, two void logical lookups,
// and at most ten MX address lookups per mechanism. Initial and explanation
// TXT lookups do not consume terms; explanation lookup errors leave Fail intact.
func CheckHostWithOptions(ctx context.Context, ip net.IP, domain, sender string, options Options) (Result, string, error) {
	if options.Resolver == nil {
		options.Resolver = &DNSResolver{}
	}
	return evaluate(ctx, ip, domain, sender, options, nil)
}

func evaluate(ctx context.Context, ip net.IP, domain, sender string, options Options, legacy Resolver) (Result, string, error) {
	if ip.To16() == nil {
		return None, "", ErrInvalidIP
	}
	if !validEvaluationDomain(domain) {
		return None, "", ErrInvalidDomain
	}
	ctx, cancel := context.WithTimeout(ctx, evaluationTimeout)
	defer cancel()
	if options.Time.IsZero() {
		options.Time = time.Now()
	}
	options.HELO = nonemptyString(options.HELO, "unknown")
	options.Receiver = nonemptyString(options.Receiver, "unknown")
	e := &evaluation{ctx: ctx, dns: options.Resolver, legacy: legacy, options: options, network: "ip6"}
	if ip.To4() != nil {
		e.network = "ip4"
	}
	addr := parseAddrSpec(sender, domain)
	return checkHost(ip, domain, addr.local+"@"+addr.domain, e, false)
}

// evaluation is also the private Resolver adapter used by the existing parser.
// One instance is shared through includes and redirects, never between checks.
type evaluation struct {
	ctx          context.Context
	dns          ContextResolver
	legacy       Resolver
	options      Options
	network      string
	terms, voids int
}

func (e *evaluation) useTerm() error {
	if err := e.ctx.Err(); err != nil {
		return err
	}
	if e.terms >= 10 {
		return fmt.Errorf("DNS-causing terms: %w", ErrDNSLimitExceeded)
	}
	e.terms++
	return nil
}

func (e *evaluation) answer(count int, err error) error {
	if ctxErr := e.ctx.Err(); ctxErr != nil {
		return errors.Join(ctxErr, err)
	}
	if err != nil && !dnsNotFound(err) {
		return err
	}
	if count == 0 || dnsNotFound(err) {
		e.voids++
		if e.voids > 2 {
			return fmt.Errorf("void DNS lookups: %w", ErrDNSLimitExceeded)
		}
	}
	return err
}

func (e *evaluation) LookupTXTStrict(name string) ([]string, error) {
	if err := e.ctx.Err(); err != nil {
		return nil, err
	}
	var records []string
	var err error
	if e.dns != nil {
		records, err = e.dns.LookupTXTContext(e.ctx, name)
	} else {
		records, err = e.legacy.LookupTXTStrict(name)
	}
	return records, e.answer(len(records), err)
}

// Explanation retrieval happens after the decision and consumes neither budget.
func (e *evaluation) LookupTXT(name string) ([]string, error) {
	if err := e.ctx.Err(); err != nil {
		return nil, err
	}
	if e.dns != nil {
		return e.dns.LookupTXTContext(e.ctx, name)
	}
	return e.legacy.LookupTXT(name)
}

func (e *evaluation) lookupIP(network, name string) ([]net.IP, error) {
	if err := e.ctx.Err(); err != nil {
		return nil, err
	}
	ips, err := e.dns.LookupIPContext(e.ctx, network, name)
	// Enforce the family contract even for a faulty custom implementation.
	filtered := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip.To16() != nil && (ip.To4() != nil) == (network == "ip4") {
			filtered = append(filtered, ip)
		}
	}
	return filtered, e.answer(len(filtered), err)
}

func (e *evaluation) Exists(name string) (bool, error) {
	if err := e.ctx.Err(); err != nil {
		return false, err
	}
	if e.dns == nil {
		found, err := e.legacy.Exists(name)
		// A false matcher result cannot generally reveal void answers. Exists is
		// the sole legacy address operation whose result reports record presence.
		count := 0
		if found {
			count = 1
		}
		return found, e.answer(count, err)
	}
	ips, err := e.lookupIP("ip4", name)
	return len(ips) > 0, err
}

func (e *evaluation) MatchIP(name string, matcher IPMatcherFunc) (bool, error) {
	if err := e.ctx.Err(); err != nil {
		return false, err
	}
	if e.dns == nil {
		found, err := e.legacy.MatchIP(name, matcher)
		if e.ctx.Err() != nil {
			return false, errors.Join(e.ctx.Err(), err)
		}
		return found, err
	}
	ips, err := e.lookupIP(e.network, name)
	if err != nil {
		return false, err
	}
	return matchAddresses(ips, matcher)
}

func (e *evaluation) MatchMX(name string, matcher IPMatcherFunc) (bool, error) {
	if err := e.ctx.Err(); err != nil {
		return false, err
	}
	if e.dns == nil {
		found, err := e.legacy.MatchMX(name, matcher)
		if e.ctx.Err() != nil {
			return false, errors.Join(e.ctx.Err(), err)
		}
		return found, err
	}
	mxs, err := e.dns.LookupMXContext(e.ctx, name)
	if err = e.answer(len(mxs), err); err != nil {
		return false, err
	}
	// Reject oversized RRsets before issuing any address lookup, even if the
	// first exchange would match. Count host lookups, not returned addresses.
	if len(mxs) > 10 {
		return false, fmt.Errorf("MX exchanges: %w", ErrDNSLimitExceeded)
	}
	for _, mx := range mxs {
		if mx == nil || mx.Host == "." {
			continue
		}
		found, err := e.MatchIP(NormalizeFQDN(mx.Host), matcher)
		if dnsNotFound(err) {
			continue
		}
		if found || err != nil {
			return found, err
		}
	}
	return false, nil
}

// validatedNames prepares bounded reverse/forward validation for step 6.
// Caller charges the DNS-causing term; extra PTR candidates are ignored.
// Ordinary DNS failures are ignored by PTR, but budgets and cancellation are not.
func (e *evaluation) validatedNames(ip net.IP) ([]string, error) {
	if e.dns == nil {
		return nil, ErrUnsupportedResolver
	}
	if err := e.ctx.Err(); err != nil {
		return nil, err
	}
	names, err := e.dns.LookupAddrContext(e.ctx, ip.String())
	if err = e.answer(len(names), err); err != nil {
		return nil, e.ptrError(err)
	}
	if len(names) > 10 {
		names = names[:10]
	}
	var valid []string
	for _, name := range names {
		if !validDNSDomain(name) {
			continue
		}
		ips, err := e.lookupIP(e.network, NormalizeFQDN(name))
		if err != nil {
			if fatal := e.ptrError(err); fatal != nil {
				return nil, fatal
			}
			continue
		}
		for _, candidate := range ips {
			if candidate.Equal(ip) {
				valid = append(valid, name)
				break
			}
		}
	}
	return valid, nil
}

func (e *evaluation) ptrError(err error) error {
	if e.ctx.Err() != nil {
		return e.ctx.Err()
	}
	if errors.Is(err, ErrDNSLimitExceeded) {
		return err
	}
	return nil
}
