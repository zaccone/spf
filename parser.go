package spf

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func matchingResult(qualifier tokenType) (Result, error) {
	switch qualifier {
	case qPlus:
		return Pass, nil
	case qMinus:
		return Fail, nil
	case qQuestionMark:
		return Neutral, nil
	case qTilde:
		return Softfail, nil
	default:
		return internalError, fmt.Errorf("invalid qualifier (%d)", qualifier) // TODO it's fishy; lexer must reject it before
	}
}

// SyntaxError represents parsing error, it holds reference to faulty token
// as well as error describing fault
type SyntaxError struct {
	token *token
	err   error
}

func (e SyntaxError) Error() string {
	return fmt.Sprintf("parse error for token %v: %v", e.token, e.err.Error())
}

// Unwrap exposes the underlying cause to errors.Is and errors.As.
func (e SyntaxError) Unwrap() error { return e.err }

// parser represents parsing structure. It keeps all arguments provided by top
// level CheckHost method as well as tokenized terms from TXT RR. One should
// call parser.Parse() for a proper SPF evaluation.
type parser struct {
	Sender              string
	Domain              string
	IP                  net.IP
	Query               string
	Mechanisms          []*token
	Explanation         *token
	Redirect            *token
	resolver            Resolver
	suppressExplanation bool
}

// newParser creates new Parser objects and returns its reference.
// It accepts CheckHost() parameters as well as SPF query (fetched from TXT RR
// during initial DNS lookup.
func newParser(sender, domain string, ip net.IP, query string, resolver Resolver) *parser {
	return &parser{Sender: sender, Domain: domain, IP: ip, Query: query, Mechanisms: make([]*token, 0, 10), resolver: resolver}
}

// parse aggregates all steps required for SPF evaluation.
// After lexing and tokenizing step it sorts tokens (and returns Permerror if
// there is any syntax error) and starts evaluating
// each token (from left to right). Once a token matches parse stops and
// returns matched result.
func (p *parser) parse() (Result, string, error) {
	tokens := lex(p.Query)
	if err := validateRecord(p.Query, tokens); err != nil {
		return Permerror, "", err
	}

	if err := p.sortTokens(tokens); err != nil {
		return Permerror, "", err
	}

	for _, token := range p.Mechanisms {
		if e, ok := p.resolver.(*evaluation); ok {
			if err := e.ctx.Err(); err != nil {
				return Temperror, "", err
			}
			switch token.mechanism {
			case tA, tMX, tInclude, tExists, tPTR:
				if err := e.useTerm(); err != nil {
					return dnsErrorResult(err), "", err
				}
			}
		}
		result := Neutral
		var matches bool
		var err error
		switch token.mechanism {
		case tVersion:
			matches, result, err = p.parseVersion(token)
		case tAll:
			matches, result, err = p.parseAll(token)
		case tA:
			matches, result, err = p.parseA(token)
		case tIP4:
			matches, result, err = p.parseIP4(token)
		case tIP6:
			matches, result, err = p.parseIP6(token)
		case tMX:
			matches, result, err = p.parseMX(token)
		case tInclude:
			matches, result, err = p.parseInclude(token)
		case tExists:
			matches, result, err = p.parseExists(token)
		case tPTR:
			matches, result, err = p.parsePTR(token)
		}

		if err != nil {
			return result, "", err
		}
		if matches {
			if result == Fail && p.Explanation != nil && !p.suppressExplanation {
				return result, p.handleExplanation(), nil
			}
			return result, "", err
		}

	}

	return p.handleRedirect(Neutral)
}

func (p *parser) sortTokens(tokens []*token) error {
	all := false
	for _, token := range tokens {
		if token.mechanism.isErr() {
			return fmt.Errorf("syntax error for token: %v", token.value)
		} else if token.mechanism.isMechanism() && !all {
			p.Mechanisms = append(p.Mechanisms, token)

			if token.mechanism == tAll {
				all = true
			}
		} else {

			if token.mechanism == tRedirect {
				if p.Redirect == nil {
					p.Redirect = token
				} else {
					return errors.New(`too many "redirect"`)
				}
			} else if token.mechanism == tExp {
				if p.Explanation == nil {
					p.Explanation = token
				} else {
					return errors.New(`too many "exp"`)
				}
			}
		}
	}

	if all {
		p.Redirect = nil
	}

	return nil
}

func nonemptyString(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (p *parser) parseVersion(t *token) (bool, Result, error) {
	if strings.EqualFold(t.value, "spf1") {
		return false, None, nil
	}
	return true, Permerror, SyntaxError{t,
		fmt.Errorf("invalid spf qualifier: %v", t.value)}
}

func (p *parser) parseAll(t *token) (bool, Result, error) {
	result, err := matchingResult(t.qualifier)
	if err != nil {
		return true, Permerror, SyntaxError{t, err}
	}
	return true, result, nil

}

func (p *parser) parseIP4(t *token) (bool, Result, error) {
	result, _ := matchingResult(t.qualifier)
	if !validIPNetwork(t.value, false) {
		return true, Permerror, SyntaxError{t, errors.New("invalid IPv4 network")}
	}
	if p.IP.To4() == nil {
		return false, result, nil
	}
	if _, network, err := net.ParseCIDR(t.value); err == nil {
		return network.Contains(p.IP), result, nil
	}
	return net.ParseIP(t.value).Equal(p.IP), result, nil
}

func (p *parser) parseIP6(t *token) (bool, Result, error) {
	result, _ := matchingResult(t.qualifier)
	if !validIPNetwork(t.value, true) {
		return true, Permerror, SyntaxError{t, errors.New("invalid IPv6 network")}
	}
	if p.IP.To4() != nil {
		return false, result, nil
	}
	if _, network, err := net.ParseCIDR(t.value); err == nil {
		return network.Contains(p.IP), result, nil
	}
	return net.ParseIP(t.value).Equal(p.IP), result, nil
}

func (p *parser) parseA(t *token) (bool, Result, error) {
	host, ip4Mask, ip6Mask, err := splitDomainDualCIDR(t.value)
	if err != nil {
		return true, Permerror, SyntaxError{t, err}
	}

	host, err = p.expandDomain(nonemptyString(host, p.Domain))
	if err != nil {
		return true, macroErrorResult(err), SyntaxError{t, err}
	}

	result, _ := matchingResult(t.qualifier)

	found, err := p.resolver.MatchIP(NormalizeFQDN(host), func(ip net.IP) (bool, error) {
		n := net.IPNet{
			IP: ip,
		}
		if ip.To4() != nil {
			n.IP, n.Mask = ip.To4(), ip4Mask
		} else {
			n.Mask = ip6Mask
		}
		return n.Contains(p.IP), nil
	})
	return mechanismDNSResult(found, result, err)
}

func (p *parser) parseMX(t *token) (bool, Result, error) {
	host, ip4Mask, ip6Mask, err := splitDomainDualCIDR(t.value)
	if err != nil {
		return true, Permerror, SyntaxError{t, err}
	}

	host, err = p.expandDomain(nonemptyString(host, p.Domain))
	if err != nil {
		return true, macroErrorResult(err), SyntaxError{t, err}
	}

	result, _ := matchingResult(t.qualifier)
	found, err := p.resolver.MatchMX(NormalizeFQDN(host), func(ip net.IP) (bool, error) {
		n := net.IPNet{
			IP: ip,
		}
		if ip.To4() != nil {
			n.IP, n.Mask = ip.To4(), ip4Mask
		} else {
			n.Mask = ip6Mask
		}
		return n.Contains(p.IP), nil
	})
	return mechanismDNSResult(found, result, err)
}

func (p *parser) parseInclude(t *token) (bool, Result, error) {
	domain, err := p.expandDomain(t.value)
	if err != nil {
		return true, macroErrorResult(err), SyntaxError{t, err}
	}
	theirResult, _, err := checkHost(p.IP, domain, p.Sender, p.resolver, true)

	/* Adhere to following result table:
	* +---------------------------------+---------------------------------+
	  | A recursive check_host() result | Causes the "include" mechanism  |
	  | of:                             | to:                             |
	  +---------------------------------+---------------------------------+
	  | pass                            | match                           |
	  |                                 |                                 |
	  | fail                            | not match                       |
	  |                                 |                                 |
	  | softfail                        | not match                       |
	  |                                 |                                 |
	  | neutral                         | not match                       |
	  |                                 |                                 |
	  | temperror                       | return temperror                |
	  |                                 |                                 |
	  | permerror                       | return permerror                |
	  |                                 |                                 |
	  | none                            | return permerror                |
	  +---------------------------------+---------------------------------+
	*/

	if err != nil {
		err = SyntaxError{t, err}
	}

	switch theirResult {
	case Pass:
		ourResult, _ := matchingResult(t.qualifier)
		return true, ourResult, err
	case Fail, Softfail, Neutral:
		return false, None, err
	case Temperror:
		return true, Temperror, err
	case None, Permerror:
		return true, Permerror, err
	default: // this should actually never happen
		return true, Permerror, SyntaxError{t, errors.New("unknown result")}
	}

}

func (p *parser) parseExists(t *token) (bool, Result, error) {
	resolvedDomain, err := p.expandDomain(t.value)
	if err != nil {
		return true, macroErrorResult(err), SyntaxError{t, err}
	}

	result, _ := matchingResult(t.qualifier)

	found, err := p.resolver.Exists(NormalizeFQDN(resolvedDomain))
	return mechanismDNSResult(found, result, err)
}

func (p *parser) parsePTR(t *token) (bool, Result, error) {
	domain, err := p.expandDomain(nonemptyString(t.value, p.Domain))
	if err != nil {
		return true, macroErrorResult(err), SyntaxError{t, err}
	}
	e, ok := p.resolver.(*evaluation)
	if !ok {
		return true, Permerror, ErrUnsupportedResolver
	}
	names, err := e.reverseNames(p.IP)
	if err != nil {
		return true, macroErrorResult(err), err
	}
	result, _ := matchingResult(t.qualifier)
	for _, name := range names {
		if withinDomain(name, domain) {
			return true, result, nil
		}
	}
	return false, result, nil
}

func mechanismDNSResult(found bool, result Result, err error) (bool, Result, error) {
	if err == nil {
		return found, result, nil
	}
	failure := dnsErrorResult(err)
	if failure == None {
		return false, result, nil
	}
	return true, failure, err
}

func (p *parser) handleRedirect(oldResult Result) (Result, string, error) {
	if p.Redirect == nil {
		return oldResult, "", nil
	}
	if e, ok := p.resolver.(*evaluation); ok {
		if err := e.useTerm(); err != nil {
			return dnsErrorResult(err), "", err
		}
	}
	domain, err := p.expandDomain(p.Redirect.value)
	if err != nil {
		return macroErrorResult(err), "", SyntaxError{p.Redirect, err}
	}
	result, explanation, err := checkHost(p.IP, domain, p.Sender, p.resolver, p.suppressExplanation)
	if result == None {
		result = Permerror
	}
	if err != nil {
		err = SyntaxError{p.Redirect, err}
	}
	return result, explanation, err
}

// Explanation failure is not an SPF evaluation error (RFC 7208 section 6.2).
// Resolvers concatenate the strings within each TXT RR; separate RRs must
// never be concatenated here.
func (p *parser) handleExplanation() string {
	// Explanation work has its own void allowance and no term charge. Reuse
	// any completed reverse validation, without changing evaluation counters.
	copyParser := *p
	if e, ok := p.resolver.(*evaluation); ok {
		copyEvaluation := *e
		copyEvaluation.voids = 0
		copyEvaluation.explaining = true
		copyParser.resolver = &copyEvaluation
	}
	p = &copyParser
	domain, err := p.expandDomain(p.Explanation.value)
	if err != nil {
		return ""
	}
	txts, err := p.resolver.LookupTXT(NormalizeFQDN(domain))
	if err != nil || len(txts) != 1 || !validExplainString(txts[0]) {
		return ""
	}
	exp, err := parseMacro(p, txts[0])
	if err != nil || !printableASCII(exp) {
		return ""
	}
	return exp
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

func validExplainString(s string) bool {
	for _, part := range strings.Split(s, " ") {
		if valid, _ := validMacroStringLetters(part, "slodiphvcrtSLODIPHVCRT"); !valid {
			return false
		}
	}
	return true
}

func parseCIDRMask(s string, bits int) (net.IPMask, error) {
	if s == "" {
		return net.CIDRMask(bits, bits), nil
	}
	if len(s) > 1 && s[0] == '0' {
		return nil, errInvalidCIDRLength
	}
	for _, c := range s {
		if !isDigit(c) {
			return nil, errInvalidCIDRLength
		}
	}
	var (
		l   int
		err error
	)
	if l, err = strconv.Atoi(s); err != nil {
		return nil, errInvalidCIDRLength
	}
	mask := net.CIDRMask(l, bits)
	if mask == nil {
		return nil, errInvalidCIDRLength
	}
	return mask, nil
}

// splitDomainDualCIDR ignores slashes inside macro expansions.
func splitDomainDualCIDR(value string) (string, net.IPMask, net.IPMask, error) {
	if validDomainSpec(value) {
		return value, net.CIDRMask(32, 32), net.CIDRMask(128, 128), nil
	}
	// Find the final mask, then its optional IPv6 separator and IPv4
	// prefix. Working from the right preserves slashes inside domain-spec.
	end := strings.LastIndexByte(value, '/')
	if end < 0 {
		if value == "" {
			return "", net.CIDRMask(32, 32), net.CIDRMask(128, 128), nil
		}
		return "", nil, nil, ErrInvalidDomain
	}
	if end > 0 && value[end-1] == '/' {
		end--
		start := end
		for start > 0 && isDigit(rune(value[start-1])) {
			start--
		}
		if start > 0 && start < end && value[start-1] == '/' {
			end = start - 1
		}
	}
	domain, suffix := value[:end], value[end:]
	m4, m6 := net.CIDRMask(32, 32), net.CIDRMask(128, 128)
	if domain != "" && !validDomainSpec(domain) {
		return "", nil, nil, ErrInvalidDomain
	}
	var err error
	if suffix != "" && !strings.HasPrefix(suffix, "//") {
		if suffix[0] != '/' {
			return "", nil, nil, errInvalidCIDRLength
		}
		suffix = suffix[1:]
		n := strings.IndexByte(suffix, '/')
		if n < 0 {
			n = len(suffix)
		}
		if n == 0 {
			return "", nil, nil, errInvalidCIDRLength
		}
		m4, err = parseCIDRMask(suffix[:n], 32)
		if err != nil {
			return "", nil, nil, err
		}
		suffix = suffix[n:]
	}
	if suffix != "" {
		if !strings.HasPrefix(suffix, "//") || len(suffix) == 2 {
			return "", nil, nil, errInvalidCIDRLength
		}
		m6, err = parseCIDRMask(suffix[2:], 128)
		if err != nil {
			return "", nil, nil, err
		}
	}
	return domain, m4, m6, nil
}
