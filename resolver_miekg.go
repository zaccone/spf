package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// NewMiekgDNSResolver returns a resolver using the specified DNS server.
func NewMiekgDNSResolver(addr string) (Resolver, error) { return newMiekgResolver(addr) }

// NewMiekgDNSResolverContext returns the context-capable view of the resolver.
func NewMiekgDNSResolverContext(addr string) (ContextResolver, error) { return newMiekgResolver(addr) }

func newMiekgResolver(addr string) (*MiekgDNSResolver, error) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, err
	}
	return &MiekgDNSResolver{client: new(dns.Client), serverAddr: addr}, nil
}

// MiekgDNSResolver implements Resolver and ContextResolver using miekg/dns.
// Each query owns its connection. Aliases are limited to ten hops, including
// aliases present in a single response. Truncated UDP is retried once over TCP.
type MiekgDNSResolver struct {
	client     *dns.Client
	serverAddr string
}

func (r *MiekgDNSResolver) exchangeContext(ctx context.Context, req *dns.Msg, tcp bool) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, wrapDNSError(ctx, err)
	}
	client := *r.client
	if tcp {
		client.Net = "tcp"
	}
	conn, err := client.DialContext(ctx, r.serverAddr)
	if err != nil {
		return nil, wrapDNSError(ctx, err)
	}
	// ExchangeWithConnContext honors deadlines; closing the connection also
	// interrupts a read when a context is explicitly canceled before its deadline.
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { conn.Close(); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
		conn.Close()
	}()
	res, _, err := client.ExchangeWithConnContext(ctx, req, conn)
	if err = wrapDNSError(ctx, err); err != nil {
		return nil, err
	}
	if res == nil || !res.Response || res.Opcode != req.Opcode || len(res.Question) != 1 ||
		!strings.EqualFold(res.Question[0].Name, req.Question[0].Name) ||
		res.Question[0].Qtype != req.Question[0].Qtype || res.Question[0].Qclass != req.Question[0].Qclass {
		return nil, wrapDNSError(ctx, errors.New("mismatched DNS response"))
	}
	if res.Truncated {
		if !tcp {
			return r.exchangeContext(ctx, req, true)
		}
		return nil, wrapDNSError(ctx, errors.New("truncated TCP DNS response"))
	}
	if res.Rcode != dns.RcodeSuccess {
		cause := &net.DNSError{Err: dns.RcodeToString[res.Rcode], Name: req.Question[0].Name, Server: r.serverAddr,
			IsNotFound: res.Rcode == dns.RcodeNameError, IsTemporary: res.Rcode != dns.RcodeNameError}
		return nil, wrapDNSError(ctx, cause)
	}
	return res, nil
}

// lookup only accepts records whose owner is the queried name or a validated
// alias target. Unrelated records in Answer (or Additional) cannot cause a match.
func (r *MiekgDNSResolver) lookup(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	ctx, cancel := context.WithTimeout(ctx, evaluationTimeout)
	defer cancel()
	// Normalize presentation escaping once at the API boundary. DNS replies
	// use escaped presentation strings, including for spaces and backslashes.
	var err error
	name, err = dnsPresentationName(name)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{strings.ToLower(name): true}
	hops := 0
	for {
		req := new(dns.Msg)
		req.SetQuestion(name, qtype)
		res, err := r.exchangeContext(ctx, req, false)
		if err != nil {
			return nil, err
		}
		followed := false
		for {
			var records []dns.RR
			target := ""
			for _, rr := range res.Answer {
				h := rr.Header()
				if h.Class != dns.ClassINET || !strings.EqualFold(h.Name, name) {
					continue
				}
				if h.Rrtype == qtype {
					records = append(records, rr)
				}
				if cname, ok := rr.(*dns.CNAME); ok {
					if target != "" && !strings.EqualFold(target, cname.Target) {
						return nil, wrapDNSError(ctx, errors.New("conflicting CNAME targets"))
					}
					target = cname.Target
				}
			}
			if target == "" {
				if len(records) > 0 || !followed {
					return records, nil
				}
				// The last alias target wasn't included in this response. Query it.
				break
			}
			if len(records) > 0 {
				return nil, wrapDNSError(ctx, errors.New("CNAME and data at the same owner"))
			}
			hops++
			key := strings.ToLower(NormalizeFQDN(target))
			if hops > 10 || seen[key] {
				return nil, wrapDNSError(ctx, errors.New("CNAME chain limit or cycle"))
			}
			seen[key] = true
			name, followed = NormalizeFQDN(target), true
		}
	}
}

// LookupTXTContext returns one string per TXT RR, joining its component strings.
func (r *MiekgDNSResolver) LookupTXTContext(ctx context.Context, name string) ([]string, error) {
	rrs, err := r.lookup(ctx, name, dns.TypeTXT)
	var records []string
	for _, rr := range rrs {
		if txt, ok := rr.(*dns.TXT); ok {
			records = append(records, strings.Join(txt.Txt, ""))
		}
	}
	return records, err
}

// LookupIPContext queries only the selected address family.
func (r *MiekgDNSResolver) LookupIPContext(ctx context.Context, network, name string) ([]net.IP, error) {
	qtype := uint16(dns.TypeA)
	switch network {
	case "ip4":
	case "ip6":
		qtype = dns.TypeAAAA
	default:
		return nil, fmt.Errorf("invalid address network %q", network)
	}
	rrs, err := r.lookup(ctx, name, qtype)
	var records []net.IP
	for _, rr := range rrs {
		switch a := rr.(type) {
		case *dns.A:
			records = append(records, a.A)
		case *dns.AAAA:
			records = append(records, a.AAAA)
		}
	}
	return records, err
}

// LookupMXContext returns exchanges before address resolution.
func (r *MiekgDNSResolver) LookupMXContext(ctx context.Context, name string) ([]*net.MX, error) {
	rrs, err := r.lookup(ctx, name, dns.TypeMX)
	var records []*net.MX
	for _, rr := range rrs {
		if mx, ok := rr.(*dns.MX); ok {
			host, nameErr := dnsLiteralName(mx.Mx)
			if nameErr != nil {
				return nil, nameErr
			}
			records = append(records, &net.MX{Host: host, Pref: mx.Preference})
		}
	}
	return records, err
}

// LookupAddrContext performs the IPv4 or IPv6 reverse query, without forward
// validation. Only the first ten PTR candidates are returned (RFC 7208, 4.6.4).
func (r *MiekgDNSResolver) LookupAddrContext(ctx context.Context, addr string) ([]string, error) {
	name, err := dns.ReverseAddr(addr)
	if err != nil {
		return nil, err
	}
	rrs, err := r.lookup(ctx, name, dns.TypePTR)
	var records []string
	for _, rr := range rrs {
		if ptr, ok := rr.(*dns.PTR); ok {
			// Ignore excess candidates before conversion: an unrepresentable
			// name beyond the limit must not invalidate the usable candidates.
			if len(records) == 10 {
				break
			}
			host, nameErr := dnsLiteralName(ptr.Ptr)
			if nameErr != nil {
				return nil, nameErr
			}
			records = append(records, host)
		}
	}
	return records, err
}

func (r *MiekgDNSResolver) LookupTXTStrict(name string) ([]string, error) {
	return legacyTXT(r, name, true)
}
func (r *MiekgDNSResolver) LookupTXT(name string) ([]string, error) { return legacyTXT(r, name, false) }
func (r *MiekgDNSResolver) Exists(name string) (bool, error)        { return legacyExists(r, name) }
func (r *MiekgDNSResolver) MatchIP(name string, matcher IPMatcherFunc) (bool, error) {
	return legacyMatchIP(r, name, matcher)
}
func (r *MiekgDNSResolver) MatchMX(name string, matcher IPMatcherFunc) (bool, error) {
	return legacyMatchMX(r, name, matcher)
}

// The evaluator supplies literal dot-separated labels. Build the wire name
// directly, then let miekg/dns produce its canonical presentation spelling.
func dnsPresentationName(name string) (string, error) {
	if name == "." {
		return name, nil
	}
	if !validExpandedDomain(name) {
		return "", ErrInvalidDomain
	}
	wire := make([]byte, 0, 255)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	wire = append(wire, 0)
	name, _, err := dns.UnpackDomainName(wire, 0)
	return name, err
}

// MX/PTR values leave the transport in the same literal form as query names.
// A label containing a dot cannot be represented by this interface and must
// not be mistaken for a subdomain boundary during PTR validation.
func dnsLiteralName(name string) (string, error) {
	wire := make([]byte, 255)
	end, err := dns.PackDomainName(name, wire, 0, nil, false)
	if err != nil {
		return "", err
	}
	var labels []string
	for pos := 0; pos < end && wire[pos] != 0; {
		length := int(wire[pos])
		pos++
		label := string(wire[pos : pos+length])
		pos += length
		if strings.Contains(label, ".") {
			return "", ErrInvalidDomain
		}
		labels = append(labels, label)
	}
	return strings.Join(labels, ".") + ".", nil
}
