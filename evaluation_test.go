package spf

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

type evaluationResolver struct {
	records     map[string][]string
	txtErrors   map[string]error
	lookupError error
	match       bool
	calls       []string
}

func (r *evaluationResolver) txt(kind, name string) ([]string, error) {
	r.calls = append(r.calls, kind+" "+name)
	return r.records[name], r.txtErrors[name]
}
func (r *evaluationResolver) LookupTXTStrict(name string) ([]string, error) {
	return r.txt("spf", name)
}
func (r *evaluationResolver) LookupTXT(name string) ([]string, error) { return r.txt("exp", name) }
func (r *evaluationResolver) lookup(kind, name string) (bool, error) {
	r.calls = append(r.calls, kind+" "+name)
	return r.match, r.lookupError
}
func (r *evaluationResolver) MatchIP(name string, _ IPMatcherFunc) (bool, error) {
	return r.lookup("a", name)
}
func (r *evaluationResolver) MatchMX(name string, _ IPMatcherFunc) (bool, error) {
	return r.lookup("mx", name)
}
func (r *evaluationResolver) Exists(name string) (bool, error) { return r.lookup("exists", name) }
func evaluateRecord(r *evaluationResolver) (Result, string, error) {
	return CheckHostWithResolver(net.IP{192, 0, 2, 1}, "example.com", "sender@example.com", r)
}

func TestEvaluationDNSErrors(t *testing.T) {
	missing := &net.DNSError{Err: "missing", Name: "target.example", IsNotFound: true}
	transport := &net.DNSError{Err: "timeout", Name: "target.example", IsTimeout: true}
	cases := []struct {
		name string
		err  error
		want Result
	}{
		{"temporary", ErrDNSTemperror, Temperror}, {"limit", ErrDNSLimitExceeded, Permerror},
		{"NXDOMAIN", ErrDNSPermerror, None}, {"no-SPF", ErrSPFNotFound, None},
		{"structured-missing", missing, None}, {"transport", transport, Temperror},
		{"other", errors.New("transport failed"), Temperror},
	}
	for _, tc := range cases {
		for _, wrapped := range []bool{false, true} {
			cause := tc.err
			if wrapped {
				cause = fmt.Errorf("lookup context: %w", cause)
			}
			for _, term := range []string{"a:target.example", "mx:target.example", "exists:target.example", "include:target.example", "redirect=target.example", "initial"} {
				t.Run(fmt.Sprintf("%s/%t/%s", tc.name, wrapped, term), func(t *testing.T) {
					query := "v=spf1 " + term + " +all"
					if strings.HasPrefix(term, "redirect=") {
						query = "v=spf1 " + term
					}
					r := &evaluationResolver{records: map[string][]string{"example.com.": {query}}, txtErrors: map[string]error{}, lookupError: cause}
					want := tc.want
					switch {
					case term == "initial":
						r.txtErrors["example.com."] = cause
					case strings.HasPrefix(term, "include:"), strings.HasPrefix(term, "redirect="):
						r.txtErrors["target.example."] = cause
						if want == None {
							want = Permerror
						}
					default:
						if want == None {
							want = Pass
						}
					}
					got, exp, err := evaluateRecord(r)
					if got != want || exp != "" {
						t.Fatalf("got (%v,%q,%v), want %v", got, exp, err, want)
					}
					if want == Pass {
						if err != nil {
							t.Fatalf("missing address answer must be a non-match: %v", err)
						}
						return
					}
					if !errors.Is(err, tc.err) {
						t.Fatalf("lost cause: %v", err)
					}
					if tc.err == transport {
						var dnsErr *net.DNSError
						if !errors.As(err, &dnsErr) || dnsErr != transport {
							t.Fatalf("lost typed cause: %v", err)
						}
					}
				})
			}
		}
	}
	// A resolver error wins even if a custom resolver also reports a match.
	for _, term := range []string{"a", "mx", "exists:target.example"} {
		r := &evaluationResolver{records: map[string][]string{"example.com.": {"v=spf1 -" + term + " +all exp=exp.example"}}, match: true, lookupError: ErrDNSTemperror}
		got, exp, err := evaluateRecord(r)
		if got != Temperror || exp != "" || !errors.Is(err, ErrDNSTemperror) {
			t.Fatalf("%s: got (%v,%q,%v)", term, got, exp, err)
		}
	}
}

func TestIncludeResults(t *testing.T) {
	for _, qualifier := range []string{"+", "-", "~", "?"} {
		for _, child := range []struct {
			record string
			want   Result
		}{
			{"v=spf1 +all", Pass}, {"v=spf1 -all", Fail}, {"v=spf1 ~all", Softfail}, {"v=spf1 ?all", Neutral}, {"v=spf1 bad", Permerror}, {"unrelated TXT", None},
		} {
			t.Run(qualifier+child.record, func(t *testing.T) {
				r := &evaluationResolver{records: map[string][]string{"example.com.": {"v=spf1 " + qualifier + "include:child.example -all"}, "child.example.": {child.record}}}
				want := Fail
				if child.want == Pass {
					want = map[string]Result{"+": Pass, "-": Fail, "~": Softfail, "?": Neutral}[qualifier]
				}
				if child.want == None || child.want == Permerror {
					want = Permerror
				}
				got, _, err := evaluateRecord(r)
				if got != want || (want != Permerror && err != nil) || (want == Permerror && err == nil) {
					t.Fatalf("got (%v,%v), want %v", got, err, want)
				}
			})
		}
	}
}

func TestExplanationProvenance(t *testing.T) {
	for _, tc := range []struct {
		name, root, child string
		want              Result
		exp               string
		calls             []string
	}{
		{"include-failure", "v=spf1 include:child.example -all exp=parent.example", "v=spf1 -all exp=child-exp.example", Fail, "parent", []string{"spf example.com.", "spf child.example.", "exp parent.example."}},
		{"qualified-include", "v=spf1 -include:child.example exp=parent.example", "v=spf1 +all exp=child-exp.example", Fail, "parent", []string{"spf example.com.", "spf child.example.", "exp parent.example."}},
		{"redirect", "v=spf1 redirect=child.example exp=parent.example", "v=spf1 -all exp=child-exp.example", Fail, "child", []string{"spf example.com.", "spf child.example.", "exp child-exp.example."}},
		{"redirect-no-exp", "v=spf1 redirect=child.example exp=parent.example", "v=spf1 -all", Fail, "", []string{"spf example.com.", "spf child.example."}},
		{"include-redirect", "v=spf1 include:child.example -all exp=parent.example", "v=spf1 redirect=grandchild.example", Fail, "parent", []string{"spf example.com.", "spf child.example.", "spf grandchild.example.", "exp parent.example."}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &evaluationResolver{records: map[string][]string{"example.com.": {tc.root}, "child.example.": {tc.child}, "grandchild.example.": {"v=spf1 -all exp=child-exp.example"}, "parent.example.": {"parent"}, "child-exp.example.": {"child"}}}
			got, exp, err := evaluateRecord(r)
			if got != tc.want || exp != tc.exp || err != nil || !reflect.DeepEqual(r.calls, tc.calls) {
				t.Fatalf("got (%v,%q,%v), calls %v", got, exp, err, r.calls)
			}
		})
	}
}

func TestExplanationFallback(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records []string
		err     error
		want    string
	}{
		{"valid", []string{"Denied %{s} from %{d}"}, nil, "Denied sender@example.com from example.com"},
		{"none", nil, nil, ""}, {"multiple", []string{"one", "two"}, nil, ""},
		{"temporary", nil, ErrDNSTemperror, ""}, {"limit", nil, ErrDNSLimitExceeded, ""},
		{"malformed", []string{"%{"}, nil, ""}, {"unknown-macro", []string{"%{z}"}, nil, ""},
		{"zero-transformer", []string{"Denied %{d0}"}, nil, ""},
		{"non-ASCII", []string{"denied é"}, nil, ""}, {"newline", []string{"denied\r\ntext"}, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &evaluationResolver{records: map[string][]string{"example.com.": {"v=spf1 -all exp=exp.example"}, "exp.example.": tc.records}, txtErrors: map[string]error{"exp.example.": tc.err}}
			got, exp, err := evaluateRecord(r)
			if got != Fail || exp != tc.want || err != nil {
				t.Fatalf("got (%v,%q,%v), want fail/%q/nil", got, exp, err, tc.want)
			}
		})
	}
}

func TestSenderNormalization(t *testing.T) {
	for _, tc := range []struct{ sender, want string }{
		{"", "postmaster@example.com"}, {"helo.example", "postmaster@helo.example"}, {"@", "postmaster@example.com"},
		{"@mail.example", "postmaster@mail.example"}, {"user@", "user@example.com"}, {"User@mail.example", "User@mail.example"},
	} {
		for _, policy := range []string{"v=spf1 -all exp=exp.example", "v=spf1 redirect=child.example", "v=spf1 include:child.example -all exp=exp.example"} {
			t.Run(tc.sender+"/"+policy, func(t *testing.T) {
				r := &evaluationResolver{records: map[string][]string{"example.com.": {policy}, "child.example.": {"v=spf1 -all exp=exp.example"}, "exp.example.": {"%{s}|%{l}|%{o}"}}}
				got, exp, err := CheckHostWithResolver(net.IP{192, 0, 2, 1}, "example.com", tc.sender, r)
				parts := strings.SplitN(tc.want, "@", 2)
				want := tc.want + "|" + parts[0] + "|" + parts[1]
				if got != Fail || exp != want || err != nil {
					t.Fatalf("got (%v,%q,%v), want %q", got, exp, err, want)
				}
			})
		}
	}
}

func TestEvaluationInputs(t *testing.T) {
	for _, domain := range []string{"", "localhost", "localhost.", ".", "foo..example", strings.Repeat("a", 64) + ".example", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62)} {
		r := &evaluationResolver{}
		got, _, err := CheckHostWithResolver(net.IP{192, 0, 2, 1}, domain, "", r)
		if got != None || !errors.Is(err, ErrInvalidDomain) || len(r.calls) != 0 {
			t.Errorf("%q: got (%v,%v), calls %v", domain, got, err, r.calls)
		}
	}
	for _, ip := range []net.IP{nil, {}, {1, 2, 3}, make(net.IP, 17)} {
		r := &evaluationResolver{records: map[string][]string{"example.com.": {"v=spf1 +all"}}}
		got, _, err := CheckHostWithResolver(ip, "example.com", "", r)
		if got != None || !errors.Is(err, ErrInvalidIP) || len(r.calls) != 0 {
			t.Errorf("invalid IP %v: got (%v,%v), calls %v", ip, got, err, r.calls)
		}
	}
}

func TestSyntaxErrorUnwrap(t *testing.T) {
	cause := &net.DNSError{Err: "timeout", IsTimeout: true}
	err := fmt.Errorf("outer: %w", SyntaxError{err: cause})
	var dnsErr *net.DNSError
	if !errors.Is(err, cause) || !errors.As(err, &dnsErr) || dnsErr != cause {
		t.Fatalf("lost cause: %v", err)
	}
}

func TestEvaluationDomainBoundaries(t *testing.T) {
	longest := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, domain := range []string{"example.com", "example.com.", "_spf.example.com", "xn--bcher-kva.example", longest, longest + "."} {
		r := &evaluationResolver{records: map[string][]string{NormalizeFQDN(domain): {"v=spf1 +all"}}}
		got, _, err := CheckHostWithResolver(net.IP{192, 0, 2, 1}, domain, "", r)
		if got != Pass || err != nil || len(r.calls) != 1 {
			t.Errorf("%q: got (%v,%v), calls %v", domain, got, err, r.calls)
		}
	}
}

func TestRecursiveSenderIdentity(t *testing.T) {
	// The child uses sender macros for DNS, even when its own explanation
	// is suppressed. Normalization must retain the original domain.
	for _, sender := range []string{"", "@", "postmaster@"} {
		for _, term := range []string{"include:child.example", "redirect=child.example"} {
			r := &evaluationResolver{records: map[string][]string{
				"example.com.":   {"v=spf1 " + term},
				"child.example.": {"v=spf1 exists:%{l}.%{o}.seen.example -all"},
			}, match: true}
			got, _, err := CheckHostWithResolver(net.IP{192, 0, 2, 1}, "example.com", sender, r)
			want := []string{"spf example.com.", "spf child.example.", "exists postmaster.example.com.seen.example."}
			if got != Pass || err != nil || !reflect.DeepEqual(r.calls, want) {
				t.Errorf("%q/%s: got (%v,%v), calls %v", sender, term, got, err, r.calls)
			}
		}
	}
}

func TestRedirectChainExplanation(t *testing.T) {
	r := &evaluationResolver{records: map[string][]string{
		"example.com.":        {"v=spf1 redirect=child.example exp=unused.example"},
		"child.example.":      {"v=spf1 redirect=grandchild.example exp=unused.example"},
		"grandchild.example.": {"v=spf1 -all exp=exp.example"},
		"exp.example.":        {"Denied %{s} by %{d}"},
	}}
	got, exp, err := evaluateRecord(r)
	if got != Fail || exp != "Denied sender@example.com by grandchild.example" || err != nil {
		t.Fatalf("got (%v,%q,%v)", got, exp, err)
	}
	want := []string{"spf example.com.", "spf child.example.", "spf grandchild.example.", "exp exp.example."}
	if !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("lookups %v", r.calls)
	}
}

func TestExplanationExpansionFailure(t *testing.T) {
	for _, tc := range []struct {
		policy, text, sender string
		calls                int
	}{
		{"v=spf1 -all exp=%{s}", "ignored", "sender@example.com", 1},
		{"v=spf1 -all exp=exp.example", "Denied %{s}", "a\nb@example.com", 2},
	} {
		r := &evaluationResolver{records: map[string][]string{"example.com.": {tc.policy}, "exp.example.": {tc.text}}}
		got, exp, err := CheckHostWithResolver(net.IP{192, 0, 2, 1}, "example.com", tc.sender, r)
		if got != Fail || exp != "" || err != nil || len(r.calls) != tc.calls {
			t.Errorf("%q: got (%v,%q,%v), calls %v", tc.text, got, exp, err, r.calls)
		}
	}
}

func TestExplanationSingleRRMultipleStrings(t *testing.T) {
	mux, resolver := newTestDNS(t)
	mux.HandleFunc("example.com.", zone(t, map[uint16][]string{dns.TypeTXT: {`example.com. 0 IN TXT "v=spf1 -all exp=exp.example"`}}))
	mux.HandleFunc("exp.example.", zone(t, map[uint16][]string{dns.TypeTXT: {`exp.example. 0 IN TXT "Denied " "%{s}"`}}))
	got, exp, err := CheckHostWithResolver(net.IP{192, 0, 2, 1}, "example.com", "sender@example.com", resolver)
	if got != Fail || exp != "Denied sender@example.com" || err != nil {
		t.Fatalf("got (%v,%q,%v)", got, exp, err)
	}
}

func TestRedirectResults(t *testing.T) {
	for _, tc := range []struct {
		record string
		want   Result
	}{
		{"v=spf1 +all", Pass}, {"v=spf1 -all", Fail}, {"v=spf1 ~all", Softfail},
		{"v=spf1 ?all", Neutral}, {"v=spf1 bad", Permerror}, {"unrelated TXT", Permerror},
	} {
		r := &evaluationResolver{records: map[string][]string{"example.com.": {"v=spf1 redirect=child.example"}, "child.example.": {tc.record}}}
		got, _, err := evaluateRecord(r)
		if got != tc.want || (got == Permerror) != (err != nil) {
			t.Errorf("%q: got (%v,%v), want %v", tc.record, got, err, tc.want)
		}
	}
}

func TestRecursiveMechanismErrors(t *testing.T) {
	for _, term := range []string{"include:child.example +all", "redirect=child.example"} {
		for _, cause := range []error{ErrDNSTemperror, ErrDNSLimitExceeded} {
			r := &evaluationResolver{records: map[string][]string{
				"example.com.":   {"v=spf1 " + term + " exp=unused.example"},
				"child.example.": {"v=spf1 a:target.example -all exp=unused.example"},
			}, lookupError: fmt.Errorf("address lookup: %w", cause)}
			got, exp, err := evaluateRecord(r)
			want := Temperror
			if cause == ErrDNSLimitExceeded {
				want = Permerror
			}
			if got != want || exp != "" || !errors.Is(err, cause) {
				t.Fatalf("%s: got (%v,%q,%v)", term, got, exp, err)
			}
			expected := []string{"spf example.com.", "spf child.example.", "a target.example."}
			if !reflect.DeepEqual(r.calls, expected) {
				t.Fatalf("continued after error: %v", r.calls)
			}
		}
	}
}
