package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestStep6MacroTransformations(t *testing.T) {
	p := newParser("strong-bad+tag@email.example.com", "email.example.com", net.ParseIP("2001:db8::cb01"), "", nil)
	p.resolver = &evaluation{ctx: context.Background(), options: Options{HELO: "helo.example", Receiver: "receiver.example", Time: time.Unix(1234567890, 0)}}
	for _, tc := range []struct{ input, want string }{
		{"%{i}", "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.0.1"},
		{"%{i4r}", "1.0.0.2"}, {"%{v2r-}", "ip6"},
		{"%{c} %{h} %{r} %{t}", "2001:db8::cb01 helo.example receiver.example 1234567890"},
		{"%{C}", "2001%3Adb8%3A%3Acb01"},
		{"%{S}", "strong-bad%2Btag%40email.example.com"},
		{"%{l1r+-}", "strong"}, {"%{l2R+-}", "bad.strong"},
		{"%{d0002}", "example.com"}, {"%{d" + strings.Repeat("9", 100) + "}", "email.example.com"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parseMacro(p, tc.input)
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	p.Sender = "+a--b+@example.com"
	got, err := parseMacro(p, "%{l+-}")
	if err != nil || got != ".a..b." {
		t.Fatalf("empty parts: %q %v", got, err)
	}
	if got := escapeMacro("AZaz09-._~ !*'();:@&=+$,/?#[]%"); got != "AZaz09-._~%20%21%2A%27%28%29%3B%3A%40%26%3D%2B%24%2C%2F%3F%23%5B%5D%25" {
		t.Fatal(got)
	}
	for _, input := range []string{"%{d0}", "%{d000}", "%{d-2}", "%{d2rr}", "%{x}", "%{s2!}", "%{i", "%"} {
		if _, err := parseMacro(p, input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}

func TestStep6DomainSpecs(t *testing.T) {
	for _, term := range []string{"a:%{h}/24", "mx:%{h}/24", "include:%{h}", "exists:%{h}", "redirect=%{h}", "ptr:%{h}"} {
		t.Run(term, func(t *testing.T) {
			calls := 0
			r := &contextFixture{
				txt: func(_ context.Context, name string) ([]string, error) {
					if name == "example.test." {
						return []string{"v=spf1 " + term}, nil
					}
					if name != "helo.test." {
						t.Fatalf("unexpanded TXT name %q", name)
					}
					calls++
					return []string{"v=spf1 +all"}, nil
				},
				ip: func(_ context.Context, family, name string) ([]net.IP, error) {
					if family != "ip4" || name != "helo.test." {
						t.Fatalf("IP %q %q", family, name)
					}
					calls++
					return []net.IP{net.ParseIP("192.0.2.1")}, nil
				},
				mx: func(_ context.Context, name string) ([]*net.MX, error) {
					if name != "helo.test." {
						t.Fatalf("MX %q", name)
					}
					return []*net.MX{{Host: "helo.test."}}, nil
				},
				ptr: func(context.Context, string) ([]string, error) { return []string{"helo.test."}, nil },
			}
			result, _, err := CheckHostWithOptions(context.Background(), net.ParseIP("192.0.2.1"), "example.test", "sender@example.test", Options{Resolver: r, HELO: "helo.test"})
			if result != Pass || err != nil || calls != 1 {
				t.Fatalf("%v %v, calls %d", result, err, calls)
			}
		})
	}
	for _, term := range []string{"a:%{l}.test", "mx:%{l}.test", "include:%{l}.test", "exists:%{l}.test", "redirect=%{l}.test", "ptr:%{l}.test"} {
		r := recordFixture("v=spf1 " + term)
		result, _, err := CheckHostWithOptions(context.Background(), net.ParseIP("192.0.2.1"), "example.test", strings.Repeat("x", 64)+"@example.test", Options{Resolver: r})
		if result != Permerror || !errors.Is(err, ErrInvalidDomain) {
			t.Errorf("%s: %v %v", term, result, err)
		}
	}
	// c/r/t are explanation-text only, including after a would-be early match.
	for _, letter := range []string{"c", "r", "t", "C", "R", "T"} {
		r := recordFixture("v=spf1 +all exists:%{" + letter + "}.test")
		got, _, err := CheckHostWithOptions(context.Background(), net.ParseIP("192.0.2.1"), "example.test", "", Options{Resolver: r})
		if got != Permerror || err == nil {
			t.Fatalf("%s: %v %v", letter, got, err)
		}
	}
}

func TestStep6DomainLength(t *testing.T) {
	p := newParser("", "example.test", net.ParseIP("192.0.2.1"), "", nil)
	tail := strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) + ".test"
	p.Sender = strings.Repeat("a", 63) + "." + tail + "@example.test"
	got, err := p.expandDomain("%{l}")
	if err != nil || got != tail {
		t.Fatalf("%q %v", got, err)
	}
	p.Sender = strings.Repeat("a", 63) + "." + tail + ".@example.test"
	got, err = p.expandDomain("%{l}")
	if err != nil || got != tail+"." {
		t.Fatalf("root dot: %q %v", got, err)
	}
	for _, local := range []string{strings.Repeat("x", 254), "bad..test", "bad\n.test"} {
		p.Sender = local + "@example.test"
		if _, err := p.expandDomain("%{l}"); !errors.Is(err, ErrInvalidDomain) {
			t.Errorf("%q: %v", local, err)
		}
	}
}

func TestStep6RecursiveIdentities(t *testing.T) {
	r := &contextFixture{txt: func(_ context.Context, n string) ([]string, error) {
		switch n {
		case "example.test.":
			return []string{"v=spf1 include:child.test redirect=final.test"}, nil
		case "child.test.":
			return []string{"v=spf1 exists:%{h}.%{o}.%{d} ?all"}, nil
		case "final.test.":
			return []string{"v=spf1 -all exp=%{h}.explain.test"}, nil
		case "helo.test.explain.test.":
			return []string{"%{s} %{d} %{h} %{r} %{t} %{c} %{S} %{p}"}, nil
		default:
			t.Fatalf("unexpected TXT %q", n)
			return nil, nil
		}
	}, ip: func(_ context.Context, f, n string) ([]net.IP, error) {
		if f != "ip4" || n != "helo.test.sender.test.child.test." {
			t.Fatalf("lookup %s %s", f, n)
		}
		return nil, nil
	}}
	got, exp, err := CheckHostWithOptions(context.Background(), net.ParseIP("192.0.2.1"), "example.test", "sender@sender.test", Options{Resolver: r, HELO: "helo.test", Receiver: "receiver.test", Time: time.Unix(42, 0)})
	want := "sender@sender.test final.test helo.test receiver.test 42 192.0.2.1 sender%40sender.test unknown"
	if got != Fail || err != nil || exp != want {
		t.Fatalf("%v %q %v", got, exp, err)
	}
}

func TestStep6PTR(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		valid        bool
		want         Result
	}{
		{"mail.example.test.", "example.test", true, Pass},
		{"EXAMPLE.TEST.", "example.test", true, Pass},
		{"badexample.test.", "example.test", true, Fail},
		{"example.test.evil.test.", "example.test", true, Fail},
		{"example.test.", "mail.example.test", true, Fail},
		{"mail.example.test.", "example.test", false, Fail},
	} {
		for _, client := range []string{"192.0.2.1", "2001:db8::1"} {
			t.Run(tc.name+tc.target+client+fmt.Sprint(tc.valid), func(t *testing.T) {
				r := recordFixture("v=spf1 ptr:" + tc.target + " -all")
				r.ptr = func(_ context.Context, addr string) ([]string, error) {
					if addr != client {
						t.Fatal(addr)
					}
					return []string{tc.name}, nil
				}
				r.ip = func(_ context.Context, f, n string) ([]net.IP, error) {
					wantFamily := "ip4"
					if strings.Contains(client, ":") {
						wantFamily = "ip6"
					}
					if f != wantFamily || n != tc.name {
						t.Fatalf("%s %s", f, n)
					}
					if tc.valid {
						return []net.IP{net.ParseIP(client)}, nil
					}
					return []net.IP{net.ParseIP("192.0.2.99")}, nil
				}
				got, _, err := CheckHostWithOptions(context.Background(), net.ParseIP(client), "example.test", "", Options{Resolver: r})
				if got != tc.want || err != nil {
					t.Fatalf("%v %v", got, err)
				}
			})
		}
	}
	for _, prefix := range []string{"", "-", "~", "?"} {
		r := recordFixture("v=spf1 " + prefix + "ptr -all")
		r.ptr = func(context.Context, string) ([]string, error) { return []string{"example.test."}, nil }
		r.ip = func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		}
		want := map[string]Result{"": Pass, "-": Fail, "~": Softfail, "?": Neutral}[prefix]
		runContext(t, r, want, nil)
	}
}

func TestStep6PTRMacroPreferenceAndReuse(t *testing.T) {
	for _, names := range [][]string{{"other.test.", "sub.example.test.", "EXAMPLE.TEST."}, {"other.test.", "sub.example.test."}, {"other.test."}} {
		r := recordFixture("v=spf1 exists:%{p}.%{p}.check.test -all")
		reverseCalls := 0
		r.ptr = func(context.Context, string) ([]string, error) { reverseCalls++; return names, nil }
		r.ip = func(_ context.Context, _ string, n string) ([]net.IP, error) {
			if strings.HasSuffix(n, ".check.test.") {
				want := strings.TrimSuffix(names[len(names)-1], ".")
				if n != want+"."+want+".check.test." {
					t.Fatal(n)
				}
			}
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		}
		runContext(t, r, Pass, nil)
		if reverseCalls != 1 {
			t.Fatal(reverseCalls)
		}
	}
}

func TestStep6PTRErrorsAndLimits(t *testing.T) {
	for _, stage := range []string{"reverse", "forward"} {
		r := recordFixture("v=spf1 ptr -all")
		r.ptr = func(context.Context, string) ([]string, error) {
			if stage == "reverse" {
				return nil, ErrDNSTemperror
			}
			return []string{"example.test."}, nil
		}
		r.ip = func(context.Context, string, string) ([]net.IP, error) { return nil, ErrDNSTemperror }
		runContext(t, r, Fail, nil)
	}
	r := recordFixture("v=spf1 ptr -all")
	r.ptr = func(context.Context, string) ([]string, error) {
		var names []string
		for i := 0; i < 11; i++ {
			names = append(names, fmt.Sprintf("host%d.example.test.", i))
		}
		return names, nil
	}
	calls := 0
	r.ip = func(_ context.Context, _ string, n string) ([]net.IP, error) {
		calls++
		if calls > 10 {
			t.Fatal("11th PTR candidate queried")
		}
		return []net.IP{net.ParseIP("192.0.2.2")}, nil
	}
	runContext(t, r, Fail, nil)
	if calls != 10 {
		t.Fatal(calls)
	}
	r.ip = func(context.Context, string, string) ([]net.IP, error) { return nil, nil }
	runContext(t, r, Permerror, ErrDNSLimitExceeded)
	ctx, cancel := context.WithCancel(context.Background())
	r = recordFixture("v=spf1 exists:%{p}.test -all")
	r.ptr = func(context.Context, string) ([]string, error) { cancel(); return nil, context.Canceled }
	got, _, err := CheckHostWithOptions(ctx, net.ParseIP("192.0.2.1"), "example.test", "", Options{Resolver: r})
	if got != Temperror || !errors.Is(err, context.Canceled) {
		t.Fatalf("%v %v", got, err)
	}
	legacy := &evaluationResolver{records: map[string][]string{"example.com.": {"v=spf1 ptr -all"}}}
	got, _, err = CheckHostWithResolver(net.ParseIP("192.0.2.1"), "example.com", "", legacy)
	if got != Permerror || !errors.Is(err, ErrUnsupportedResolver) {
		t.Fatalf("%v %v", got, err)
	}
}

func TestStep6PTRBackends(t *testing.T) {
	for _, backend := range []string{"standard", "server"} {
		for _, client := range []string{"192.0.2.1", "2001:db8::1"} {
			t.Run(backend+client, func(t *testing.T) {
				reverse, _ := dns.ReverseAddr(client)
				addr := startDualDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
					reply := new(dns.Msg)
					reply.SetReply(q)
					question := q.Question[0]
					var rr string
					switch {
					case question.Name == "example.test." && question.Qtype == dns.TypeTXT:
						rr = "example.test. 60 IN TXT \"v=spf1 ptr -all\""
					case question.Name == reverse && question.Qtype == dns.TypePTR:
						rr = reverse + " 60 IN PTR mail.example.test."
					case question.Name == "mail.example.test." && question.Qtype == dns.TypeA && client == "192.0.2.1":
						rr = "mail.example.test. 60 IN A " + client
					case question.Name == "mail.example.test." && question.Qtype == dns.TypeAAAA && client != "192.0.2.1":
						rr = "mail.example.test. 60 IN AAAA " + client
					}
					if rr != "" {
						record, err := dns.NewRR(rr)
						if err != nil {
							t.Error(err)
						} else {
							reply.Answer = []dns.RR{record}
						}
					}
					if err := w.WriteMsg(reply); err != nil {
						t.Error(err)
					}
				}))
				result, _, err := CheckHostWithOptions(context.Background(), net.ParseIP(client), "example.test", "", Options{Resolver: contextBackend(t, backend, addr)})
				if result != Pass || err != nil {
					t.Fatalf("%v %v", result, err)
				}
			})
		}
	}
}

func FuzzMacroExpansion(f *testing.F) {
	for _, s := range []string{"%{l1r+-}", "%{i4r}", "%{S}", "%{d000}", "%{d999999999999999999999999}", "%{p}.test"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}
		p := newParser("a-b+tag@example.test", "example.test", net.ParseIP("2001:db8::1"), "", nil)
		_, _ = parseMacro(p, s)
		_, _ = p.expandDomain(s)
	})
}

func TestStep6PTRMacroErrorPolicy(t *testing.T) {
	for _, mechanism := range []string{"ptr", "exists:%{p}.check.test"} {
		r := recordFixture("v=spf1 " + mechanism + " -all")
		r.ptr = func(context.Context, string) ([]string, error) { return []string{"broken.test.", "example.test."}, nil }
		r.ip = func(_ context.Context, _ string, name string) ([]net.IP, error) {
			switch name {
			case "broken.test.":
				return nil, ErrDNSTemperror
			case "example.test.", "unknown.check.test.":
				return []net.IP{net.ParseIP("192.0.2.1")}, nil
			default:
				t.Fatalf("unexpected name: %s", name)
				return nil, nil
			}
		}
		runContext(t, r, Pass, nil)
	}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		for _, mechanism := range []string{"ptr", "exists:%{p}.check.test"} {
			r := recordFixture("v=spf1 " + mechanism + " -all")
			// A resolver may have its own canceled context; retain its cause even
			// when the evaluator's parent context is still active.
			r.ptr = func(context.Context, string) ([]string, error) { return nil, fmt.Errorf("resolver: %w", cause) }
			runContext(t, r, Temperror, cause)
		}
	}
}

func TestStep6PTRMacroTermBoundary(t *testing.T) {
	for _, count := range []int{5, 6} {
		r := recordFixture("v=spf1 " + strings.Repeat("a:%{p}.test ", count) + "-all")
		r.ptr = func(context.Context, string) ([]string, error) { return []string{"other.test."}, nil }
		r.ip = func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("192.0.2.2")}, nil
		}
		if count == 5 {
			runContext(t, r, Fail, nil)
		} else {
			runContext(t, r, Permerror, ErrDNSLimitExceeded)
		}
	}
}

func TestStep6ExplanationAtTermLimit(t *testing.T) {
	r := &contextFixture{txt: func(_ context.Context, name string) ([]string, error) {
		if name == "example.test." {
			return []string{"v=spf1 " + strings.Repeat("a ", 10) + "-all exp=%{p}.explain.test"}, nil
		}
		if name != "example.test.explain.test." {
			t.Fatal(name)
		}
		return []string{"%{p} %{h} %{r} %{t}"}, nil
	}, ptr: func(context.Context, string) ([]string, error) { return []string{"example.test."}, nil }}
	calls := 0
	r.ip = func(context.Context, string, string) ([]net.IP, error) {
		calls++
		ip := "192.0.2.2"
		if calls == 11 {
			ip = "192.0.2.1"
		}
		return []net.IP{net.ParseIP(ip)}, nil
	}
	got, exp, err := CheckHostWithOptions(context.Background(), net.ParseIP("192.0.2.1"), "example.test", "", Options{Resolver: r, Time: time.Unix(42, 0)})
	if got != Fail || err != nil || exp != "example.test unknown unknown 42" || calls != 11 {
		t.Fatalf("%v %q %v, calls=%d", got, exp, err, calls)
	}
	// The same supported explanation macros work through a legacy resolver,
	// with unknown for p and explicit entrypoint timestamp capture for t.
	legacy := &evaluationResolver{records: map[string][]string{
		"example.com.": {"v=spf1 -all exp=exp.example"},
		"exp.example.": {"Denied %{c} %{p} %{S} %{l1r+-}"},
	}}
	got, exp, err = CheckHostWithResolver(net.ParseIP("192.0.2.1"), "example.com", "sender@example.com", legacy)
	if got != Fail || err != nil || exp != "Denied 192.0.2.1 unknown sender%40example.com sender" {
		t.Fatalf("%v %q %v", got, exp, err)
	}
}

func TestStep6PTRMacroRecursivePreference(t *testing.T) {
	reverseCalls := 0
	r := &contextFixture{
		txt: func(_ context.Context, name string) ([]string, error) {
			switch name {
			case "example.test.":
				return []string{"v=spf1 a:%{p} include:child.test -all"}, nil
			case "child.test.":
				return []string{"v=spf1 exists:%{p}.check.test -all"}, nil
			default:
				t.Fatalf("unexpected TXT %q", name)
				return nil, nil
			}
		},
		ptr: func(context.Context, string) ([]string, error) {
			reverseCalls++
			return []string{"example.test.", "child.test."}, nil
		},
	}
	forwardCalls := 0
	r.ip = func(_ context.Context, _ string, name string) ([]net.IP, error) {
		forwardCalls++
		switch forwardCalls {
		case 1, 2:
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		case 3:
			if name != "example.test." {
				t.Fatal(name)
			}
			return []net.IP{net.ParseIP("192.0.2.2")}, nil
		default:
			if name != "child.test.check.test." {
				t.Fatal(name)
			}
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		}
	}
	runContext(t, r, Pass, nil)
	if reverseCalls != 1 || forwardCalls != 4 {
		t.Fatalf("reverse=%d forward=%d", reverseCalls, forwardCalls)
	}
}

func FuzzStep6Evaluation(f *testing.F) {
	for _, s := range []string{"ptr -all", "exists:%{p}.test -all", "include:%{d}", "redirect=%{d}", "a:%{i}.test", "-all exp=%{p}.test", "+all exists:%{c}.test"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}
		calls := 0
		r := &contextFixture{
			txt: func(context.Context, string) ([]string, error) { calls++; return []string{"v=spf1 " + s}, nil },
			ip: func(context.Context, string, string) ([]net.IP, error) {
				calls++
				return []net.IP{net.ParseIP("192.0.2.2")}, nil
			},
			ptr: func(context.Context, string) ([]string, error) { calls++; return []string{"example.test."}, nil },
			mx: func(context.Context, string) ([]*net.MX, error) {
				calls++
				return []*net.MX{{Host: "example.test."}}, nil
			},
		}
		_, _, _ = CheckHostWithOptions(context.Background(), net.ParseIP("192.0.2.1"), "example.test", "sender@example.test", Options{Resolver: r, Time: time.Unix(42, 0)})
		if calls > 150 {
			t.Fatalf("unbounded DNS work: %d calls", calls)
		}
	})
}
