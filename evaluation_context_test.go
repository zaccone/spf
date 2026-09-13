package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

type contextFixture struct {
	txt func(context.Context, string) ([]string, error)
	ip  func(context.Context, string, string) ([]net.IP, error)
	mx  func(context.Context, string) ([]*net.MX, error)
	ptr func(context.Context, string) ([]string, error)
}

func (r *contextFixture) LookupTXTContext(c context.Context, n string) ([]string, error) {
	if r.txt != nil {
		return r.txt(c, n)
	}
	return nil, nil
}
func (r *contextFixture) LookupIPContext(c context.Context, f, n string) ([]net.IP, error) {
	if r.ip != nil {
		return r.ip(c, f, n)
	}
	return nil, nil
}
func (r *contextFixture) LookupMXContext(c context.Context, n string) ([]*net.MX, error) {
	if r.mx != nil {
		return r.mx(c, n)
	}
	return nil, nil
}
func (r *contextFixture) LookupAddrContext(c context.Context, n string) ([]string, error) {
	if r.ptr != nil {
		return r.ptr(c, n)
	}
	return nil, nil
}
func recordFixture(record string) *contextFixture {
	return &contextFixture{txt: func(context.Context, string) ([]string, error) { return []string{record}, nil }}
}
func runContext(t *testing.T, r ContextResolver, want Result, cause error) {
	t.Helper()
	result, _, err := CheckHostWithOptions(context.Background(), net.ParseIP("192.0.2.1"), "example.test", "sender@example.test", Options{Resolver: r})
	if result != want || !errors.Is(err, cause) {
		t.Fatalf("got %v, %v; want %v, %v", result, err, want, cause)
	}
}

func TestEvaluationTermBoundary(t *testing.T) {
	for _, count := range []int{10, 11} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			r := recordFixture("v=spf1" + strings.Repeat(" a", count) + " -all exp=explain.test")
			calls, txts := 0, 0
			r.txt = func(_ context.Context, n string) ([]string, error) {
				txts++
				if n == "explain.test." {
					return []string{"denied"}, nil
				}
				return []string{"v=spf1" + strings.Repeat(" a", count) + " -all exp=explain.test"}, nil
			}
			r.ip = func(context.Context, string, string) ([]net.IP, error) {
				calls++
				return []net.IP{net.ParseIP("192.0.2.2")}, nil
			}
			result, exp, err := CheckHostWithOptions(context.Background(), net.ParseIP("192.0.2.1"), "example.test", "", Options{Resolver: r})
			if calls != 10 {
				t.Fatalf("dispatched %d address calls", calls)
			}
			if count == 10 {
				if result != Fail || exp != "denied" || err != nil || txts != 2 {
					t.Fatalf("%v %q %v; TXT=%d", result, exp, err, txts)
				}
			} else if result != Permerror || !errors.Is(err, ErrDNSLimitExceeded) || txts != 1 {
				t.Fatalf("%v %v; TXT=%d", result, err, txts)
			}
		})
	}
}

func TestEvaluationRecursiveBudgets(t *testing.T) {
	for _, term := range []string{"include:", "redirect="} {
		for _, count := range []int{10, 11} {
			t.Run(fmt.Sprintf("%s%d", term, count), func(t *testing.T) {
				calls := 0
				r := &contextFixture{txt: func(context.Context, string) ([]string, error) {
					calls++
					if calls <= count {
						return []string{"v=spf1 " + term + "next.test"}, nil
					}
					return []string{"v=spf1 +all"}, nil
				}}
				if count == 10 {
					runContext(t, r, Pass, nil)
				} else {
					runContext(t, r, Permerror, ErrDNSLimitExceeded)
				}
				if calls != 11 {
					t.Fatalf("TXT lookups=%d, want 11 (initial plus ten terms)", calls)
				}
			})
		}
		t.Run(term+"cycle", func(t *testing.T) {
			calls := 0
			r := &contextFixture{txt: func(context.Context, string) ([]string, error) {
				calls++
				return []string{"v=spf1 " + term + "example.test"}, nil
			}}
			runContext(t, r, Permerror, ErrDNSLimitExceeded)
			if calls != 11 {
				t.Fatalf("cycle dispatched %d TXT lookups", calls)
			}
		})
	}
	// Sibling includes share the same counter as their child mechanisms.
	r := &contextFixture{txt: func(_ context.Context, n string) ([]string, error) {
		if n == "example.test." {
			return []string{"v=spf1" + strings.Repeat(" include:child.test", 6) + " +all"}, nil
		}
		return []string{"v=spf1 a -all"}, nil
	}, ip: func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.2")}, nil
	}}
	runContext(t, r, Permerror, ErrDNSLimitExceeded)
}

func TestEvaluationVoidBoundary(t *testing.T) {
	for _, absence := range []error{nil, &net.DNSError{Err: "localized missing name", IsNotFound: true}} {
		for _, count := range []int{2, 3} {
			t.Run(fmt.Sprintf("%v/%d", absence, count), func(t *testing.T) {
				calls := 0
				r := recordFixture("v=spf1" + strings.Repeat(" a", count) + " +all")
				r.ip = func(context.Context, string, string) ([]net.IP, error) { calls++; return nil, absence }
				if count == 2 {
					runContext(t, r, Pass, nil)
				} else {
					runContext(t, r, Permerror, ErrDNSLimitExceeded)
				}
				if calls != count {
					t.Fatalf("got %d calls", calls)
				}
			})
		}
	}
	// Empty child address answers are shared with the parent and siblings.
	r := &contextFixture{txt: func(_ context.Context, n string) ([]string, error) {
		if n == "example.test." {
			return []string{"v=spf1 include:child.test include:child.test a +all"}, nil
		}
		return []string{"v=spf1 a -all"}, nil
	}}
	runContext(t, r, Permerror, ErrDNSLimitExceeded)
}

func TestEvaluationMXDispatch(t *testing.T) {
	for _, count := range []int{10, 11} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			calls := 0
			r := recordFixture("v=spf1 mx -all")
			r.mx = func(context.Context, string) ([]*net.MX, error) {
				var mxs []*net.MX
				for i := 0; i < count; i++ {
					mxs = append(mxs, &net.MX{Host: fmt.Sprintf("mx%d.test.", i)})
				}
				return mxs, nil
			}
			r.ip = func(_ context.Context, f, n string) ([]net.IP, error) {
				calls++
				if f != "ip4" {
					t.Fatal(f)
				}
				if n == "mx9.test." {
					return []net.IP{net.ParseIP("192.0.2.1")}, nil
				}
				return []net.IP{net.ParseIP("192.0.2.2")}, nil
			}
			if count == 10 {
				runContext(t, r, Pass, nil)
				if calls != 10 {
					t.Fatal(calls)
				}
			} else {
				runContext(t, r, Permerror, ErrDNSLimitExceeded)
				if calls != 0 {
					t.Fatalf("oversized MX set dispatched %d addresses", calls)
				}
			}
		})
	}
	// Many returned addresses from one exchange are still one address lookup.
	r := recordFixture("v=spf1 mx -all")
	r.mx = func(context.Context, string) ([]*net.MX, error) { return []*net.MX{{Host: "mx.test."}}, nil }
	r.ip = func(context.Context, string, string) ([]net.IP, error) {
		ips := make([]net.IP, 20)
		for i := range ips {
			ips[i] = net.ParseIP("192.0.2.2")
		}
		ips[19] = net.ParseIP("192.0.2.1")
		return ips, nil
	}
	runContext(t, r, Pass, nil)
	// Absent and null MX sets must not fall back to the domain's addresses.
	for _, mxs := range [][]*net.MX{nil, {{Host: "."}}} {
		r.mx = func(context.Context, string) ([]*net.MX, error) { return mxs, nil }
		r.ip = func(context.Context, string, string) ([]net.IP, error) {
			t.Fatal("unexpected implicit MX lookup")
			return nil, nil
		}
		runContext(t, r, Fail, nil)
	}
}

func TestEvaluationFamily(t *testing.T) {
	for _, ip := range []string{"192.0.2.1", "2001:db8::1"} {
		for _, term := range []string{"a/24//64", "mx/24//64", "exists:target.test"} {
			t.Run(ip+term, func(t *testing.T) {
				r := recordFixture("v=spf1 " + term + " -all")
				r.mx = func(context.Context, string) ([]*net.MX, error) { return []*net.MX{{Host: "target.test."}}, nil }
				r.ip = func(_ context.Context, f, n string) ([]net.IP, error) {
					want := "ip4"
					if strings.Contains(ip, ":") && !strings.HasPrefix(term, "exists") {
						want = "ip6"
					}
					if f != want {
						t.Fatalf("network %s want %s", f, want)
					}
					if f == "ip4" {
						return []net.IP{net.ParseIP("192.0.2.99")}, nil
					}
					return []net.IP{net.ParseIP("2001:db8::99")}, nil
				}
				result, _, err := CheckHostWithOptions(context.Background(), net.ParseIP(ip), "example.test", "", Options{Resolver: r})
				if result != Pass || err != nil {
					t.Fatalf("%v %v", result, err)
				}
			})
		}
	}
}

func TestEvaluationCancellation(t *testing.T) {
	for _, operation := range []string{"txt", "a", "mx", "exists", "include", "redirect"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := recordFixture("v=spf1 " + operation + " +all")
			block := func(c context.Context) { cancel(); <-c.Done() }
			switch operation {
			case "txt":
				r.txt = func(c context.Context, _ string) ([]string, error) { block(c); return nil, c.Err() }
			case "a", "exists":
				r = recordFixture("v=spf1 a +all")
				if operation == "exists" {
					r = recordFixture("v=spf1 exists:target.test +all")
				}
				r.ip = func(c context.Context, _, _ string) ([]net.IP, error) { block(c); return nil, c.Err() }
			case "mx":
				r.mx = func(c context.Context, _ string) ([]*net.MX, error) { block(c); return nil, c.Err() }
			default:
				r.txt = func(c context.Context, n string) ([]string, error) {
					if n == "child.test." {
						block(c)
						return nil, c.Err()
					}
					term := "include:child.test"
					if operation == "redirect" {
						term = "redirect=child.test"
					}
					return []string{"v=spf1 " + term}, nil
				}
			}
			result, _, err := CheckHostWithOptions(ctx, net.ParseIP("192.0.2.1"), "example.test", "", Options{Resolver: r})
			if result != Temperror || !errors.Is(err, context.Canceled) {
				t.Fatalf("%v %v", result, err)
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	r := &contextFixture{txt: func(c context.Context, _ string) ([]string, error) { <-c.Done(); return nil, c.Err() }}
	result, _, err := CheckHostWithOptions(ctx, net.ParseIP("192.0.2.1"), "example.test", "", Options{Resolver: r})
	if result != Temperror || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v %v", result, err)
	}
}

func TestEvaluationSharedDeadline(t *testing.T) {
	var first context.Context
	calls := 0
	r := &contextFixture{txt: func(ctx context.Context, _ string) ([]string, error) {
		calls++
		if first == nil {
			first = ctx
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 20*time.Second {
				t.Fatal("missing default deadline")
			}
		} else if ctx != first {
			t.Fatal("recursion replaced evaluation context")
		}
		if calls == 1 {
			return []string{"v=spf1 redirect=child.test"}, nil
		}
		return []string{"v=spf1 +all"}, nil
	}}
	runContext(t, r, Pass, nil)
	if calls != 2 {
		t.Fatal(calls)
	}
}

func TestPTRValidationBudgetInfrastructure(t *testing.T) {
	calls := 0
	r := &contextFixture{ptr: func(context.Context, string) ([]string, error) {
		var names []string
		for i := 0; i < 11; i++ {
			names = append(names, fmt.Sprintf("ptr%d.test.", i))
		}
		return names, nil
	}, ip: func(context.Context, string, string) ([]net.IP, error) {
		calls++
		return []net.IP{net.ParseIP("192.0.2.1")}, nil
	}}
	e := &evaluation{ctx: context.Background(), dns: r, network: "ip4"}
	names, err := e.validatedNames(net.ParseIP("192.0.2.1"))
	if err != nil || len(names) != 10 || calls != 10 {
		t.Fatalf("names=%d calls=%d err=%v", len(names), calls, err)
	}
	r.ip = func(context.Context, string, string) ([]net.IP, error) { return nil, nil }
	e.voids = 0
	_, err = e.validatedNames(net.ParseIP("192.0.2.1"))
	if !errors.Is(err, ErrDNSLimitExceeded) {
		t.Fatal(err)
	}
	e.dns = nil
	if _, err = e.validatedNames(net.ParseIP("192.0.2.1")); !errors.Is(err, ErrUnsupportedResolver) {
		t.Fatal(err)
	}
}

func TestLegacyResolverTermBudget(t *testing.T) {
	r := &evaluationResolver{records: map[string][]string{"example.test.": {"v=spf1 include:example.test"}}}
	result, _, err := CheckHostWithResolver(net.ParseIP("192.0.2.1"), "example.test", "", r)
	if result != Permerror || !errors.Is(err, ErrDNSLimitExceeded) {
		t.Fatalf("%v %v", result, err)
	}
}

func TestContextEvaluationErrorPropagation(t *testing.T) {
	missing := &net.DNSError{Err: "absent", IsNotFound: true}
	transport := &net.DNSError{Err: "transport failure", IsTemporary: true}
	for _, term := range []string{"a", "mx", "exists:target.test", "include:target.test", "redirect=target.test"} {
		for _, cause := range []error{missing, transport, ErrDNSLimitExceeded} {
			t.Run(fmt.Sprintf("%s/%v", term, cause), func(t *testing.T) {
				wrapped := fmt.Errorf("fixture: %w", cause)
				r := recordFixture("v=spf1 " + term + " +all")
				if strings.HasPrefix(term, "redirect") {
					r = recordFixture("v=spf1 " + term)
				}
				original := r.txt
				r.txt = func(ctx context.Context, n string) ([]string, error) {
					if n == "target.test." {
						return nil, wrapped
					}
					return original(ctx, n)
				}
				r.ip = func(context.Context, string, string) ([]net.IP, error) { return nil, wrapped }
				r.mx = func(context.Context, string) ([]*net.MX, error) { return nil, wrapped }
				want := Temperror
				wantErr := cause
				if cause == ErrDNSLimitExceeded {
					want = Permerror
				}
				if cause == missing {
					want = Pass
					wantErr = nil
					if strings.HasPrefix(term, "include") || strings.HasPrefix(term, "redirect") {
						want = Permerror
						wantErr = cause
					}
				}
				runContext(t, r, want, wantErr)
			})
		}
	}
}

func TestContextEvaluationReuse(t *testing.T) {
	r := recordFixture("v=spf1" + strings.Repeat(" a", 10) + " -all")
	r.ip = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.2")}, nil
	}
	runContext(t, r, Fail, nil)
	runContext(t, r, Fail, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.txt = func(context.Context, string) ([]string, error) {
		t.Fatal("canceled evaluation dispatched DNS")
		return nil, nil
	}
	result, _, err := CheckHostWithOptions(ctx, net.ParseIP("192.0.2.1"), "example.test", "", Options{Resolver: r})
	if result != Temperror || !errors.Is(err, context.Canceled) {
		t.Fatalf("%v %v", result, err)
	}
}

func TestCancellationPreservesDNSError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	missing := &net.DNSError{Err: "missing at cancellation", IsNotFound: true}
	r := &contextFixture{txt: func(context.Context, string) ([]string, error) { cancel(); return nil, missing }}
	result, _, err := CheckHostWithOptions(ctx, net.ParseIP("192.0.2.1"), "example.test", "", Options{Resolver: r})
	var de *net.DNSError
	if result != Temperror || !errors.Is(err, context.Canceled) || !errors.As(err, &de) || de != missing {
		t.Fatalf("lost cancellation or DNS cause: %v %v", result, err)
	}
}
