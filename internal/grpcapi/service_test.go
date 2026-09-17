package grpcapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	spfv1 "github.com/zaccone/spf/api/spf/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type resolver struct {
	txt func(context.Context, string) ([]string, error)
}

func (r resolver) LookupTXTContext(ctx context.Context, name string) ([]string, error) {
	return r.txt(ctx, name)
}
func (resolver) LookupIPContext(context.Context, string, string) ([]net.IP, error) {
	panic("unexpected IP lookup")
}
func (resolver) LookupMXContext(context.Context, string) ([]*net.MX, error) {
	panic("unexpected MX lookup")
}
func (resolver) LookupAddrContext(context.Context, string) ([]string, error) {
	panic("unexpected PTR lookup")
}
func service(t *testing.T, txt func(context.Context, string) ([]string, error), timeout time.Duration) *Service {
	t.Helper()
	s, err := New(Config{Resolver: resolver{txt}, Timeout: timeout, MaxChecks: 1, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func request() *spfv1.CheckRequest {
	return &spfv1.CheckRequest{ClientIp: "192.0.2.1", Sender: "a@example.test", Helo: "helo.example.test"}
}

func TestResults(t *testing.T) {
	for _, tt := range []struct {
		policy string
		dnsErr error
		want   spfv1.Result
	}{
		{"v=spf1 +all", nil, spfv1.Result_RESULT_PASS},
		{"v=spf1 -all", nil, spfv1.Result_RESULT_FAIL},
		{"v=spf1 ~all", nil, spfv1.Result_RESULT_SOFTFAIL},
		{"v=spf1 ?all", nil, spfv1.Result_RESULT_NEUTRAL},
		{"", nil, spfv1.Result_RESULT_NONE},
		{"v=spf1 invalid", nil, spfv1.Result_RESULT_PERMERROR},
		{"", errors.New("DNS unavailable"), spfv1.Result_RESULT_TEMPERROR},
	} {
		t.Run(tt.want.String(), func(t *testing.T) {
			s := service(t, func(context.Context, string) ([]string, error) { return []string{tt.policy}, tt.dnsErr }, time.Second)
			got, err := s.Check(context.Background(), request())
			if err != nil || got.GetResult() != tt.want {
				t.Fatalf("%v, %v", got, err)
			}
		})
	}
}
func TestInvalidRequests(t *testing.T) {
	s := service(t, func(context.Context, string) ([]string, error) { t.Fatal("unexpected DNS"); return nil, nil }, time.Second)
	for _, change := range []func(*spfv1.CheckRequest){
		func(r *spfv1.CheckRequest) { r.ClientIp = "bad" },
		func(r *spfv1.CheckRequest) { r.Sender = "bad"; r.Domain = "example.test" },
		func(r *spfv1.CheckRequest) { r.Sender = ""; r.Helo = "" },
		func(r *spfv1.CheckRequest) { r.Sender = "A <a@example.test>" },
		func(r *spfv1.CheckRequest) { r.Sender = "a@@example.test" },
		func(r *spfv1.CheckRequest) { r.Helo = "a\n.example" },
		func(r *spfv1.CheckRequest) { r.Domain = "é.example" },
		func(r *spfv1.CheckRequest) { r.Helo = strings.Repeat("a", 4097) },
	} {
		req := request()
		change(req)
		if _, err := s.Check(context.Background(), req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%v: %v", req, err)
		}
	}
	if _, err := s.Check(context.Background(), nil); status.Code(err) != codes.InvalidArgument {
		t.Fatal(err)
	}
}
func TestIdentitySelection(t *testing.T) {
	for _, tt := range []struct{ sender, helo, domain, want string }{
		{"", "helo.example", "", "helo.example."},
		{"<>", "helo.example", "", "helo.example."},
		{"", "", "override.example", "override.example."},
		{"a@example.test", "helo.example", "override.example", "override.example."},
		{`"a<>b"@example.test`, "", "", "example.test."},
	} {
		s := service(t, func(_ context.Context, name string) ([]string, error) {
			if name != tt.want {
				t.Errorf("got %s want %s", name, tt.want)
			}
			return []string{"v=spf1 +all"}, nil
		}, time.Second)
		got, err := s.Check(context.Background(), &spfv1.CheckRequest{ClientIp: "2001:db8::1", Sender: tt.sender, Helo: tt.helo, Domain: tt.domain})
		if err != nil || got.GetResult() != spfv1.Result_RESULT_PASS {
			t.Fatalf("%v %v", got, err)
		}
	}
	s := service(t, func(context.Context, string) ([]string, error) { t.Fatal("unexpected DNS"); return nil, nil }, time.Second)
	got, err := s.Check(context.Background(), &spfv1.CheckRequest{ClientIp: "192.0.2.1", Helo: "[192.0.2.1]"})
	if err != nil || got.GetResult() != spfv1.Result_RESULT_NONE {
		t.Fatalf("%v %v", got, err)
	}
}
func TestOverloadCancellationAndSlotRelease(t *testing.T) {
	entered := make(chan struct{}, 1)
	s := service(t, func(ctx context.Context, _ string) ([]string, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := s.Check(ctx, request()); done <- err }()
	<-entered
	if _, err := s.Check(context.Background(), request()); status.Code(err) != codes.ResourceExhausted {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; status.Code(err) != codes.Canceled {
		t.Fatal(err)
	}
	if len(s.slots) != 0 {
		t.Fatal("leaked slot")
	}
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel2()
	if _, err := s.Check(ctx, request()); status.Code(err) != codes.DeadlineExceeded {
		t.Fatal(err)
	}
}
func TestEvaluationAndExplanationTimeouts(t *testing.T) {
	for _, explanation := range []bool{false, true} {
		s := service(t, func(ctx context.Context, name string) ([]string, error) {
			if explanation && name == "example.test." {
				return []string{"v=spf1 -all exp=explain.test"}, nil
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}, 10*time.Millisecond)
		got, err := s.Check(context.Background(), request())
		want := spfv1.Result_RESULT_TEMPERROR
		if explanation {
			want = spfv1.Result_RESULT_FAIL
		}
		if err != nil || got.GetResult() != want {
			t.Fatalf("explanation=%v: %v %v", explanation, got, err)
		}
	}
}
func TestExplanation(t *testing.T) {
	s := service(t, func(_ context.Context, name string) ([]string, error) {
		if name == "example.test." {
			return []string{"v=spf1 -all exp=explain.test"}, nil
		}
		return []string{"not authorized"}, nil
	}, time.Second)
	got, err := s.Check(context.Background(), request())
	if err != nil || got.GetExplanation() != "not authorized" {
		t.Fatalf("%v %v", got, err)
	}
}
