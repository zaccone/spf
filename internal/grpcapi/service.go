// Package grpcapi adapts the SPF library to the versioned gRPC API.
package grpcapi

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/mail"
	"strings"
	"time"

	spf "github.com/zaccone/spf"
	spfv1 "github.com/zaccone/spf/api/spf/v1"
	"github.com/zaccone/spf/internal/identity"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Config contains server-owned settings; clients cannot change DNS or capacity.
type Config struct {
	Resolver  spf.ContextResolver
	Receiver  string
	Timeout   time.Duration
	MaxChecks int
	Logger    *slog.Logger
}

// Service bounds evaluations across all client connections without queuing.
type Service struct {
	spfv1.UnimplementedSPFServiceServer
	config Config
	slots  chan struct{}
}

func New(config Config) (*Service, error) {
	if config.Resolver == nil || config.Timeout <= 0 || config.Timeout > 20*time.Second || config.MaxChecks <= 0 {
		return nil, errors.New("resolver, timeout (0,20s], and positive max checks are required")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Service{config: config, slots: make(chan struct{}, config.MaxChecks)}, nil
}

func (s *Service) Check(ctx context.Context, req *spfv1.CheckRequest) (*spfv1.CheckResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	ip, domain, sender, err := validate(req)
	if err != nil {
		return nil, err
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return nil, status.Error(codes.ResourceExhausted, "SPF evaluation capacity exhausted")
	}
	checkctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
	started := time.Now()
	result, explanation, _ := spf.CheckHostWithOptions(checkctx, ip, domain, sender, spf.Options{
		Resolver: s.config.Resolver, Receiver: s.config.Receiver, HELO: req.GetHelo(),
	})
	// Caller cancellation is an RPC failure. An internal evaluation deadline is
	// an SPF outcome; notably, explanation timeouts must preserve SPF fail.
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	wire, ok := wireResult(result)
	if !ok {
		return nil, status.Error(codes.Internal, "unexpected SPF result")
	}
	s.config.Logger.Info("SPF gRPC evaluation", "result", result.String(), "elapsed_ms", time.Since(started).Milliseconds())
	return &spfv1.CheckResponse{Result: wire, Explanation: explanation}, nil
}

func validate(req *spfv1.CheckRequest) (net.IP, string, string, error) {
	invalid := func(message string) (net.IP, string, string, error) {
		return nil, "", "", status.Error(codes.InvalidArgument, message)
	}
	if req == nil {
		return invalid("request is required")
	}
	for _, value := range []string{req.ClientIp, req.Sender, req.Helo, req.Domain} {
		if len(value) > 4096 {
			return invalid("identity field exceeds 4096 bytes")
		}
		for _, c := range []byte(value) {
			if c < 32 || c >= 127 {
				return invalid("identities must contain printable ASCII")
			}
		}
	}
	ip := net.ParseIP(req.ClientIp)
	if ip == nil {
		return invalid("client_ip must be a literal IP address")
	}
	sender := identity.NormalizeSender(req.Sender)
	if sender != "" {
		address, err := mail.ParseAddress(sender)
		if err != nil || address.Name != "" || strings.HasPrefix(sender, "<") {
			return invalid("sender must be an envelope mailbox")
		}
		// Also apply the existing daemon's identity convention.
		if _, err := identity.Domain(sender, req.Helo); err != nil {
			return invalid("invalid envelope sender")
		}
	}
	domain := req.Domain
	if domain == "" {
		var err error
		domain, err = identity.Domain(sender, req.Helo)
		if err != nil {
			return invalid("null sender requires HELO or domain")
		}
	}
	return ip, domain, sender, nil
}

func wireResult(result spf.Result) (spfv1.Result, bool) {
	switch result {
	case spf.None:
		return spfv1.Result_RESULT_NONE, true
	case spf.Neutral:
		return spfv1.Result_RESULT_NEUTRAL, true
	case spf.Pass:
		return spfv1.Result_RESULT_PASS, true
	case spf.Fail:
		return spfv1.Result_RESULT_FAIL, true
	case spf.Softfail:
		return spfv1.Result_RESULT_SOFTFAIL, true
	case spf.Temperror:
		return spfv1.Result_RESULT_TEMPERROR, true
	case spf.Permerror:
		return spfv1.Result_RESULT_PERMERROR, true
	default:
		return spfv1.Result_RESULT_UNSPECIFIED, false
	}
}
