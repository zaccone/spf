// Command grpc-client demonstrates a local SPF RPC with an explicit deadline.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	spfv1 "github.com/zaccone/spf/api/spf/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	target := flag.String("target", "127.0.0.1:50051", "local TCP address or unix:///absolute/socket/path")
	ip := flag.String("ip", "192.0.2.1", "SMTP client IP")
	sender := flag.String("sender", "sender@example.com", "envelope sender")
	helo := flag.String("helo", "", "HELO identity")
	domain := flag.String("domain", "", "optional policy domain override")
	flag.Parse()
	// This example is for the daemon's local-only, plaintext transport.
	conn, err := grpc.NewClient(*target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := spfv1.NewSPFServiceClient(conn).Check(ctx, &spfv1.CheckRequest{
		ClientIp: *ip, Sender: *sender, Helo: *helo, Domain: *domain,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// An SPF fail/temperror/permerror is a successful RPC, not a transport error.
	fmt.Printf("result=%s explanation=%q\n", response.GetResult(), response.GetExplanation())
}
