package dnscompat

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	dns "codeberg.org/miekg/dns"
)

// A pipe makes read entry observable without depending on DNS servers, packet
// scheduling, or elapsed time to guess whether Exchange has begun reading.
type observedConn struct {
	net.Conn
	reading chan struct{}
	once    sync.Once
}

func (c *observedConn) Read(b []byte) (int, error) {
	c.once.Do(func() { close(c.reading) })
	return c.Conn.Read(b)
}

func TestCancellationDuringRead(t *testing.T) {
	for _, closeOnCancel := range []bool{false, true} {
		name := "native"
		if closeOnCancel {
			name = "owned-connection"
		}
		t.Run(name, func(t *testing.T) {
			clientConn, peer := net.Pipe()
			conn := &observedConn{Conn: clientConn, reading: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			peerDone := make(chan struct{})
			finished := make(chan struct{})
			go func() {
				defer close(peerDone)
				// Read the request but never send a response.
				_, _ = io.Copy(io.Discard, peer)
			}()
			defer func() {
				conn.Close()
				peer.Close()
				<-peerDone
				<-finished
			}()

			client := dns.NewClient()
			client.ReadTimeout = 5 * time.Second
			done := make(chan error, 1)
			go func() {
				defer close(finished)
				if closeOnCancel {
					stopped := make(chan struct{})
					stop := context.AfterFunc(ctx, func() { conn.Close(); close(stopped) })
					defer func() {
						if !stop() {
							<-stopped
						}
						conn.Close()
					}()
				}
				_, _, err := client.ExchangeWithConn(ctx, dns.NewMsg("cancel.test.", dns.TypeTXT), conn)
				done <- errors.Join(ctx.Err(), err)
			}()
			select {
			case <-conn.reading:
			case err := <-done:
				t.Fatalf("exchange ended before reading: %v", err)
			case <-time.After(time.Second):
				t.Fatal("exchange never reached the response read")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("lost context cause: %v", err)
				}
				t.Log("cancellation interrupted an in-flight read")
			case <-time.After(250 * time.Millisecond):
				// Release and join the exchange before reporting any failure.
				conn.Close()
				<-done
				if closeOnCancel {
					t.Fatal("owned connection did not interrupt the read")
				}
				t.Log("TRANSPORT REQUIREMENT: native context cancellation did not interrupt the read; the owned-connection case supplies the required close")
			}
		})
	}
}
