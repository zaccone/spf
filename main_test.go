package spf

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var testResolver Resolver

func TestMain(m *testing.M) {
	s, err := runLocalUDPServer("127.0.0.1:0")
	if err != nil {
		panic(fmt.Sprintf("unable to run local server: %v", err))
	}

	dns.HandleFunc(".", rootZone)

	defer func() {
		dns.HandleRemove(".")
		_ = s.Shutdown()
	}()

	testResolver = NewMiekgDNSResolver(s.PacketConn.LocalAddr().String())
	os.Exit(m.Run())
}

func runLocalUDPServer(laddr string) (*dns.Server, error) {
	pc, err := net.ListenPacket("udp", laddr)
	if err != nil {
		return nil, err
	}
	server := &dns.Server{PacketConn: pc, ReadTimeout: time.Second, WriteTimeout: time.Second}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	go func() {
		_ = server.ActivateAndServe()
		_ = pc.Close()
	}()

	waitLock.Lock()
	return server, nil
}

func rootZone(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	switch req.Question[0].Name {
	case ".":
		m.SetReply(req)
		rr, _ := dns.NewRR(". 0 IN SOA a.root-servers.net. nstld.verisign-grs.com. 2016110600 1800 900 604800 86400")
		m.Ns = []dns.RR{rr}
	default:
		m.SetRcode(req, dns.RcodeNameError)
	}
	_ = w.WriteMsg(m)
}

func zone(zone map[uint16][]string) func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)

		rr, ok := zone[req.Question[0].Qtype]
		if !ok {
			_ = w.WriteMsg(m)
			return
		}
		m.Answer = make([]dns.RR, 0, len(rr))
		for _, r := range rr {
			if !strings.HasPrefix(r, req.Question[0].Name) {
				continue
			}
			a, err := dns.NewRR(r)
			if err != nil {
				fmt.Printf("unable to prepare dns response: %s\n", err)
				continue
			}
			m.Answer = append(m.Answer, a)
		}
		_ = w.WriteMsg(m)
	}
}
