// Command testhost is a plain host for the routing integration test. It
// answers HTTP requests on :8000 with the client's address (to observe
// masquerading) and, when DNS_ANSWER is set, answers DNS queries for
// *.corp.test on :53 with that address (for split DNS).
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func main() {
	if a := os.Getenv("DNS_ANSWER"); a != "" {
		go serveDNS(netip.MustParseAddr(a))
	}
	srv := &http.Server{
		Addr:              ":8000",
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			fmt.Fprintln(w, host)
		}),
	}
	log.Fatal(srv.ListenAndServe())
}

func serveDNS(answer netip.Addr) {
	pc, err := net.ListenPacket("udp4", ":53")
	if err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			log.Fatal(err)
		}
		var m dnsmessage.Message
		if m.Unpack(buf[:n]) != nil || len(m.Questions) != 1 {
			continue
		}
		q := m.Questions[0]
		m.Response, m.Authoritative = true, true
		if !strings.HasSuffix(q.Name.String(), ".corp.test.") {
			m.RCode = dnsmessage.RCodeNameError
		} else if q.Type == dnsmessage.TypeA {
			m.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: answer.As4()},
			}}
		}
		out, err := m.Pack()
		if err == nil {
			_, _ = pc.WriteTo(out, from)
		}
	}
}
