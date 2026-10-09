// Command fsrv serves 10 MB of random data at /10M (e2e MTU checks: a bulk
// TCP transfer through the tunnels).
//
//	fsrv ADDR                       HTTP on ADDR
//	fsrv -dns ADDR NAME=IP...       DNS on ADDR (UDP): A records of the names and
//	                                their subdomains, others NXDOMAIN
package main

import (
	"crypto/rand"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/miekg/dns"
)

func main() {
	if len(os.Args) > 2 && os.Args[1] == "-dns" {
		serveDNS(os.Args[2], os.Args[3:])
		return
	}
	buf := make([]byte, 10_000_000)
	_, _ = rand.Read(buf)
	http.HandleFunc("/10M", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(buf) })
	_ = http.ListenAndServe(os.Args[1], nil)
}

func serveDNS(addr string, records []string) {
	a := map[string]net.IP{}
	for _, r := range records {
		name, ip, _ := strings.Cut(r, "=")
		a[dns.Fqdn(strings.ToLower(name))] = net.ParseIP(ip).To4()
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		var ip net.IP
		ok := false
		for name, v := range a { // the name and its subdomains
			if n := strings.ToLower(q.Name); n == name || strings.HasSuffix(n, "."+name) {
				ip, ok = v, true
			}
		}
		switch {
		case !ok:
			m.Rcode = dns.RcodeNameError
		case q.Qtype == dns.TypeA:
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: ip}}
		}
		_ = w.WriteMsg(m)
	})
	_ = (&dns.Server{Addr: addr, Net: "udp", Handler: h}).ListenAndServe()
}
