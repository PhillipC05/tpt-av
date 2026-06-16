//go:build linux

package guard

import (
	"github.com/miekg/dns"
)

// Start begins listening for DNS queries on the configured listen address.
func (r *DNSResolver) Start() error {
	listen := r.cfg.Network.DNSListen
	if listen == "" {
		listen = "127.0.0.1:5353"
	}
	r.server = &dns.Server{
		Addr:    listen,
		Net:     "udp",
		Handler: dns.HandlerFunc(r.handle),
	}
	go r.server.ListenAndServe()
	return nil
}
