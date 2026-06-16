package guard

import (
	"log"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"
	"github.com/tpt-av/tpt-av/internal/config"
	"github.com/tpt-av/tpt-av/internal/events"
)

// PhishingChecker blocks domains known to be phishing sites.
type PhishingChecker interface {
	IsPhishing(domain string) bool
}

// IPReputationChecker blocks IPs with a bad abuse score.
type IPReputationChecker interface {
	IsAbusive(ip string) bool
}

// DNSResolver is a local stub resolver that:
//   - Enforces domain allow-lists (default-deny policy)
//   - Blocks phishing domains (optional)
//   - Blocks resolved IPs with high AbuseIPDB confidence (optional)
//   - Forwards allowed queries over DoH or plain UDP
type DNSResolver struct {
	cfg      config.GuardConfig
	log      *events.Logger
	server   *dns.Server
	allowed  []string
	phishing PhishingChecker
	abuseIP  IPReputationChecker
}

func NewDNSResolver(cfg config.GuardConfig, log *events.Logger,
	phishing PhishingChecker, abuseIP IPReputationChecker) *DNSResolver {

	patterns := make([]string, 0, len(cfg.Allow.Domains)+4)
	for _, d := range cfg.Allow.Domains {
		patterns = append(patterns, d.Pattern)
	}
	for _, p := range cfg.Allow.Processes {
		patterns = append(patterns, p.Domains...)
	}
	return &DNSResolver{
		cfg:      cfg,
		log:      log,
		allowed:  patterns,
		phishing: phishing,
		abuseIP:  abuseIP,
	}
}

func (r *DNSResolver) Stop() {
	if r.server != nil {
		r.server.Shutdown()
	}
}

func (r *DNSResolver) handle(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = false

	for _, q := range req.Question {
		name := strings.TrimSuffix(q.Name, ".")

		// Default-deny allow-list check
		if r.cfg.Network.DefaultPolicy == "deny" && !r.domainAllowed(name) {
			m.Rcode = dns.RcodeNameError
			r.log.Write(events.New(events.SourceGuard, "connection_blocked", events.Info,
				map[string]string{"domain": name, "reason": "not_whitelisted"}))
			w.WriteMsg(m)
			return
		}

		// Phishing domain check
		if r.phishing != nil && r.phishing.IsPhishing(name) {
			m.Rcode = dns.RcodeNameError
			r.log.Write(events.New(events.SourceGuard, "connection_blocked", events.Warn,
				map[string]string{"domain": name, "reason": "phishing"}))
			w.WriteMsg(m)
			return
		}
	}

	// Forward upstream
	resp := r.forwardUpstream(req)
	if resp == nil {
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}

	// AbuseIPDB check on resolved IPs (non-blocking — block and log if abusive)
	if r.abuseIP != nil {
		for _, ans := range resp.Answer {
			var ip string
			switch rr := ans.(type) {
			case *dns.A:
				ip = rr.A.String()
			case *dns.AAAA:
				ip = rr.AAAA.String()
			}
			if ip != "" && r.abuseIP.IsAbusive(ip) {
				m.Rcode = dns.RcodeNameError
				var name string
				if len(req.Question) > 0 {
					name = strings.TrimSuffix(req.Question[0].Name, ".")
				}
				r.log.Write(events.New(events.SourceGuard, "connection_blocked", events.Warn,
					map[string]string{"domain": name, "ip": ip, "reason": "abuseipdb"}))
				w.WriteMsg(m)
				return
			}
		}
	}

	resp.Id = req.Id
	w.WriteMsg(resp)
}

// forwardUpstream tries DoH first (if configured), then falls back to plain UDP.
func (r *DNSResolver) forwardUpstream(req *dns.Msg) *dns.Msg {
	if r.cfg.Network.DoHUpstream != "" {
		resp, err := resolveDoH(r.cfg.Network.DoHUpstream, req)
		if err == nil {
			return resp
		}
		log.Printf("DoH failed (%v), falling back to UDP", err)
	}

	upstream := r.cfg.Network.DNSUpstream
	if upstream == "" {
		upstream = "8.8.8.8:53"
	}
	c := new(dns.Client)
	resp, _, err := c.Exchange(req, upstream)
	if err != nil || resp == nil {
		return nil
	}
	return resp
}

// domainAllowed checks whether name matches any whitelisted pattern.
func (r *DNSResolver) domainAllowed(name string) bool {
	for _, pattern := range r.allowed {
		if matched, _ := filepath.Match(pattern, name); matched {
			return true
		}
		suffix := strings.TrimPrefix(pattern, "*.")
		if strings.HasSuffix(name, "."+suffix) || name == suffix {
			return true
		}
	}
	return false
}

