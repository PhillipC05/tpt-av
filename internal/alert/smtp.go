package alert

import (
	"fmt"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/tpt-av/tpt-av/internal/config"
	"github.com/tpt-av/tpt-av/internal/events"
)

type Mailer struct {
	cfg      config.AlertConfig
	cooldown time.Duration
	minSev   events.Severity
	mu       sync.Mutex
	lastSent map[string]time.Time // event type → last send time
}

var severityOrder = map[events.Severity]int{
	events.Debug:    0,
	events.Info:     1,
	events.Warn:     2,
	events.Critical: 3,
}

func New(cfg config.AlertConfig) (*Mailer, error) {
	cooldown, err := time.ParseDuration(cfg.Cooldown)
	if err != nil {
		cooldown = 5 * time.Minute
	}
	minSev := events.Severity(cfg.MinSeverity)
	if _, ok := severityOrder[minSev]; !ok {
		minSev = events.Warn
	}
	return &Mailer{
		cfg:      cfg,
		cooldown: cooldown,
		minSev:   minSev,
		lastSent: make(map[string]time.Time),
	}, nil
}

// Send sends an alert email for the given event, respecting cooldown and severity threshold.
func (m *Mailer) Send(e events.Event) error {
	if m.cfg.SMTPHost == "" || len(m.cfg.Recipients) == 0 {
		return nil
	}
	if severityOrder[e.Severity] < severityOrder[m.minSev] {
		return nil
	}

	m.mu.Lock()
	last, ok := m.lastSent[e.Type]
	if ok && time.Since(last) < m.cooldown {
		m.mu.Unlock()
		return nil // still in cooldown
	}
	m.lastSent[e.Type] = time.Now()
	m.mu.Unlock()

	return m.send(e)
}

func (m *Mailer) send(e events.Event) error {
	hostPort := m.cfg.SMTPHost
	parts := strings.SplitN(hostPort, ":", 2)
	host := parts[0]

	var auth smtp.Auth
	if m.cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", m.cfg.SMTPUser, m.cfg.SMTPPass, host)
	}

	subject := fmt.Sprintf("[tpt-av] %s: %s", strings.ToUpper(string(e.Severity)), e.Type)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Time:     %s\n", e.TS.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Source:   %s\n", e.Source))
	sb.WriteString(fmt.Sprintf("Type:     %s\n", e.Type))
	sb.WriteString(fmt.Sprintf("Severity: %s\n", e.Severity))
	if len(e.Data) > 0 {
		sb.WriteString("\nDetails:\n")
		for k, v := range e.Data {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
		}
	}

	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		m.cfg.SMTPUser,
		strings.Join(m.cfg.Recipients, ", "),
		subject,
		sb.String(),
	)

	return smtp.SendMail(hostPort, auth, m.cfg.SMTPUser, m.cfg.Recipients, []byte(msg))
}
