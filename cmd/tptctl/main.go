package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	guardAddr  = "http://127.0.0.1:7731"
	patrolAddr = "http://127.0.0.1:7732"
)

// apiToken holds the bearer token for authenticated API calls.
// Set via --token flag or read automatically from the platform token file.
var apiToken string

func tokenFilePath() string {
	if runtime.GOOS == "windows" {
		return os.Getenv("ProgramData") + `\TPT\api.token`
	}
	return "/etc/tpt/api.token"
}

func main() {
	root := &cobra.Command{
		Use:   "tptctl",
		Short: "TPT-AV control CLI",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if apiToken == "" {
				if data, err := os.ReadFile(tokenFilePath()); err == nil {
					apiToken = strings.TrimSpace(string(data))
				}
			}
		},
	}

	root.PersistentFlags().StringVar(&apiToken, "token", "", "API bearer token (overrides token file)")

	root.AddCommand(guardCmd())
	root.AddCommand(patrolCmd())
	root.AddCommand(eventsCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ─── guard ────────────────────────────────────────────────────────────────────

func guardCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "guard", Short: "Manage TPT Guard firewall"}

	// guard status
	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show Guard daemon status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return printJSON(get(guardAddr + "/status"))
		},
	})

	// guard rules
	rules := &cobra.Command{Use: "rules", Short: "Manage firewall rules"}

	rules.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List all whitelist rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return printJSON(get(guardAddr + "/rules"))
		},
	})

	var allowCIDR, allowComment string
	allowIP := &cobra.Command{
		Use:   "allow",
		Short: "Add an IP/CIDR allow rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			body := fmt.Sprintf(`{"cidr":%q,"comment":%q}`, allowCIDR, allowComment)
			return printJSON(post(guardAddr+"/rules/allow/ip", body))
		},
	}
	allowIP.Flags().StringVar(&allowCIDR, "ip", "", "IP or CIDR to allow (required)")
	allowIP.Flags().StringVar(&allowComment, "comment", "", "Optional comment")
	allowIP.MarkFlagRequired("ip")
	rules.AddCommand(allowIP)

	var denyID string
	denyCmd := &cobra.Command{
		Use:   "deny",
		Short: "Remove an allow rule by ID",
		RunE: func(cmd *cobra.Command, args []string) error {
			return printJSON(del(guardAddr + "/rules/" + denyID))
		},
	}
	denyCmd.Flags().StringVar(&denyID, "id", "", "Rule ID to remove (required)")
	denyCmd.MarkFlagRequired("id")
	rules.AddCommand(denyCmd)

	cmd.AddCommand(rules)
	return cmd
}

// ─── patrol ───────────────────────────────────────────────────────────────────

func patrolCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "patrol", Short: "Manage TPT Patrol scanner"}

	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show Patrol daemon status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return printJSON(get(patrolAddr + "/status"))
		},
	})

	var scanPath string
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Trigger an immediate scan",
		RunE: func(cmd *cobra.Command, args []string) error {
			url := patrolAddr + "/scan"
			if scanPath != "" {
				url += "?path=" + scanPath
			}
			return printJSON(post(url, "{}"))
		},
	}
	scanCmd.Flags().StringVar(&scanPath, "path", "", "Specific path to scan (optional)")
	cmd.AddCommand(scanCmd)

	var rebuild bool
	baselineCmd := &cobra.Command{
		Use:   "baseline",
		Short: "Show or rebuild the file-integrity baseline",
		RunE: func(cmd *cobra.Command, args []string) error {
			if rebuild {
				return printJSON(post(patrolAddr+"/baseline/rebuild", "{}"))
			}
			return printJSON(get(patrolAddr + "/baseline"))
		},
	}
	baselineCmd.Flags().BoolVar(&rebuild, "rebuild", false, "Rebuild the baseline from scratch")
	cmd.AddCommand(baselineCmd)

	// quarantine subcommands
	quar := &cobra.Command{Use: "quarantine", Short: "Manage quarantined files"}

	quar.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List quarantined files",
		RunE: func(cmd *cobra.Command, args []string) error {
			return printJSON(get(patrolAddr + "/quarantine"))
		},
	})

	quar.AddCommand(&cobra.Command{
		Use:   "restore [id]",
		Short: "Restore a quarantined file to its original path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return printJSON(post(patrolAddr+"/quarantine/"+args[0]+"/restore", "{}"))
		},
	})

	quar.AddCommand(&cobra.Command{
		Use:   "delete [id]",
		Short: "Permanently delete a quarantined file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return printJSON(del(patrolAddr + "/quarantine/" + args[0]))
		},
	})

	cmd.AddCommand(quar)
	return cmd
}

// ─── events ───────────────────────────────────────────────────────────────────

func eventsCmd() *cobra.Command {
	var tailMode bool
	var source, severity string
	var since string

	cmd := &cobra.Command{
		Use:   "events",
		Short: "View the shared event log",
		RunE: func(cmd *cobra.Command, args []string) error {
			if tailMode {
				return tailEvents(source, severity)
			}
			url := patrolAddr + "/events"
			if since != "" {
				url += "?since=" + since
			}
			return printJSON(get(url))
		},
	}
	cmd.Flags().BoolVar(&tailMode, "tail", false, "Stream events continuously")
	cmd.Flags().StringVar(&source, "source", "", "Filter by source: guard|patrol")
	cmd.Flags().StringVar(&severity, "severity", "", "Minimum severity: debug|info|warn|critical")
	cmd.Flags().StringVar(&since, "since", "", "RFC3339 timestamp to start from")
	return cmd
}

func tailEvents(source, severity string) error {
	last := time.Now().Add(-5 * time.Second)
	sevOrder := map[string]int{"debug": 0, "info": 1, "warn": 2, "critical": 3}
	minSev := sevOrder[severity]

	for {
		url := patrolAddr + "/events?since=" + last.Format(time.RFC3339Nano)
		body, err := get(url)
		if err == nil {
			var evts []map[string]any
			if json.Unmarshal([]byte(body), &evts) == nil {
				for _, e := range evts {
					if source != "" && e["source"] != source {
						continue
					}
					sev, _ := e["severity"].(string)
					if severity != "" && sevOrder[sev] < minSev {
						continue
					}
					b, _ := json.Marshal(e)
					fmt.Println(string(b))
				}
				if len(evts) > 0 {
					last = time.Now()
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

func addAuth(req *http.Request) {
	if apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+apiToken)
	}
}

func get(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	addAuth(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot connect to daemon (%s): %w", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func post(url, body string) (string, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	addAuth(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot connect to daemon (%s): %w", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func del(url string) (string, error) {
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return "", err
	}
	addAuth(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot connect to daemon (%s): %w", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func printJSON(body string, err error) error {
	if err != nil {
		return err
	}
	// Pretty-print if valid JSON
	var v any
	if json.Unmarshal([]byte(body), &v) == nil {
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Print(body)
	}
	return nil
}
