//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"time"

	"github.com/getlantern/systray"
)

const (
	guardURL  = "http://127.0.0.1:7731"
	patrolURL = "http://127.0.0.1:7732"
)

func main() {
	systray.Run(onReady, nil)
}

func onReady() {
	systray.SetTitle("TPT-AV")
	systray.SetTooltip("TPT-AV Security Suite")

	mDashboard := systray.AddMenuItem("Open Dashboard", "Open the TPT-AV web dashboard")
	mScan := systray.AddMenuItem("Trigger Scan", "Run an immediate file scan")
	mBackup := systray.AddMenuItem("Backup Now", "Run an immediate backup")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Exit", "Exit TPT-AV tray")

	// Start health polling
	go pollHealth()

	for {
		select {
		case <-mDashboard.ClickedCh:
			exec.Command("cmd", "/c", "start", guardURL).Start()
		case <-mScan.ClickedCh:
			go triggerScan()
		case <-mBackup.ClickedCh:
			go triggerBackup()
		case <-mQuit.ClickedCh:
			systray.Quit()
			return
		}
	}
}

// pollHealth checks both daemons every 60 seconds and updates the tray icon tooltip.
func pollHealth() {
	client := &http.Client{Timeout: 5 * time.Second}
	for {
		guardOK := ping(client, guardURL+"/status")
		patrolOK := ping(client, patrolURL+"/status")

		tooltip := "TPT-AV"
		switch {
		case guardOK && patrolOK:
			tooltip = "TPT-AV — All services running"
		case !guardOK && !patrolOK:
			tooltip = "TPT-AV — Services offline"
			systray.SetTooltip(tooltip)
		default:
			tooltip = "TPT-AV — Partial service failure"
		}
		systray.SetTooltip(tooltip)

		time.Sleep(60 * time.Second)
	}
}

func ping(client *http.Client, url string) bool {
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func triggerScan() {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(patrolURL+"/scan", "application/json", nil)
	if err != nil {
		log.Printf("trigger scan: %v", err)
		return
	}
	resp.Body.Close()
}

func triggerBackup() {
	// tpt-backup -run (start backup daemon in one-shot mode)
	if err := exec.Command("tpt-backup.exe", "-run").Start(); err != nil {
		log.Printf("trigger backup: %v", err)
	}
}

// healthScore fetches the guard health score for tooltip display.
func healthScore(client *http.Client) string {
	resp, err := client.Get(guardURL + "/health-score")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var result struct {
		Score int `json:"score"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}
	return fmt.Sprintf("Score: %d/100", result.Score)
}
