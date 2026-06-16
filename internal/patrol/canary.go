package patrol

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tpt-av/tpt-av/internal/events"
)

const canaryPrefix = "~$tpt-canary-"

// CanaryManager plants hidden sentinel files in watched directories.
// Any access, rename, or deletion of a canary fires a critical alert.
type CanaryManager struct {
	log      events.Writer
	mu       sync.RWMutex
	canaries map[string]string // absolute path → directory
}

func NewCanaryManager(log events.Writer) *CanaryManager {
	return &CanaryManager{
		log:      log,
		canaries: make(map[string]string),
	}
}

// Plant creates a canary file in dir. Safe to call multiple times for the same dir.
func (c *CanaryManager) Plant(dir string) {
	name := canaryPrefix + uuid.New().String() + ".dat"
	path := filepath.Join(dir, name)

	if err := os.WriteFile(path, []byte("tpt-canary"), 0o600); err != nil {
		log.Printf("canary: failed to plant in %s: %v", dir, err)
		return
	}

	c.mu.Lock()
	c.canaries[path] = dir
	c.mu.Unlock()
}

// PlantAll plants canary files in each of the provided directories.
func (c *CanaryManager) PlantAll(dirs []string) {
	for _, dir := range dirs {
		c.Plant(dir)
	}
}

// IsCanary returns true if path is a known canary file.
func (c *CanaryManager) IsCanary(path string) bool {
	c.mu.RLock()
	_, ok := c.canaries[path]
	c.mu.RUnlock()
	if ok {
		return true
	}
	// Also detect by filename pattern in case the map wasn't populated
	return strings.HasPrefix(filepath.Base(path), canaryPrefix)
}

// Triggered fires a critical alert and re-plants the canary.
func (c *CanaryManager) Triggered(path string) {
	c.mu.Lock()
	dir := c.canaries[path]
	delete(c.canaries, path)
	c.mu.Unlock()

	c.log.Write(events.New(events.SourcePatrol, "canary_triggered", events.Critical,
		map[string]string{"path": path, "directory": dir}))

	// Re-plant a fresh canary in the same directory
	if dir != "" {
		go func() {
			time.Sleep(500 * time.Millisecond)
			c.Plant(dir)
		}()
	}
}

// CleanupAll removes all canary files (called on shutdown).
func (c *CanaryManager) CleanupAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for path := range c.canaries {
		os.Remove(path)
	}
}
