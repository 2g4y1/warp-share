package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type SpeedLimiter struct {
	globalLimitKB int64
	altLimitKB    int64
	altStartHour  int64
	altEndHour    int64

	mu       sync.RWMutex
	ipCounts map[string]int
	activeIP int
}

func NewSpeedLimiter() *SpeedLimiter {
	return &SpeedLimiter{
		globalLimitKB: 200,
		altLimitKB:    0,
		altStartHour:  2,
		altEndHour:    5,
		ipCounts:      make(map[string]int),
	}
}

func (s *SpeedLimiter) Start(dataDir string, stopChan <-chan struct{}) {
	go s.watch(dataDir, stopChan)
}

func (s *SpeedLimiter) watch(dataDir string, stopChan <-chan struct{}) {
	configPath := filepath.Join(dataDir, "speed_limit.txt")
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Initial read
	s.readConfig(configPath)

	for {
		select {
		case <-stopChan:
			log.Println("Speed config watcher shutting down")
			return
		case <-ticker.C:
			s.readConfig(configPath)
		}
	}
}

func (s *SpeedLimiter) readConfig(configPath string) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return // File might not exist yet, that's OK
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) >= 4 {
		v1, err1 := strconv.ParseInt(strings.TrimSpace(lines[0]), 10, 64)
		v2, err2 := strconv.ParseInt(strings.TrimSpace(lines[1]), 10, 64)
		v3, err3 := strconv.ParseInt(strings.TrimSpace(lines[2]), 10, 64)
		v4, err4 := strconv.ParseInt(strings.TrimSpace(lines[3]), 10, 64)
		if err1 == nil && err2 == nil && err3 == nil && err4 == nil {
			atomic.StoreInt64(&s.globalLimitKB, v1)
			atomic.StoreInt64(&s.altLimitKB, v2)
			atomic.StoreInt64(&s.altStartHour, v3)
			atomic.StoreInt64(&s.altEndHour, v4)
		}
	} else if len(lines) == 1 {
		if val, err := strconv.ParseInt(strings.TrimSpace(lines[0]), 10, 64); err == nil {
			atomic.StoreInt64(&s.globalLimitKB, val)
		}
	}
}

func (s *SpeedLimiter) SetLimits(def, alt, start, end int64) {
	atomic.StoreInt64(&s.globalLimitKB, def)
	atomic.StoreInt64(&s.altLimitKB, alt)
	atomic.StoreInt64(&s.altStartHour, start)
	atomic.StoreInt64(&s.altEndHour, end)
}

func (s *SpeedLimiter) GetConfig() (def, alt, start, end int64) {
	return atomic.LoadInt64(&s.globalLimitKB),
		atomic.LoadInt64(&s.altLimitKB),
		atomic.LoadInt64(&s.altStartHour),
		atomic.LoadInt64(&s.altEndHour)
}

func (s *SpeedLimiter) WriteConfig(path string, def, alt, start, end int64) error {
	tmpPath := path + ".tmp"
	data := fmt.Sprintf("%d\n%d\n%d\n%d", def, alt, start, end)
	if err := os.WriteFile(tmpPath, []byte(data), 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func (s *SpeedLimiter) WrapFileWithIP(f *os.File, ip string) *throttledFile {
	release := s.acquire(ip)
	return &throttledFile{
		File:    f,
		limiter: s,
		ip:      ip,
		release: release,
	}
}

func (s *SpeedLimiter) Info(now time.Time) (schedule string, current string) {
	defLimit := atomic.LoadInt64(&s.globalLimitKB)
	altLimit := atomic.LoadInt64(&s.altLimitKB)
	startH := atomic.LoadInt64(&s.altStartHour)
	endH := atomic.LoadInt64(&s.altEndHour)

	// If both limits are unlimited, return empty strings (hide speed info)
	if defLimit <= 0 && altLimit <= 0 {
		return "", ""
	}

	defStr := fmt.Sprintf("%d KB/s", defLimit)
	if defLimit <= 0 {
		defStr = "unlimited"
	}
	altStr := fmt.Sprintf("%d KB/s", altLimit)
	if altLimit <= 0 {
		altStr = "unlimited"
	}

	schedule = fmt.Sprintf("%02d:00–%02d:00: %s · otherwise: %s", startH, endH, altStr, defStr)

	h := int64(now.Local().Hour())
	if startH < endH {
		if h >= startH && h < endH {
			current = altStr
		} else {
			current = defStr
		}
	} else if startH > endH {
		if h >= startH || h < endH {
			current = altStr
		} else {
			current = defStr
		}
	} else {
		current = defStr
	}
	return schedule, current
}

type throttledFile struct {
	*os.File
	limiter     *SpeedLimiter
	ip          string
	release     func()
	lastCheck   time.Time
	allowance   float64
	lastRateBps float64
}

func (t *throttledFile) Close() error {
	if t.release != nil {
		t.release()
		t.release = nil
	}
	return t.File.Close()
}

func (t *throttledFile) Read(p []byte) (n int, err error) {
	now := time.Now()
	limitKB := t.limiter.currentLimitKB(now)
	if limitKB <= 0 {
		return t.File.Read(p)
	}

	activeIP, downloadsForIP := t.limiter.currentShare(t.ip)
	if activeIP <= 0 {
		activeIP = 1
	}
	if downloadsForIP <= 0 {
		downloadsForIP = 1
	}

	rateBps := (float64(limitKB) * 1024) / float64(activeIP) / float64(downloadsForIP)
	if rateBps < 1 {
		rateBps = 1
	}

	if t.lastCheck.IsZero() || rateBps != t.lastRateBps {
		t.lastCheck = now
		t.allowance = 0 // Start with no allowance to prevent initial burst
		t.lastRateBps = rateBps
	}

	elapsed := now.Sub(t.lastCheck).Seconds()
	if elapsed > 0 {
		t.allowance += elapsed * rateBps
		if t.allowance > rateBps {
			t.allowance = rateBps
		}
		t.lastCheck = now
	}

	n, err = t.File.Read(p)
	if n > 0 {
		if t.allowance < float64(n) {
			sleepSec := (float64(n) - t.allowance) / rateBps
			time.Sleep(time.Duration(sleepSec * float64(time.Second)))
			t.allowance = 0
		} else {
			t.allowance -= float64(n)
		}
	}
	return
}

func (s *SpeedLimiter) currentLimitKB(now time.Time) int64 {
	startH := atomic.LoadInt64(&s.altStartHour)
	endH := atomic.LoadInt64(&s.altEndHour)
	h := int64(now.Local().Hour())

	isAltTime := false
	if startH < endH {
		isAltTime = h >= startH && h < endH
	} else if startH > endH {
		isAltTime = h >= startH || h < endH
	}

	if isAltTime {
		return atomic.LoadInt64(&s.altLimitKB)
	}
	return atomic.LoadInt64(&s.globalLimitKB)
}

func (s *SpeedLimiter) acquire(ip string) func() {
	s.mu.Lock()
	if s.ipCounts[ip] == 0 {
		s.activeIP++
	}
	s.ipCounts[ip]++
	s.mu.Unlock()

	return func() {
		s.mu.Lock()
		if s.ipCounts[ip] > 0 {
			s.ipCounts[ip]--
			if s.ipCounts[ip] == 0 {
				delete(s.ipCounts, ip)
				s.activeIP--
			}
		}
		s.mu.Unlock()
	}
}

func (s *SpeedLimiter) currentShare(ip string) (activeIP int, downloadsForIP int) {
	s.mu.RLock()
	activeIP = s.activeIP
	downloadsForIP = s.ipCounts[ip]
	s.mu.RUnlock()
	return
}
