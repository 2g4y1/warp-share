package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// SpeedLimiter Tests
// ============================================================================

func TestNewSpeedLimiter(t *testing.T) {
	sl := NewSpeedLimiter()

	if sl == nil {
		t.Fatal("NewSpeedLimiter() returned nil")
	}

	def, alt, start, end := sl.GetConfig()
	if def != 200 {
		t.Errorf("default limit = %d, want 200", def)
	}
	if alt != 0 {
		t.Errorf("alt limit = %d, want 0", alt)
	}
	if start != 2 {
		t.Errorf("start hour = %d, want 2", start)
	}
	if end != 5 {
		t.Errorf("end hour = %d, want 5", end)
	}
}

func TestSpeedLimiterSetLimits(t *testing.T) {
	sl := NewSpeedLimiter()

	sl.SetLimits(500, 100, 22, 6)

	def, alt, start, end := sl.GetConfig()
	if def != 500 {
		t.Errorf("default limit = %d, want 500", def)
	}
	if alt != 100 {
		t.Errorf("alt limit = %d, want 100", alt)
	}
	if start != 22 {
		t.Errorf("start hour = %d, want 22", start)
	}
	if end != 6 {
		t.Errorf("end hour = %d, want 6", end)
	}
}

func TestSpeedLimiterInfo(t *testing.T) {
	sl := NewSpeedLimiter()

	t.Run("returns empty when no limits", func(t *testing.T) {
		sl.SetLimits(0, 0, 2, 5) // Both unlimited
		schedule, current := sl.Info(time.Now())
		if schedule != "" || current != "" {
			t.Errorf("Info() = (%q, %q), want empty strings", schedule, current)
		}
	})

	t.Run("returns schedule when limits exist", func(t *testing.T) {
		sl.SetLimits(200, 0, 2, 5)
		schedule, current := sl.Info(time.Now())
		if schedule == "" {
			t.Error("schedule should not be empty when default limit is set")
		}
		if current == "" {
			t.Error("current should not be empty")
		}
	})

	t.Run("uses alt limit during alt hours", func(t *testing.T) {
		sl.SetLimits(200, 500, 0, 24) // Alt hours all day
		_, current := sl.Info(time.Now())
		if current != "500 KB/s" {
			t.Errorf("current = %q, want '500 KB/s'", current)
		}
	})
}

func TestSpeedLimiterInfoSameStartEnd(t *testing.T) {
	sl := NewSpeedLimiter()
	sl.SetLimits(200, 100, 5, 5)

	_, current := sl.Info(time.Now())
	if current != "200 KB/s" {
		t.Errorf("current = %q, want 200 KB/s", current)
	}
}

func TestSpeedLimiterCurrentLimitKB(t *testing.T) {
	sl := NewSpeedLimiter()

	t.Run("returns default outside alt hours", func(t *testing.T) {
		sl.SetLimits(200, 500, 2, 5)
		// Use a time outside 2-5 AM
		testTime := time.Date(2025, 1, 1, 12, 0, 0, 0, time.Local)
		limit := sl.currentLimitKB(testTime)
		if limit != 200 {
			t.Errorf("currentLimitKB = %d, want 200", limit)
		}
	})

	t.Run("returns alt during alt hours", func(t *testing.T) {
		sl.SetLimits(200, 500, 2, 5)
		// Use a time within 2-5 AM
		testTime := time.Date(2025, 1, 1, 3, 0, 0, 0, time.Local)
		limit := sl.currentLimitKB(testTime)
		if limit != 500 {
			t.Errorf("currentLimitKB = %d, want 500", limit)
		}
	})

	t.Run("handles overnight range", func(t *testing.T) {
		sl.SetLimits(200, 500, 22, 6) // 10PM to 6AM

		// 11PM should be alt
		testTime := time.Date(2025, 1, 1, 23, 0, 0, 0, time.Local)
		limit := sl.currentLimitKB(testTime)
		if limit != 500 {
			t.Errorf("currentLimitKB at 11PM = %d, want 500", limit)
		}

		// 3AM should be alt
		testTime = time.Date(2025, 1, 1, 3, 0, 0, 0, time.Local)
		limit = sl.currentLimitKB(testTime)
		if limit != 500 {
			t.Errorf("currentLimitKB at 3AM = %d, want 500", limit)
		}

		// 12PM should be default
		testTime = time.Date(2025, 1, 1, 12, 0, 0, 0, time.Local)
		limit = sl.currentLimitKB(testTime)
		if limit != 200 {
			t.Errorf("currentLimitKB at 12PM = %d, want 200", limit)
		}
	})
}

func TestSpeedLimiterAcquire(t *testing.T) {
	sl := NewSpeedLimiter()

	t.Run("tracks active IPs", func(t *testing.T) {
		release1 := sl.acquire("192.168.1.1")
		release2 := sl.acquire("192.168.1.2")

		active, _ := sl.currentShare("192.168.1.1")
		if active != 2 {
			t.Errorf("activeIP = %d, want 2", active)
		}

		release1()
		release2()

		active, _ = sl.currentShare("192.168.1.1")
		if active != 0 {
			t.Errorf("activeIP after release = %d, want 0", active)
		}
	})

	t.Run("tracks downloads per IP", func(t *testing.T) {
		release1 := sl.acquire("192.168.1.1")
		release2 := sl.acquire("192.168.1.1")
		release3 := sl.acquire("192.168.1.1")

		_, downloads := sl.currentShare("192.168.1.1")
		if downloads != 3 {
			t.Errorf("downloads = %d, want 3", downloads)
		}

		release1()
		release2()

		_, downloads = sl.currentShare("192.168.1.1")
		if downloads != 1 {
			t.Errorf("downloads after 2 releases = %d, want 1", downloads)
		}

		release3()
	})

	t.Run("concurrent access", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				release := sl.acquire(ip)
				time.Sleep(time.Millisecond)
				release()
			}("192.168.1.1")
		}
		wg.Wait()

		active, downloads := sl.currentShare("192.168.1.1")
		if active != 0 || downloads != 0 {
			t.Errorf("after concurrent test: active=%d, downloads=%d, want 0,0", active, downloads)
		}
	})
}

func TestSpeedLimiterWriteConfig(t *testing.T) {
	sl := NewSpeedLimiter()

	tmpDir, err := os.MkdirTemp("", "speed-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	configPath := filepath.Join(tmpDir, "speed_limit.txt")

	t.Run("writes config file", func(t *testing.T) {
		err := sl.WriteConfig(configPath, 300, 100, 1, 7)
		if err != nil {
			t.Fatalf("WriteConfig() error = %v", err)
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("failed to read config: %v", err)
		}

		// Format is: def\nalt\nstart\nend (no newline at end)
		expected := "300\n100\n1\n7"
		if string(data) != expected {
			t.Errorf("config content = %q, want %q", string(data), expected)
		}
	})
}

func TestSpeedLimiterReadConfig(t *testing.T) {
	sl := NewSpeedLimiter()

	tmpDir, err := os.MkdirTemp("", "speed-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	configPath := filepath.Join(tmpDir, "speed_limit.txt")

	t.Run("reads config file", func(t *testing.T) {
		// Format is: def\nalt\nstart\nend
		content := "400\n150\n3\n8"
		if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		sl.readConfig(configPath)

		def, alt, start, end := sl.GetConfig()
		if def != 400 {
			t.Errorf("default = %d, want 400", def)
		}
		if alt != 150 {
			t.Errorf("alt = %d, want 150", alt)
		}
		if start != 3 {
			t.Errorf("start = %d, want 3", start)
		}
		if end != 8 {
			t.Errorf("end = %d, want 8", end)
		}
	})
}

func TestSpeedLimiterWatchAndStart(t *testing.T) {
	sl := NewSpeedLimiter()
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "speed_limit.txt")
	if err := os.WriteFile(configPath, []byte("123\n0\n2\n5"), 0644); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	close(stop)
	// Call watch directly to cover initial read
	sl.watch(tmpDir, stop)

	def, _, _, _ := sl.GetConfig()
	if def != 123 {
		t.Errorf("default limit = %d, want 123", def)
	}

	// Start should be callable without blocking
	sl.Start(tmpDir, stop)
}

func TestThrottledFileReadAndClose(t *testing.T) {
	sl := NewSpeedLimiter()
	sl.SetLimits(1, 0, 0, 0)

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "data.txt")
	if err := os.WriteFile(filePath, []byte("abc"), 0644); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}

	th := sl.WrapFileWithIP(f, "127.0.0.1")
	buf := make([]byte, 1)
	if _, err := th.Read(buf); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if err := th.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	active, downloads := sl.currentShare("127.0.0.1")
	if active != 0 || downloads != 0 {
		t.Errorf("after Close: active=%d downloads=%d, want 0,0", active, downloads)
	}
}

func TestThrottledFileReadUnlimited(t *testing.T) {
	sl := NewSpeedLimiter()
	sl.SetLimits(0, 0, 0, 0)

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "data.txt")
	if err := os.WriteFile(filePath, []byte("abc"), 0644); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	th := sl.WrapFileWithIP(f, "127.0.0.1")
	buf := make([]byte, 3)
	if _, err := th.Read(buf); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	_ = th.Close()
}
