package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ============================================================================
// generateSecurePath Tests
// ============================================================================

func TestGenerateSecurePath(t *testing.T) {
	t.Run("generates valid path", func(t *testing.T) {
		path, err := generateSecurePath()
		if err != nil {
			t.Fatalf("generateSecurePath() error = %v", err)
		}

		// Should be 16 bytes -> 22 base64 chars (without padding)
		if len(path) != 22 {
			t.Errorf("path length = %d, want 22", len(path))
		}

		// Should be URL-safe
		if !looksLikeToken(path, 20) {
			t.Errorf("path %q contains invalid characters", path)
		}
	})

	t.Run("generates unique paths", func(t *testing.T) {
		paths := make(map[string]bool)
		for i := 0; i < 100; i++ {
			path, err := generateSecurePath()
			if err != nil {
				t.Fatalf("generateSecurePath() error = %v", err)
			}
			if paths[path] {
				t.Errorf("generateSecurePath() generated duplicate: %s", path)
			}
			paths[path] = true
		}
	})
}

func TestGenerateSecurePathError(t *testing.T) {
	old := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("boom") }
	defer func() { randRead = old }()

	if _, err := generateSecurePath(); err == nil {
		t.Error("expected error from generateSecurePath when randRead fails")
	}
}

// ============================================================================
// loadConfig Tests
// ============================================================================

func TestLoadConfig(t *testing.T) {
	// Save original env vars
	origPublicBase := os.Getenv("PUBLIC_BASE")
	origDataDir := os.Getenv("DATA_DIR")
	origAdminPath := os.Getenv("ADMIN_PATH")
	origMediaRoot := os.Getenv("MEDIA_ROOT")
	origBrowseStart := os.Getenv("BROWSE_START_REL")
	origUploadTemp := os.Getenv("UPLOAD_TEMP_DIR")
	origUploadTarget := os.Getenv("UPLOAD_TARGET_DIR")
	origTempCleanupInterval := os.Getenv("TEMP_CLEANUP_INTERVAL")
	origTempCleanupAge := os.Getenv("TEMP_CLEANUP_AGE")
	origSessionTTL := os.Getenv("SESSION_TTL")
	origGrantTTL := os.Getenv("GRANT_TTL")
	origReadHeaderTimeout := os.Getenv("SERVER_READ_HEADER_TIMEOUT")
	origReadTimeout := os.Getenv("SERVER_READ_TIMEOUT")
	origWriteTimeout := os.Getenv("SERVER_WRITE_TIMEOUT")
	origIdleTimeout := os.Getenv("SERVER_IDLE_TIMEOUT")
	origShutdownTimeout := os.Getenv("SERVER_SHUTDOWN_TIMEOUT")
	origDBTimeout := os.Getenv("DB_TIMEOUT")
	origBootstrapUser := os.Getenv("BOOTSTRAP_ADMIN_USER")
	origBootstrapPass := os.Getenv("BOOTSTRAP_ADMIN_PASSWORD")
	origPasskeysEnabled := os.Getenv("PASSKEYS_ENABLED")
	origPasskeysRPID := os.Getenv("PASSKEYS_RP_ID")
	origPasskeysRPOrigins := os.Getenv("PASSKEYS_RP_ORIGINS")
	origPasskeysRPDisplay := os.Getenv("PASSKEYS_RP_DISPLAY_NAME")
	origPasskeysTimeout := os.Getenv("PASSKEYS_TIMEOUT")
	origPasskeysUV := os.Getenv("PASSKEYS_USER_VERIFICATION")
	origPasskeysResident := os.Getenv("PASSKEYS_RESIDENT_KEY")
	origPasskeysAttach := os.Getenv("PASSKEYS_AUTHENTICATOR_ATTACHMENT")
	origPasskeysAttestation := os.Getenv("PASSKEYS_ATTESTATION")

	// Cleanup
	defer func() {
		_ = os.Setenv("PUBLIC_BASE", origPublicBase)
		_ = os.Setenv("DATA_DIR", origDataDir)
		_ = os.Setenv("ADMIN_PATH", origAdminPath)
		_ = os.Setenv("MEDIA_ROOT", origMediaRoot)
		_ = os.Setenv("BROWSE_START_REL", origBrowseStart)
		_ = os.Setenv("UPLOAD_TEMP_DIR", origUploadTemp)
		_ = os.Setenv("UPLOAD_TARGET_DIR", origUploadTarget)
		_ = os.Setenv("TEMP_CLEANUP_INTERVAL", origTempCleanupInterval)
		_ = os.Setenv("TEMP_CLEANUP_AGE", origTempCleanupAge)
		_ = os.Setenv("SESSION_TTL", origSessionTTL)
		_ = os.Setenv("GRANT_TTL", origGrantTTL)
		_ = os.Setenv("SERVER_READ_HEADER_TIMEOUT", origReadHeaderTimeout)
		_ = os.Setenv("SERVER_READ_TIMEOUT", origReadTimeout)
		_ = os.Setenv("SERVER_WRITE_TIMEOUT", origWriteTimeout)
		_ = os.Setenv("SERVER_IDLE_TIMEOUT", origIdleTimeout)
		_ = os.Setenv("SERVER_SHUTDOWN_TIMEOUT", origShutdownTimeout)
		_ = os.Setenv("DB_TIMEOUT", origDBTimeout)
		_ = os.Setenv("BOOTSTRAP_ADMIN_USER", origBootstrapUser)
		_ = os.Setenv("BOOTSTRAP_ADMIN_PASSWORD", origBootstrapPass)
		_ = os.Setenv("PASSKEYS_ENABLED", origPasskeysEnabled)
		_ = os.Setenv("PASSKEYS_RP_ID", origPasskeysRPID)
		_ = os.Setenv("PASSKEYS_RP_ORIGINS", origPasskeysRPOrigins)
		_ = os.Setenv("PASSKEYS_RP_DISPLAY_NAME", origPasskeysRPDisplay)
		_ = os.Setenv("PASSKEYS_TIMEOUT", origPasskeysTimeout)
		_ = os.Setenv("PASSKEYS_USER_VERIFICATION", origPasskeysUV)
		_ = os.Setenv("PASSKEYS_RESIDENT_KEY", origPasskeysResident)
		_ = os.Setenv("PASSKEYS_AUTHENTICATOR_ATTACHMENT", origPasskeysAttach)
		_ = os.Setenv("PASSKEYS_ATTESTATION", origPasskeysAttestation)
	}()

	t.Run("requires PUBLIC_BASE", func(t *testing.T) {
		_ = os.Setenv("PUBLIC_BASE", "")
		_ = os.Setenv("DATA_DIR", "/tmp/warp-test")

		_, err := loadConfig()
		if err == nil {
			t.Error("loadConfig() should fail without PUBLIC_BASE")
		}
	})

	t.Run("loads with valid env vars", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "config-test")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()

		_ = os.Setenv("PUBLIC_BASE", "https://example.com")
		_ = os.Setenv("DATA_DIR", tmpDir)
		_ = os.Setenv("ADMIN_PATH", "/secret-admin")

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}

		if cfg.PublicBase != "https://example.com" {
			t.Errorf("PublicBase = %q, want %q", cfg.PublicBase, "https://example.com")
		}
		if cfg.AdminPath != "/secret-admin" {
			t.Errorf("AdminPath = %q, want %q", cfg.AdminPath, "/secret-admin")
		}
	})

	t.Run("generates admin path when not set", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "config-test")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()

		_ = os.Setenv("PUBLIC_BASE", "https://example.com")
		_ = os.Setenv("DATA_DIR", tmpDir)
		_ = os.Setenv("ADMIN_PATH", "")

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}

		if cfg.AdminPath == "" {
			t.Error("AdminPath should be auto-generated")
		}
		if len(cfg.AdminPath) < 20 {
			t.Errorf("AdminPath = %q, should be at least 20 chars", cfg.AdminPath)
		}

		// Check file was created
		adminPathFile := filepath.Join(tmpDir, "admin_path")
		data, err := os.ReadFile(adminPathFile)
		if err != nil {
			t.Errorf("admin_path file not created: %v", err)
		}
		if string(data) != cfg.AdminPath {
			t.Errorf("admin_path file content = %q, want %q", string(data), cfg.AdminPath)
		}
	})

	t.Run("strips trailing slash from PUBLIC_BASE", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "config-test")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()

		_ = os.Setenv("PUBLIC_BASE", "https://example.com/")
		_ = os.Setenv("DATA_DIR", tmpDir)
		_ = os.Setenv("ADMIN_PATH", "/test")

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}

		if cfg.PublicBase != "https://example.com" {
			t.Errorf("PublicBase = %q, want without trailing slash", cfg.PublicBase)
		}
	})

	t.Run("reads additional env settings", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "config-test")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()

		_ = os.Setenv("PUBLIC_BASE", "https://example.com")
		_ = os.Setenv("DATA_DIR", tmpDir)
		_ = os.Setenv("ADMIN_PATH", "/admin")
		_ = os.Setenv("MEDIA_ROOT", "/media")
		_ = os.Setenv("BROWSE_START_REL", "/browse")
		_ = os.Setenv("UPLOAD_TEMP_DIR", "/tmp/uploads")
		_ = os.Setenv("UPLOAD_TARGET_DIR", "/data/uploads")
		_ = os.Setenv("TEMP_CLEANUP_INTERVAL", "2h")
		_ = os.Setenv("TEMP_CLEANUP_AGE", "48h")
		_ = os.Setenv("SESSION_TTL", "2h")
		_ = os.Setenv("GRANT_TTL", "3h")
		_ = os.Setenv("SERVER_READ_HEADER_TIMEOUT", "1s")
		_ = os.Setenv("SERVER_READ_TIMEOUT", "2s")
		_ = os.Setenv("SERVER_WRITE_TIMEOUT", "3s")
		_ = os.Setenv("SERVER_IDLE_TIMEOUT", "4s")
		_ = os.Setenv("SERVER_SHUTDOWN_TIMEOUT", "5s")
		_ = os.Setenv("DB_TIMEOUT", "6s")
		_ = os.Setenv("BOOTSTRAP_ADMIN_USER", "root")
		_ = os.Setenv("BOOTSTRAP_ADMIN_PASSWORD", "secret")
		_ = os.Setenv("PASSKEYS_ENABLED", "true")
		_ = os.Setenv("PASSKEYS_RP_ID", "example.com")
		_ = os.Setenv("PASSKEYS_RP_ORIGINS", "https://example.com,https://admin.example.com")
		_ = os.Setenv("PASSKEYS_RP_DISPLAY_NAME", "Warp Share Admin")
		_ = os.Setenv("PASSKEYS_TIMEOUT", "90s")
		_ = os.Setenv("PASSKEYS_USER_VERIFICATION", "required")
		_ = os.Setenv("PASSKEYS_RESIDENT_KEY", "preferred")
		_ = os.Setenv("PASSKEYS_AUTHENTICATOR_ATTACHMENT", "platform")
		_ = os.Setenv("PASSKEYS_ATTESTATION", "direct")

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}

		if cfg.MediaRoot != "/media" || cfg.BrowseStartRel != "browse" {
			t.Errorf("media/browse = %q/%q", cfg.MediaRoot, cfg.BrowseStartRel)
		}
		if cfg.UploadTempDir != "/tmp/uploads" || cfg.UploadTargetDir != "/data/uploads" {
			t.Errorf("upload dirs = %q/%q", cfg.UploadTempDir, cfg.UploadTargetDir)
		}
		if cfg.TempCleanupInterval.Hours() != 2 || cfg.TempCleanupAge.Hours() != 48 {
			t.Errorf("temp cleanup not loaded")
		}
		if cfg.SessionTTL.Hours() != 2 || cfg.GrantTTL.Hours() != 3 {
			t.Errorf("ttls = %v/%v", cfg.SessionTTL, cfg.GrantTTL)
		}
		if cfg.ServerReadHeaderTimeout.Seconds() != 1 || cfg.ServerReadTimeout.Seconds() != 2 || cfg.ServerWriteTimeout.Seconds() != 3 || cfg.ServerIdleTimeout.Seconds() != 4 || cfg.ServerShutdownTimeout.Seconds() != 5 || cfg.DBTimeout.Seconds() != 6 {
			t.Errorf("timeouts not loaded")
		}
		if cfg.BootstrapAdminUser != "root" || cfg.BootstrapAdminPass != "secret" {
			t.Errorf("bootstrap user/pass not loaded")
		}
		if !cfg.PasskeysEnabled || cfg.PasskeysRPID != "example.com" || len(cfg.PasskeysRPOrigins) != 2 {
			t.Errorf("passkeys config not loaded")
		}
		if cfg.PasskeysRPDisplayName != "Warp Share Admin" || cfg.PasskeysTimeout.Seconds() != 90 {
			t.Errorf("passkeys display/timeout not loaded")
		}
		if cfg.PasskeysUserVerification != "required" || cfg.PasskeysResidentKey != "preferred" || cfg.PasskeysAuthenticatorAttach != "platform" || cfg.PasskeysAttestation != "direct" {
			t.Errorf("passkeys flags not loaded")
		}
	})

	t.Run("invalid duration returns error", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "config-test")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()

		_ = os.Setenv("PUBLIC_BASE", "https://example.com")
		_ = os.Setenv("DATA_DIR", tmpDir)
		_ = os.Setenv("ADMIN_PATH", "/admin")
		_ = os.Setenv("SESSION_TTL", "bad")

		if _, err := loadConfig(); err == nil {
			t.Error("expected error for invalid duration")
		}
	})
}
