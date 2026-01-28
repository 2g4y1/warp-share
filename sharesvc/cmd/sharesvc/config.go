package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type config struct {
	ListenAddr string
	PublicBase string
	AdminPath  string

	DataDir         string
	DBPath          string
	MediaRoot       string
	BrowseStartRel  string
	UploadTempDir   string
	UploadTargetDir string
	TempCleanupInterval time.Duration
	TempCleanupAge      time.Duration

	BootstrapAdminUser string
	BootstrapAdminPass string

	PasskeysEnabled              bool
	PasskeysRPID                 string
	PasskeysRPOrigins            []string
	PasskeysRPDisplayName        string
	PasskeysTimeout              time.Duration
	PasskeysUserVerification     string
	PasskeysResidentKey          string
	PasskeysAuthenticatorAttach  string
	PasskeysAttestation          string

	SessionTTL time.Duration
	GrantTTL   time.Duration

	ServerReadHeaderTimeout time.Duration
	ServerReadTimeout       time.Duration
	ServerWriteTimeout      time.Duration
	ServerIdleTimeout       time.Duration
	ServerShutdownTimeout   time.Duration
	DBTimeout               time.Duration
}

func loadConfig() (config, error) {
	cfg := config{
		ListenAddr:     ":8080",
		PublicBase:     "",
		AdminPath:      "",
		DataDir:        "/data",
		MediaRoot:      "/mnt/media",
		BrowseStartRel: "media",
		TempCleanupInterval: 6 * time.Hour,
		TempCleanupAge:      24 * time.Hour,
		SessionTTL:     24 * time.Hour,
		GrantTTL:       7 * 24 * time.Hour,

		PasskeysEnabled:          false,
		PasskeysRPDisplayName:    "Warp Share",
		PasskeysTimeout:          2 * time.Minute,
		PasskeysUserVerification: "preferred",
		PasskeysResidentKey:      "required",
		PasskeysAttestation:      "none",

		ServerReadHeaderTimeout: 5 * time.Second,
		ServerReadTimeout:       30 * time.Second,
		ServerWriteTimeout:      0,
		ServerIdleTimeout:       60 * time.Second,
		ServerShutdownTimeout:   30 * time.Second,
		DBTimeout:               3 * time.Second,
	}

	if v := strings.TrimSpace(os.Getenv("LISTEN_ADDR")); v != "" {
		cfg.ListenAddr = v
	}
	if v := strings.TrimSpace(os.Getenv("PUBLIC_BASE")); v != "" {
		cfg.PublicBase = strings.TrimRight(v, "/")
	}
	if v := strings.TrimSpace(os.Getenv("ADMIN_PATH")); v != "" {
		if !strings.HasPrefix(v, "/") {
			v = "/" + v
		}
		cfg.AdminPath = strings.TrimRight(v, "/")
	}

	// PUBLIC_BASE must be set
	if cfg.PublicBase == "" {
		return config{}, fmt.Errorf("PUBLIC_BASE environment variable is required")
	}

	// DATA_DIR must be set before loading ADMIN_PATH
	if v := strings.TrimSpace(os.Getenv("DATA_DIR")); v != "" {
		cfg.DataDir = v
	}

	// ADMIN_PATH: Load from file or generate and save
	if cfg.AdminPath == "" {
		adminPathFile := filepath.Join(cfg.DataDir, "admin_path")
		// Try to load from file
		if data, err := os.ReadFile(adminPathFile); err == nil {
			loaded := strings.TrimSpace(string(data))
			if loaded != "" {
				cfg.AdminPath = loaded
				log.Printf("ADMIN_PATH loaded from %s: %s", adminPathFile, cfg.AdminPath)
			}
		}
		// If still empty, generate and save
		if cfg.AdminPath == "" {
			generated, err := generateSecurePath()
			if err != nil {
				return config{}, fmt.Errorf("failed to generate ADMIN_PATH: %w", err)
			}
			cfg.AdminPath = "/" + generated
			// Save to file for persistence
			if err := os.MkdirAll(cfg.DataDir, 0750); err == nil {
				if err := os.WriteFile(adminPathFile, []byte(cfg.AdminPath), 0600); err != nil {
					log.Printf("WARNING: Could not save ADMIN_PATH: %v", err)
				}
			}
			log.Printf("════════════════════════════════════════════════════════════════")
			log.Printf("  ADMIN_PATH has been auto-generated and saved!")
			log.Printf("  Your admin path: %s", cfg.AdminPath)
			log.Printf("  Full admin URL: %s%s/", cfg.PublicBase, cfg.AdminPath)
			log.Printf("  Saved to: %s", adminPathFile)
			log.Printf("════════════════════════════════════════════════════════════════")
		}
	}

	// MEDIA_ROOT, BROWSE_START_REL and upload directories
	if v := strings.TrimSpace(os.Getenv("MEDIA_ROOT")); v != "" {
		cfg.MediaRoot = v
	}
	if v := strings.TrimSpace(os.Getenv("BROWSE_START_REL")); v != "" {
		cfg.BrowseStartRel = strings.TrimPrefix(v, "/")
	}
	if v := strings.TrimSpace(os.Getenv("UPLOAD_TEMP_DIR")); v != "" {
		cfg.UploadTempDir = v
	}
	if v := strings.TrimSpace(os.Getenv("TEMP_CLEANUP_INTERVAL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return config{}, fmt.Errorf("invalid TEMP_CLEANUP_INTERVAL: %w", err)
		}
		cfg.TempCleanupInterval = d
	}
	if v := strings.TrimSpace(os.Getenv("TEMP_CLEANUP_AGE")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return config{}, fmt.Errorf("invalid TEMP_CLEANUP_AGE: %w", err)
		}
		cfg.TempCleanupAge = d
	}
	if v := strings.TrimSpace(os.Getenv("UPLOAD_TARGET_DIR")); v != "" {
		cfg.UploadTargetDir = v
	}

	// Upload defaults: If UPLOAD_TARGET_DIR not set, use default directory in Data-Dir
	// This way upload works out-of-the-box without configuration
	if cfg.UploadTargetDir == "" {
		cfg.UploadTargetDir = filepath.Join(cfg.DataDir, "uploads")
	}
	// UPLOAD_TEMP_DIR optional - if not set, writes directly to target

	if v := strings.TrimSpace(os.Getenv("SESSION_TTL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return config{}, fmt.Errorf("invalid SESSION_TTL: %w", err)
		}
		cfg.SessionTTL = d
	}
	if v := strings.TrimSpace(os.Getenv("GRANT_TTL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return config{}, fmt.Errorf("invalid GRANT_TTL: %w", err)
		}
		cfg.GrantTTL = d
	}

	if v := strings.TrimSpace(os.Getenv("PASSKEYS_ENABLED")); v != "" {
		cfg.PasskeysEnabled = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	}
	if v := strings.TrimSpace(os.Getenv("PASSKEYS_RP_ID")); v != "" {
		cfg.PasskeysRPID = v
	}
	if v := strings.TrimSpace(os.Getenv("PASSKEYS_RP_ORIGINS")); v != "" {
		parts := strings.Split(v, ",")
		var out []string
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				out = append(out, s)
			}
		}
		cfg.PasskeysRPOrigins = out
	}
	if v := strings.TrimSpace(os.Getenv("PASSKEYS_RP_DISPLAY_NAME")); v != "" {
		cfg.PasskeysRPDisplayName = v
	}
	if v := strings.TrimSpace(os.Getenv("PASSKEYS_TIMEOUT")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return config{}, fmt.Errorf("invalid PASSKEYS_TIMEOUT: %w", err)
		}
		cfg.PasskeysTimeout = d
	}
	if v := strings.TrimSpace(os.Getenv("PASSKEYS_USER_VERIFICATION")); v != "" {
		cfg.PasskeysUserVerification = strings.ToLower(v)
	}
	if v := strings.TrimSpace(os.Getenv("PASSKEYS_RESIDENT_KEY")); v != "" {
		cfg.PasskeysResidentKey = strings.ToLower(v)
	}
	if v := strings.TrimSpace(os.Getenv("PASSKEYS_AUTHENTICATOR_ATTACHMENT")); v != "" {
		cfg.PasskeysAuthenticatorAttach = strings.ToLower(v)
	}
	if v := strings.TrimSpace(os.Getenv("PASSKEYS_ATTESTATION")); v != "" {
		cfg.PasskeysAttestation = strings.ToLower(v)
	}

	if v := strings.TrimSpace(os.Getenv("SERVER_READ_HEADER_TIMEOUT")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return config{}, fmt.Errorf("invalid SERVER_READ_HEADER_TIMEOUT: %w", err)
		}
		cfg.ServerReadHeaderTimeout = d
	}
	if v := strings.TrimSpace(os.Getenv("SERVER_READ_TIMEOUT")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return config{}, fmt.Errorf("invalid SERVER_READ_TIMEOUT: %w", err)
		}
		cfg.ServerReadTimeout = d
	}
	if v := strings.TrimSpace(os.Getenv("SERVER_WRITE_TIMEOUT")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return config{}, fmt.Errorf("invalid SERVER_WRITE_TIMEOUT: %w", err)
		}
		cfg.ServerWriteTimeout = d
	}
	if v := strings.TrimSpace(os.Getenv("SERVER_IDLE_TIMEOUT")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return config{}, fmt.Errorf("invalid SERVER_IDLE_TIMEOUT: %w", err)
		}
		cfg.ServerIdleTimeout = d
	}
	if v := strings.TrimSpace(os.Getenv("SERVER_SHUTDOWN_TIMEOUT")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return config{}, fmt.Errorf("invalid SERVER_SHUTDOWN_TIMEOUT: %w", err)
		}
		cfg.ServerShutdownTimeout = d
	}
	if v := strings.TrimSpace(os.Getenv("DB_TIMEOUT")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return config{}, fmt.Errorf("invalid DB_TIMEOUT: %w", err)
		}
		cfg.DBTimeout = d
	}

	if cfg.PasskeysEnabled {
		if cfg.PasskeysRPID == "" || len(cfg.PasskeysRPOrigins) == 0 {
			u, err := url.Parse(cfg.PublicBase)
			if err != nil {
				return config{}, fmt.Errorf("invalid PUBLIC_BASE for passkeys: %w", err)
			}
			if cfg.PasskeysRPID == "" {
				cfg.PasskeysRPID = u.Hostname()
			}
			if len(cfg.PasskeysRPOrigins) == 0 {
				cfg.PasskeysRPOrigins = []string{strings.TrimRight(cfg.PublicBase, "/")}
			}
		}
	}

	cfg.DBPath = filepath.Join(cfg.DataDir, "warp-share.sqlite")

	cfg.BootstrapAdminUser = strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_USER"))
	cfg.BootstrapAdminPass = os.Getenv("BOOTSTRAP_ADMIN_PASSWORD")
	if cfg.BootstrapAdminUser == "" {
		cfg.BootstrapAdminUser = "admin"
	}

	return cfg, nil
}

// generateSecurePath creates a cryptographically secure URL path
func generateSecurePath() (string, error) {
	b := make([]byte, 16) // 128 bit entropy
	if _, err := randRead(b); err != nil {
		return "", err
	}
	// URL-safe base64, ohne Padding
	return base64.RawURLEncoding.EncodeToString(b), nil
}
