package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

func safeJoinAndCheck(root, rel string) (string, error) {
	if strings.Contains(rel, "\\") {
		return "", fmt.Errorf("invalid path")
	}

	rel = strings.TrimPrefix(rel, "/")
	if rel == "." {
		rel = ""
	}
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path traversal")
	}
	if clean == "." {
		clean = ""
	}

	abs := filepath.Join(root, clean)
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	rootResolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}

	prefix := rootResolved + string(filepath.Separator)
	if resolved != rootResolved && !strings.HasPrefix(resolved, prefix) {
		return "", fmt.Errorf("outside root")
	}

	return resolved, nil
}

// getClientIP extracts the client IP from the request.
// Trusts X-Real-IP only when the direct peer is a trusted proxy.
// X-Forwarded-For is NOT used because it can be manipulated by the client.
func getClientIP(r *http.Request) string {
	remoteHost := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		remoteHost = host
	}
	remoteIP := net.ParseIP(remoteHost)

	if remoteIP != nil && isTrustedProxyIP(remoteIP) {
		if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
			if ip := net.ParseIP(v); ip != nil {
				return v
			}
		}
	}

	if remoteHost != "" {
		return remoteHost
	}
	return r.RemoteAddr
}

func isTrustedProxyIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate()
}

// redactPathForLogs removes sensitive identifiers from logged URLs.
func redactPathForLogs(path string, adminPath string) string {
	if adminPath != "" && (path == adminPath || strings.HasPrefix(path, adminPath+"/")) {
		suffix := strings.TrimPrefix(path, adminPath)
		if suffix == "" {
			return "/[admin]"
		}
		return "/[admin]" + suffix
	}

	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return path
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) == 2 && looksLikeToken(parts[0], 12) && looksLikeToken(parts[1], 20) {
		return "/[share]/[token]"
	}

	return path
}

func looksLikeToken(s string, minLen int) bool {
	if len(s) < minLen || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

func randomToken(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := randRead(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// nowRFC3339 returns current UTC time as RFC3339 string (used everywhere in DB)
func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// jsonError writes a JSON error response
func jsonError(w http.ResponseWriter, status int, errType, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q,"message":%q}`, errType, message)
}

// formatRemaining formats remaining downloads as string (∞ for unlimited)
func formatRemaining(maxDownloads, usedDownloads int64) string {
	if maxDownloads > 0 {
		remaining := maxDownloads - usedDownloads
		if remaining < 0 {
			remaining = 0
		}
		return fmt.Sprintf("%d", remaining)
	}
	return "∞"
}

// flushResponseWriter calls Flush on the underlying writer if supported
func flushResponseWriter(w http.ResponseWriter) {
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}
