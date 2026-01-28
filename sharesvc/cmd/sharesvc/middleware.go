package main

import (
	"log"
	"net/http"
	"strings"
	"time"
)

// loggingResponseWriter wraps ResponseWriter for logging with status code tracking
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    int64
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	n, err := lrw.ResponseWriter.Write(b)
	lrw.written += int64(n)
	return n, err
}

// Flush implements http.Flusher for streaming compatibility
func (lrw *loggingResponseWriter) Flush() {
	flushResponseWriter(lrw.ResponseWriter)
}

// Unwrap provides access to the underlying ResponseWriter
func (lrw *loggingResponseWriter) Unwrap() http.ResponseWriter {
	return lrw.ResponseWriter
}

func (a *app) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lrw, r)

		// Only log relevant requests (skip assets)
		path := r.URL.Path
		if !strings.HasSuffix(path, ".js") && !strings.HasSuffix(path, ".css") && path != "/healthz" {
			logPath := redactPathForLogs(path, a.cfg.AdminPath)
			log.Printf("REQUEST: %s %s -> %d (%s) ip=%s",
				r.Method,
				logPath,
				lrw.statusCode,
				time.Since(start).Round(time.Millisecond),
				getClientIP(r),
			)
		}
	})
}
