package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type flushWriter struct {
	http.ResponseWriter
	flushed bool
}

func (f *flushWriter) Flush() {
	f.flushed = true
}

func TestLoggingResponseWriter(t *testing.T) {
	rr := httptest.NewRecorder()
	fw := &flushWriter{ResponseWriter: rr}

	lrw := &loggingResponseWriter{ResponseWriter: fw, statusCode: http.StatusOK}
	lrw.WriteHeader(http.StatusCreated)
	_, _ = lrw.Write([]byte("ok"))
	lrw.Flush()

	if lrw.statusCode != http.StatusCreated {
		t.Errorf("statusCode = %d, want %d", lrw.statusCode, http.StatusCreated)
	}
	if lrw.written != 2 {
		t.Errorf("written = %d, want 2", lrw.written)
	}
	if !fw.flushed {
		t.Error("Flush should call underlying flusher")
	}
	if lrw.Unwrap() != fw {
		t.Error("Unwrap should return underlying ResponseWriter")
	}
}

func TestRequestLog(t *testing.T) {
	var buf bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(oldOutput)

	a := newTestApp(t)
	h := a.requestLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !strings.Contains(buf.String(), "REQUEST:") {
		t.Errorf("expected log output, got %q", buf.String())
	}

	// assets should not log
	buf.Reset()
	req2 := httptest.NewRequest(http.MethodGet, "/file.js", nil)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if buf.Len() != 0 {
		t.Errorf("expected no log for assets, got %q", buf.String())
	}
}
