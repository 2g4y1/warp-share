package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlePasskeyLoginStartDisabled(t *testing.T) {
	a := newTestApp(t)
	req := httptest.NewRequest(http.MethodPost, "/test-admin/passkeys/login/start", strings.NewReader("{}"))
	rr := httptest.NewRecorder()

	a.handlePasskeyLoginStart(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}