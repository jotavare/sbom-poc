package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	newMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestHealth(t *testing.T) {
	rec := get(t, "/health")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Fatalf("unexpected response: %d %s", rec.Code, rec.Body)
	}
}

func TestHashMD5(t *testing.T) {
	rec := get(t, "/hash?value=abc")
	if !strings.Contains(rec.Body.String(), "900150983cd24fb0d6963f7d28e17f72") {
		t.Fatalf("unexpected md5: %s", rec.Body)
	}
}

func TestToken(t *testing.T) {
	rec := get(t, "/token?user=alice")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "token") {
		t.Fatalf("unexpected response: %d %s", rec.Code, rec.Body)
	}
}
