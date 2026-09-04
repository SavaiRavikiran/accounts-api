package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetAccountUnauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/accounts/acc-1001", nil)
	rec := httptest.NewRecorder()
	requireBearer(http.HandlerFunc(getAccount)).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 (T-16 fail-closed)", rec.Code)
	}
}

func TestGetAccountOK(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/accounts/acc-1001", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	req.SetPathValue("id", "acc-1001")
	rec := httptest.NewRecorder()
	requireBearer(http.HandlerFunc(getAccount)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
}

func TestHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	health(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
}
