// accounts-api is a minimal account-read service used to demonstrate
// security controls (identity, logging, fail-closed authn). It is not a
// core-banking ledger.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type account struct {
	ID       string `json:"id"`
	Currency string `json:"currency"`
	Status   string `json:"status"`
}

// In-memory stand-in. Production reads from a locked-down datastore
// using the secret mounted at dbURLPath (T-05).
var directory = map[string]account{
	"acc-1001": {ID: "acc-1001", Currency: "GBP", Status: "active"},
	"acc-1002": {ID: "acc-1002", Currency: "GBP", Status: "frozen"},
}

const dbURLPath = "/var/run/secrets/app/db-url"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if _, err := os.Stat(dbURLPath); err != nil {
		// Missing secret is a start-up failure in prod. Local/dev may
		// set ACCOUNTS_ALLOW_EMPTY_SECRET=1 (documented, never in cluster).
		if os.Getenv("ACCOUNTS_ALLOW_EMPTY_SECRET") != "1" {
			log.Error("database secret mount missing", "path", dbURLPath)
			os.Exit(1)
		}
		log.Warn("starting without database secret mount; development only")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	mux.HandleFunc("GET /readyz", ready)
	mux.Handle("GET /accounts/{id}", requireBearer(http.HandlerFunc(getAccount)))

	addr := listenAddr()
	srv := &http.Server{
		Addr:              addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	go func() {
		log.Info("listen", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func listenAddr() string {
	if p := os.Getenv("PORT"); p != "" {
		return ":" + p
	}
	return ":8080"
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func ready(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

func getAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Do not log the bearer token or full URL query (T-14).
	slog.Info("account_lookup", "account_id", id, "request_id", r.Header.Get("X-Request-Id"))

	acct, ok := directory[id]
	if !ok {
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(acct)
}

// requireBearer is fail-closed (ADR-009 / T-16). Token verification is
// delegated to the platform gateway in production; this guard prevents
// an open datastore if the pod is reached directly.
func requireBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("Authorization")
		if !strings.HasPrefix(raw, "Bearer ") || strings.TrimSpace(raw[7:]) == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
