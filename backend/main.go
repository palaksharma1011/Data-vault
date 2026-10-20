package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"
	"github.com/joho/godotenv"
)

//go:embed web
var webFS embed.FS

func main() {

	if err := godotenv.Load(); err != nil {
        log.Println("No .env file found; using system environment variables")
    }
	dataDir := os.Getenv("VAULT_DATA_DIR")
    if dataDir == "" {
        dataDir = "./data"
    }
	dsn := os.Getenv("DATABASE_URL")
    if dsn == "" {
        log.Fatal("DATABASE_URL is required")
    }

    store, err := NewStore(dataDir, dsn)
    if err != nil {
        log.Fatalf("failed to open store: %v", err)
    }
	defer store.Close()
	km, err := NewKeyManager(dataDir)
	if err != nil {
		log.Fatalf("failed to init key manager: %v", err)
	}
	cfg := LoadConfig()
	app := NewApp(store, km, cfg)

	bootstrapAdmin(store)

	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           logRequests(app.Routes()),
		ReadHeaderTimeout: 10 * time.Second,
		// Short defaults for ordinary JSON calls; the upload/download
		// handlers extend their own deadlines per request so large
		// files are not cut off.
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	log.Printf("Data-Centric Zero-Trust Secure Data Vault listening on %s (require-mfa=%v, hide-unauthorized=%v, max-upload=%dMB)",
		addr, cfg.RequireMFA, cfg.HideUnauthorized, cfg.MaxUploadBytes>>20)
	log.Fatal(srv.ListenAndServe())
}

// Routes builds the HTTP handler (separate from main so tests can use it).
func (a *App) Routes() http.Handler {
	mux := http.NewServeMux()

	// Auth
	mux.HandleFunc("POST /api/login", a.handleLogin)
	mux.HandleFunc("POST /api/login/mfa", a.handleLoginMFA)
	mux.HandleFunc("POST /api/logout", a.handleLogout)
	mux.HandleFunc("GET /api/me", a.handleMe)

	// MFA
	mux.HandleFunc("POST /api/mfa/setup", a.handleMFASetup)
	mux.HandleFunc("POST /api/mfa/enable", a.handleMFAEnable)
	mux.HandleFunc("POST /api/mfa/disable", a.handleMFADisable)

	// Users (admin)
	mux.HandleFunc("POST /api/users", a.handleCreateUser)
	mux.HandleFunc("GET /api/users", a.handleListUsers)
	mux.HandleFunc("POST /api/users/{id}/mfa/reset", a.handleAdminResetMFA)

	// Files
	mux.HandleFunc("POST /api/files/upload", a.handleUploadFile)
	mux.HandleFunc("GET /api/files", a.handleListFiles)
	mux.HandleFunc("POST /api/files/{id}/access", a.handleAccessFile)

	// Policies (admin)
	mux.HandleFunc("POST /api/policies", a.handleCreatePolicy)
	mux.HandleFunc("GET /api/policies", a.handleListPolicies)
	mux.HandleFunc("DELETE /api/policies/{id}", a.handleDeletePolicy)

	// Audit & dashboard (admin)
	mux.HandleFunc("GET /api/audit", a.handleListAudit)
	mux.HandleFunc("GET /api/audit/verify", a.handleVerifyAudit)
	mux.HandleFunc("GET /api/dashboard/summary", a.handleDashboardSummary)

	// Static reference UI
	webRoot, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/", http.FileServer(http.FS(webRoot)))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if len(r.URL.Path) >= 5 && r.URL.Path[:5] == "/api/" {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s (%s)", r.Method, r.URL.Path, time.Since(start))
	})
}

// bootstrapAdmin creates a default administrator on first run only, so the
// demo has a way in before any policies exist. Set VAULT_ADMIN_PASSWORD to
// choose the initial password; otherwise the documented demo default is used.
// Change it (and enrol MFA) immediately in any real deployment.
func bootstrapAdmin(store *Store) {
	if _, exists := store.UserByUsername("admin"); exists {
		return
	}
	password := os.Getenv("VAULT_ADMIN_PASSWORD")
	custom := password != ""
	if !custom {
		password = "Admin@123"
	}
	hash, err := HashPassword(password)
	if err != nil {
		log.Fatalf("failed to bootstrap admin: %v", err)
	}
	admin := &User{ID: newID("user"), Username: "admin", PasswordHash: hash, Role: RoleAdmin, CreatedAt: time.Now()}
	if err := store.CreateUser(admin); err != nil {
		log.Fatalf("failed to save bootstrap admin: %v", err)
	}
	_ = LogEvent(store, admin.ID, admin.Username, admin.Role, "", "", EventUserCreate, DecisionAllow, "bootstrap administrator created on first run")
	log.Println("=====================================================")
	log.Println(" First run: created admin account (username: admin)")
	if custom {
		log.Println("   password: taken from VAULT_ADMIN_PASSWORD")
	} else {
		log.Println("   password: Admin@123   (demo default — change it!)")
	}
	log.Println(" Enrol MFA for this account immediately (Security tab).")
	log.Println("=====================================================")
}
