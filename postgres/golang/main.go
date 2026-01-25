package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	_ "github.com/lib/pq"
	"github.com/joho/godotenv"
)

var (
	adminKey     string
	superUserDSN string
	listenAddr   string
)

type ProvisionRequest struct {
	AppName string `json:"app_name"`
	AdminKey string `json:"admin_key"`
}

type ProvisionResponse struct {
	ConnectionString string `json:"connection_string"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("⚠️  .env file not found, using system environment")
	}

	// Build superUserDSN from environment
	pgUser := getEnv("POSTGRES_USER", "postgres")
	pgPassword := getEnv("POSTGRES_PASSWORD", "superadmin")
	pgHost := getEnv("POSTGRES_HOST", "postgres")
	pgPort := getEnv("POSTGRES_PORT", "5432")
	
	superUserDSN = fmt.Sprintf("postgres://%s:%s@%s:%s/postgres?sslmode=require",
		pgUser, pgPassword, pgHost, pgPort)
	
	// Ensure pgbouncer_auth user exists and userlist.txt is created FIRST
	// This must happen before starting HTTP server so pgbouncer can start
	ensurePgBouncerAuth()
	
	// Get listen port
	listenPort := getEnv("LISTEN_PORT", "8080")
	listenAddr = ":" + listenPort

	// Generate admin key on startup
	adminKey = generateAdminKey(32)
	log.Printf("🔑 ADMIN KEY: %s", adminKey)
	log.Printf("⚠️  Keep this key secret. It's required for all API requests.")

	http.HandleFunc("/provision", provisionHandler)
	http.HandleFunc("/health", healthHandler)

	log.Printf("📡 DB Provisioner listening on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	db, err := sql.Open("postgres", superUserDSN)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"status": "down", "error": err.Error()})
		return
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"status": "down", "error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func provisionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "POST only"})
		return
	}

	var req ProvisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid request body"})
		return
	}

	// Verify admin key
	if req.AdminKey != adminKey {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid admin key"})
		return
	}

	// Validate app name (alphanumeric + underscore, 3-32 chars)
	if matched, _ := regexp.MatchString("^[a-z0-9_]{3,32}$", req.AppName); !matched {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "app_name must be 3-32 chars, lowercase alphanumeric + underscore"})
		return
	}

	dbName := fmt.Sprintf("app_%s", req.AppName)
	userName := fmt.Sprintf("app_%s_user", req.AppName)
	password := generatePassword(32)

	db, err := sql.Open("postgres", superUserDSN)
	if err != nil {
		log.Printf("❌ Connection failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "database connection failed"})
		return
	}
	defer db.Close()

	// Create role with restricted privileges
	// Note: PostgreSQL doesn't support parameterized queries for DDL statements
	// Use dollar-quoting for password to safely handle special characters
	_, err = db.Exec(fmt.Sprintf(`
		CREATE ROLE %s WITH LOGIN PASSWORD $pwd$%s$pwd$
		NOSUPERUSER NOCREATEDB NOCREATEROLE;
	`, quoteIdentifier(userName), password))
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(ErrorResponse{Error: fmt.Sprintf("app '%s' already exists", req.AppName)})
			return
		}
		log.Printf("❌ Role creation failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "role creation failed"})
		return
	}

	// Create database (cannot be in a transaction)
	_, err = db.Exec(fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, quoteIdentifier(dbName), quoteIdentifier(userName)))
	if err != nil {
		// Cleanup: drop the role if database creation failed
		db.Exec(fmt.Sprintf(`DROP ROLE IF EXISTS %s`, quoteIdentifier(userName)))
		if strings.Contains(err.Error(), "already exists") {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(ErrorResponse{Error: fmt.Sprintf("app '%s' already exists", req.AppName)})
			return
		}
		log.Printf("❌ Database creation failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "database creation failed"})
		return
	}

	// Revoke public access
	_, err = db.Exec(fmt.Sprintf(`REVOKE ALL ON DATABASE %s FROM PUBLIC`, quoteIdentifier(dbName)))
	if err != nil {
		log.Printf("❌ Revoke failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "permission revoke failed"})
		return
	}

	// Grant all privileges to the app user only
	_, err = db.Exec(fmt.Sprintf(`GRANT ALL PRIVILEGES ON DATABASE %s TO %s`, quoteIdentifier(dbName), quoteIdentifier(userName)))
	if err != nil {
		log.Printf("❌ Grant failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "permission grant failed"})
		return
	}

	// Return only the connection string with URL-encoded credentials
	// Use pgbouncer port (6432) instead of postgres port (5432)
	pgbouncerHost := getEnv("PGBOUNCER_HOST", "localhost")
	userInfo := url.UserPassword(userName, password)
	connStr := fmt.Sprintf("postgres://%s@%s:6432/%s?sslmode=verify-full", userInfo.String(), pgbouncerHost, dbName)
	
	log.Printf("✅ Provisioned: %s", dbName)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(ProvisionResponse{
		ConnectionString: connStr,
	})
}

func generateAdminKey(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return "sk_" + base64.URLEncoding.EncodeToString(b)[:length]
}

func generatePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@$"
	b := make([]byte, length)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[idx.Int64()]
	}
	return string(b)
}

func getEnv(key, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultVal
}

func quoteIdentifier(ident string) string {
	// PostgreSQL identifier quoting: double quotes and escape any existing double quotes
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
}

func ensurePgBouncerAuth() {
	db, err := sql.Open("postgres", superUserDSN)
	if err != nil {
		log.Printf("⚠️  Failed to connect for pgbouncer_auth setup: %v", err)
		return
	}
	defer db.Close()

	pgbouncerAuthPassword := getEnv("PGBOUNCER_AUTH_PASSWORD", "pgbouncer_auth_pass")

	// Create pgbouncer_auth user if it doesn't exist
	_, err = db.Exec(fmt.Sprintf(`
		DO $$
		BEGIN
			IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pgbouncer_auth') THEN
				CREATE ROLE pgbouncer_auth WITH LOGIN PASSWORD $pwd$%s$pwd$;
			ELSE
				ALTER ROLE pgbouncer_auth WITH PASSWORD $pwd$%s$pwd$;
			END IF;
		END
		$$;
	`, pgbouncerAuthPassword, pgbouncerAuthPassword))
	if err != nil {
		log.Printf("⚠️  Failed to create/update pgbouncer_auth user: %v", err)
		return
	}

	// Grant necessary permissions
	_, err = db.Exec(`
		GRANT pg_read_all_settings TO pgbouncer_auth;
		GRANT pg_read_all_stats TO pgbouncer_auth;
		GRANT SELECT ON pg_shadow TO pgbouncer_auth;
	`)
	if err != nil {
		log.Printf("⚠️  Failed to grant permissions to pgbouncer_auth: %v", err)
		return
	}

	// Write userlist.txt to shared volume
	// Use plaintext password for auth_user so PgBouncer can perform SCRAM auth to Postgres
	if pgbouncerAuthPassword == "" {
		log.Printf("⚠️  PGBOUNCER_AUTH_PASSWORD is empty")
		return
	}
	userlistContent := fmt.Sprintf(`"pgbouncer_auth" "%s"`, pgbouncerAuthPassword)
	userlistPath := "/etc/pgbouncer/userlist.txt"
	
	// Ensure directory exists and is readable by pgbouncer
	if err := os.MkdirAll("/etc/pgbouncer", 0755); err != nil {
		log.Printf("⚠️  Could not create /etc/pgbouncer directory: %v", err)
		return
	}
	if err := os.Chmod("/etc/pgbouncer", 0755); err != nil {
		log.Printf("⚠️  Could not chmod /etc/pgbouncer directory: %v", err)
		return
	}
	
	// Write file with proper permissions (readable by pgbouncer)
	err = os.WriteFile(userlistPath, []byte(userlistContent), 0644)
	if err != nil {
		log.Printf("⚠️  Could not write userlist.txt: %v", err)
		return
	}
	if err := os.Chmod(userlistPath, 0644); err != nil {
		log.Printf("⚠️  Could not chmod userlist.txt: %v", err)
		return
	}
	
	// Verify file was written
	if info, err := os.Stat(userlistPath); err == nil {
		log.Printf("✅ PgBouncer auth user configured, userlist.txt created (%d bytes)", info.Size())
	} else {
		log.Printf("⚠️  userlist.txt verification failed: %v", err)
	}
}
