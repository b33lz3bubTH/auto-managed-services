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
	"os"
	"regexp"
	"strings"

	_ "github.com/lib/pq"
)

const (
	superUserDSN = "postgres://postgres:superadmin@postgres:5432/postgres?sslmode=disable"
	listenAddr   = ":8080"
)

var adminKey string

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

	tx, err := db.Begin()
	if err != nil {
		log.Printf("❌ Transaction start failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "transaction start failed"})
		return
	}

	// Create role with restricted privileges
	_, err = tx.Exec(`
		CREATE ROLE $1 WITH LOGIN PASSWORD $2
		NOSUPERUSER NOCREATEDB NOCREATEROLE;
	`, userName, password)
	if err != nil {
		tx.Rollback()
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

	// Create database
	_, err = tx.Exec(fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, dbName, userName))
	if err != nil {
		tx.Rollback()
		log.Printf("❌ Database creation failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "database creation failed"})
		return
	}

	// Revoke public access
	_, err = tx.Exec(fmt.Sprintf(`REVOKE ALL ON DATABASE %s FROM PUBLIC`, dbName))
	if err != nil {
		tx.Rollback()
		log.Printf("❌ Revoke failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "permission revoke failed"})
		return
	}

	// Grant all privileges to the app user only
	_, err = tx.Exec(fmt.Sprintf(`GRANT ALL PRIVILEGES ON DATABASE %s TO %s`, dbName, userName))
	if err != nil {
		tx.Rollback()
		log.Printf("❌ Grant failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "permission grant failed"})
		return
	}

	if err = tx.Commit(); err != nil {
		log.Printf("❌ Commit failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "transaction commit failed"})
		return
	}

	// Return only the connection string
	connStr := fmt.Sprintf("postgres://%s:%s@postgres:5432/%s?sslmode=disable", userName, password, dbName)
	
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
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_=+"
	b := make([]byte, length)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[idx.Int64()]
	}
	return string(b)
}
