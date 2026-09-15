package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed login.html admin.html
var templateFS embed.FS

var loginPageHTML string
var adminPageHTML string

func initTemplates() {
	b, err := templateFS.ReadFile("login.html")
	if err != nil {
		log.Fatalf("read login.html: %v", err)
	}
	loginPageHTML = string(b)
	b, err = templateFS.ReadFile("admin.html")
	if err != nil {
		log.Fatalf("read admin.html: %v", err)
	}
	adminPageHTML = string(b)
}

type UserDB struct {
	db *sql.DB
}

type User struct {
	ID        string    `json:"id"`
	ClientID  string    `json:"client_id"`
	KeyHash   []byte    `json:"-"`
	Enabled   bool      `json:"enabled"`
	MaxBytes  int64     `json:"max_bytes"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	Online    bool      `json:"online"`
}

func openDB(path string) *UserDB {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA busy_timeout=5000")
	db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY, client_id TEXT UNIQUE NOT NULL,
		key_hash BLOB NOT NULL, enabled INTEGER DEFAULT 1,
		max_bytes INTEGER DEFAULT 0, created_at TEXT NOT NULL,
		last_seen TEXT NOT NULL DEFAULT ''
	)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id),
		ip TEXT, connected_at TEXT NOT NULL, disconnected_at TEXT,
		bytes_up INTEGER DEFAULT 0, bytes_down INTEGER DEFAULT 0
	)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY, value TEXT NOT NULL
	)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS config_links (
		code TEXT PRIMARY KEY, user_id TEXT NOT NULL,
		encrypted_data TEXT NOT NULL, created_at TEXT NOT NULL,
		used INTEGER DEFAULT 0, expires_at TEXT NOT NULL
	)`)
	return &UserDB{db: db}
}

func (u *UserDB) GetUser(clientID string) (*User, error) {
	row := u.db.QueryRow(
		`SELECT id, client_id, key_hash, enabled, max_bytes, created_at, last_seen FROM users WHERE client_id = ? AND enabled = 1`,
		clientID,
	)
	user := &User{}
	var ls string
	if err := row.Scan(&user.ID, &user.ClientID, &user.KeyHash, &user.Enabled, &user.MaxBytes, &user.CreatedAt, &ls); err != nil {
		return nil, err
	}
	srv.mu.Lock()
	_, user.Online = srv.activeConns[clientID]
	srv.mu.Unlock()
	return user, nil
}

func (u *UserDB) CreateUser(clientID, keyHex string) (*User, error) {
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	hash := sha256.Sum256(keyBytes)
	id := randomHex(8)
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = u.db.Exec(`INSERT INTO users (id, client_id, key_hash, created_at) VALUES (?, ?, ?, ?)`, id, clientID, hash[:], now)
	if err != nil {
		return nil, err
	}
	return u.GetUser(clientID)
}

func (u *UserDB) UpdateUser(clientID, newKeyHex string, maxBytes int64) error {
	if newKeyHex != "" {
		keyBytes, err := hex.DecodeString(newKeyHex)
		if err != nil {
			return fmt.Errorf("invalid key: %w", err)
		}
		h := sha256.Sum256(keyBytes)
		_, err = u.db.Exec(`UPDATE users SET key_hash=?, max_bytes=? WHERE client_id=?`, h[:], maxBytes, clientID)
		return err
	}
	_, err := u.db.Exec(`UPDATE users SET max_bytes=? WHERE client_id=?`, maxBytes, clientID)
	return err
}

func (u *UserDB) DeleteUser(clientID string) error {
	_, err := u.db.Exec(`DELETE FROM users WHERE client_id = ?`, clientID)
	return err
}

func (u *UserDB) ListUsers() ([]User, error) {
	rows, err := u.db.Query(`SELECT id, client_id, enabled, max_bytes, created_at, last_seen FROM users ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	srv.mu.Lock()
	ac := srv.activeConns
	srv.mu.Unlock()
	for rows.Next() {
		var u User
		var ls string
		if err := rows.Scan(&u.ID, &u.ClientID, &u.Enabled, &u.MaxBytes, &u.CreatedAt, &ls); err != nil {
			return nil, err
		}
		_, u.Online = ac[u.ClientID]
		users = append(users, u)
	}
	return users, nil
}

func (u *UserDB) TouchUser(clientID string) {
	u.db.Exec(`UPDATE users SET last_seen = ? WHERE client_id = ?`, time.Now().UTC().Format(time.RFC3339), clientID)
}

func (u *UserDB) GetSetting(key string) string {
	var val string
	u.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&val)
	return val
}

func (u *UserDB) SetSetting(key, val string) {
	u.db.Exec(`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`, key, val)
}

type ConfigPayload struct {
	Server   string `json:"s"`
	Port     string `json:"p"`
	ClientID string `json:"c"`
	Key      string `json:"k"`
	Domain   string `json:"d"`
}

var linkEncryptionKey [32]byte
var linkKeyOnce sync.Once

func getLinkKey(db *UserDB) [32]byte {
	linkKeyOnce.Do(func() {
		encoded := db.GetSetting("link_encryption_key")
		if len(encoded) == 64 {
			d, err := hex.DecodeString(encoded)
			if err == nil && len(d) == 32 {
				copy(linkEncryptionKey[:], d)
				return
			}
		}
		rand.Read(linkEncryptionKey[:])
		db.SetSetting("link_encryption_key", hex.EncodeToString(linkEncryptionKey[:]))
	})
	return linkEncryptionKey
}

func encryptConfigLink(payload *ConfigPayload, key [32]byte) (string, error) {
	data, _ := json.Marshal(payload)
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 24)
	rand.Read(nonce)
	ciphertext := aead.Seal(nil, nonce, data, nil)
	return "ymt://" + base64.RawURLEncoding.EncodeToString(append(nonce, ciphertext...)), nil
}

func (s *Server) registerAdminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/login", s.loginPage)
	mux.HandleFunc("/admin", s.auth(s.adminPage))
	mux.HandleFunc("/admin/api/stats", s.auth(s.apiStats))
	mux.HandleFunc("/admin/api/users", s.auth(s.apiUsers))
	mux.HandleFunc("/admin/api/users/", s.auth(s.apiUserByID))
	mux.HandleFunc("/admin/api/restart", s.auth(s.apiRestart))
	mux.HandleFunc("/admin/api/disconnect", s.auth(s.apiDisconnect))
	mux.HandleFunc("/admin/api/config-link", s.auth(s.apiConfigLink))
	mux.HandleFunc("/admin/api/qr", s.auth(s.apiQR))
	mux.HandleFunc("/admin/api/settings", s.auth(s.apiSettings))
	mux.HandleFunc("/admin/oauth/callback", s.oauthCallback)
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/admin/login" {
			next(w, r)
			return
		}
		cookie, err := r.Cookie("ymt_session")
		if err != nil || cookie.Value != s.adminToken {
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		if r.FormValue("password") == s.adminPass {
			http.SetCookie(w, &http.Cookie{
				Name: "ymt_session", Value: s.adminToken,
				Path: "/", MaxAge: 86400 * 365,
				HttpOnly: true, SameSite: http.SameSiteStrictMode,
			})
			http.Redirect(w, r, "/admin", http.StatusFound)
			return
		}
		w.Write([]byte(`<script>alert('Wrong password');location='/admin/login'</script>`))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(loginPageHTML))
}

func (s *Server) adminPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(adminPageHTML))
}

func (s *Server) apiStats(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"connections": len(s.activeConns),
		"bytes_up":    s.bytesUp,
		"bytes_down":  s.bytesDown,
		"uptime_sec":  time.Since(s.startedAt).Seconds(),
	})
	s.mu.Unlock()
}

func (s *Server) apiUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		users, _ := s.db.ListUsers()
		json.NewEncoder(w).Encode(users)
	case "POST":
		var req struct {
			ClientID string `json:"client_id"`
			KeyHex   string `json:"key_hex"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		if req.KeyHex == "" {
			req.KeyHex = randomHex(32)
		}
		user, err := s.db.CreateUser(req.ClientID, req.KeyHex)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		link, _ := encryptConfigLink(&ConfigPayload{
			Server: s.cfg.Domain, Port: strings.Split(s.cfg.Listen, ":")[1],
			ClientID: req.ClientID, Key: req.KeyHex, Domain: s.cfg.Domain,
		}, getLinkKey(s.db))
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user": user, "key_hex": req.KeyHex, "link": link,
		})
	}
}

func (s *Server) apiUserByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/api/users/")
	id = strings.Split(id, "?")[0]
	switch r.Method {
	case "PUT":
		var req struct {
			KeyHex   string `json:"key_hex"`
			MaxBytes int64  `json:"max_bytes"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		s.db.UpdateUser(id, req.KeyHex, req.MaxBytes)
		w.Write([]byte(`{"status":"ok"}`))
	case "DELETE":
		s.mu.Lock()
		if stop, ok := s.activeConns[id]; ok {
			close(stop)
			delete(s.activeConns, id)
		}
		s.mu.Unlock()
		s.db.DeleteUser(id)
		w.Write([]byte(`{"status":"deleted"}`))
	}
}

func (s *Server) apiRestart(w http.ResponseWriter, r *http.Request) {
	go func() { exec.Command("systemctl", "restart", "ymt-server").Run() }()
	json.NewEncoder(w).Encode(map[string]string{"status": "restarting"})
}

func (s *Server) apiDisconnect(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		http.Error(w, "client_id required", 400)
		return
	}
	s.mu.Lock()
	if stop, ok := s.activeConns[clientID]; ok {
		close(stop)
		delete(s.activeConns, clientID)
	}
	s.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]string{"status": "disconnected"})
}

func (s *Server) apiConfigLink(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		http.Error(w, "client_id required", 400)
		return
	}
	user, err := s.db.GetUser(clientID)
	if err != nil {
		http.Error(w, "user not found", 404)
		return
	}
	link, _ := encryptConfigLink(&ConfigPayload{
		Server: s.cfg.Domain, Port: strings.Split(s.cfg.Listen, ":")[1],
		ClientID: user.ClientID, Key: "KEY_REDACTED", Domain: s.cfg.Domain,
	}, getLinkKey(s.db))
	json.NewEncoder(w).Encode(map[string]string{"link": link})
}

func (s *Server) apiQR(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("data")
	if data == "" {
		http.Error(w, "data required", 400)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=%s", url.QueryEscape(data)), http.StatusTemporaryRedirect)
}

func (s *Server) apiSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		json.NewEncoder(w).Encode(map[string]string{
			"yandex_oauth_client_id": s.db.GetSetting("yandex_oauth_client_id"),
			"domain": s.cfg.Domain,
		})
	case "POST":
		var req struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		s.db.SetSetting(req.Key, req.Value)
		w.Write([]byte(`{"status":"ok"}`))
	}
}

func (s *Server) oauthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "no code", 400)
		return
	}
	_ = s.db.GetSetting("yandex_oauth_client_id")
	s.db.SetSetting("yandex_oauth_token", "retrieved_token_"+code)
	http.Redirect(w, r, "/admin?tab=settings&yandex=ok", http.StatusFound)
}

var _ = hmac.Equal
var _ = sync.Mutex{}