package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
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

// ─── User DB ───

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
	db.Exec(`PRAGMA journal_mode=WAL`)
	db.Exec(`PRAGMA busy_timeout=5000`)
	db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			client_id TEXT UNIQUE NOT NULL,
			key_hash BLOB NOT NULL,
			enabled INTEGER DEFAULT 1,
			max_bytes INTEGER DEFAULT 0,
			created_at TEXT NOT NULL,
			last_seen TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT REFERENCES users(id),
			ip TEXT,
			connected_at TEXT NOT NULL,
			disconnected_at TEXT,
			bytes_up INTEGER DEFAULT 0,
			bytes_down INTEGER DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS config_links (
			code TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			encrypted_data TEXT NOT NULL,
			created_at TEXT NOT NULL,
			used INTEGER DEFAULT 0,
			expires_at TEXT NOT NULL
		);
	`)
	return &UserDB{db: db}
}

func (u *UserDB) GetUser(clientID string) (*User, error) {
	row := u.db.QueryRow(
		`SELECT id, client_id, key_hash, enabled, max_bytes, created_at, last_seen FROM users WHERE client_id = ? AND enabled = 1`,
		clientID,
	)
	user := &User{}
	var lastSeen string
	if err := row.Scan(&user.ID, &user.ClientID, &user.KeyHash, &user.Enabled, &user.MaxBytes, &user.CreatedAt, &lastSeen); err != nil {
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
	_, err = u.db.Exec(
		`INSERT INTO users (id, client_id, key_hash, created_at) VALUES (?, ?, ?, ?)`,
		id, clientID, hash[:], now,
	)
	if err != nil {
		return nil, err
	}
	return u.GetUser(clientID)
}

func (u *UserDB) UpdateUser(clientID, newKeyHex string, maxBytes int64) error {
	var hash []byte
	if newKeyHex != "" {
		keyBytes, err := hex.DecodeString(newKeyHex)
		if err != nil {
			return fmt.Errorf("invalid key: %w", err)
		}
		h := sha256.Sum256(keyBytes)
		hash = h[:]
		_, err = u.db.Exec(`UPDATE users SET key_hash=?, max_bytes=? WHERE client_id=?`, hash, maxBytes, clientID)
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

// ─── Config Link Encryption ───

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
	combined := append(nonce, ciphertext...)
	return "ymt://" + base64.RawURLEncoding.EncodeToString(combined), nil
}

func decryptConfigLink(code string, key [32]byte) (*ConfigPayload, error) {
	if !strings.HasPrefix(code, "ymt://") {
		return nil, fmt.Errorf("invalid link")
	}
	raw, err := base64.RawURLEncoding.DecodeString(code[6:])
	if err != nil {
		return nil, err
	}
	if len(raw) < 24 {
		return nil, fmt.Errorf("too short")
	}
	aead, err := chacha20poly1305.NewX(linkEncryptionKey[:])
	if err != nil {
		return nil, err
	}
	nonce := raw[:24]
	ciphertext := raw[24:]
	data, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	var p ConfigPayload
	json.Unmarshal(data, &p)
	return &p, nil
}

// ─── Admin Routes ───

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
	w.Write([]byte(loginHTML))
}

func (s *Server) adminPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(adminHTML))
}

func (s *Server) apiStats(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	online := len(s.activeConns)
	stats := map[string]interface{}{
		"connections": online,
		"bytes_up":    s.bytesUp,
		"bytes_down":  s.bytesDown,
		"uptime_sec":  time.Since(s.startedAt).Seconds(),
	}
	s.mu.Unlock()
	json.NewEncoder(w).Encode(stats)
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
			"user":    user,
			"key_hex": req.KeyHex,
			"link":    link,
		})
	default:
		http.Error(w, "method not allowed", 405)
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
		if err := s.db.UpdateUser(id, req.KeyHex, req.MaxBytes); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write([]byte(`{"status":"ok"}`))

	case "DELETE":
		// force disconnect
		s.mu.Lock()
		if stop, ok := s.activeConns[id]; ok {
			close(stop)
			delete(s.activeConns, id)
		}
		s.mu.Unlock()
		s.db.DeleteUser(id)
		w.Write([]byte(`{"status":"deleted"}`))

	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (s *Server) apiRestart(w http.ResponseWriter, r *http.Request) {
	go func() {
		exec.Command("systemctl", "restart", "ymt-server").Run()
	}()
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
	// We need the raw key — store it temporarily in memory or re-derive
	// For now, generate a fresh link with a dummy key placeholder
	// In production: store raw keys in encrypted form
	link, _ := encryptConfigLink(&ConfigPayload{
		Server: s.cfg.Domain,
		Port:   strings.Split(s.cfg.Listen, ":")[1],
		ClientID: user.ClientID,
		Key:     "KEY_REDACTED",
		Domain:  s.cfg.Domain,
	}, getLinkKey(s.db))
	json.NewEncoder(w).Encode(map[string]string{"link": link})
}

func (s *Server) apiQR(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("data")
	if data == "" {
		http.Error(w, "data required", 400)
		return
	}
	// Simple QR via Google Charts API (no deps)
	qrURL := fmt.Sprintf("https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=%s", url.QueryEscape(data))
	http.Redirect(w, r, qrURL, http.StatusTemporaryRedirect)
}

func (s *Server) apiSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		json.NewEncoder(w).Encode(map[string]string{
			"yandex_oauth_client_id": s.db.GetSetting("yandex_oauth_client_id"),
			"domain":                s.cfg.Domain,
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
	// Exchange code for token (simplified; real OAuth needs client_secret)
	_ = s.db.GetSetting("yandex_oauth_client_id")
	// In production: POST to https://oauth.yandex.ru/token
	s.db.SetSetting("yandex_oauth_token", "retrieved_token_"+code)
	http.Redirect(w, r, "/admin?tab=settings&yandex=ok", http.StatusFound)
}

// ─── Static HTML ───

const loginHTML = `<!DOCTYPE html>
<html lang="ru" data-theme="dark"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>YMT Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:linear-gradient(135deg,#0f0f12 0%,#1a1a24 100%);display:flex;
justify-content:center;align-items:center;height:100vh;color:#e0e0e0}
form{background:#1a1a24;padding:40px;border-radius:16px;width:380px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
h1{font-size:22px;margin-bottom:8px;color:#fff}
p{font-size:13px;color:#888;margin-bottom:28px}
input{width:100%;padding:12px 16px;background:#2a2a38;border:1px solid #3a3a48;
border-radius:10px;color:#fff;font-size:15px;margin-bottom:20px;transition:border .2s}
input:focus{border-color:#3b82f6;outline:none}
button{width:100%;padding:12px;background:#3b82f6;color:#fff;border:none;
border-radius:10px;font-size:15px;cursor:pointer;font-weight:600}
button:hover{background:#2563eb}
</style></head><body>
<form method="post"><h1>YMT Server</h1><p>Enter admin password</p>
<input type="password" name="password" placeholder="Password" required autofocus>
<button type="submit">Login</button></form></body></html>`

const adminHTML = `<!DOCTYPE html>
<html lang="ru" data-theme="dark"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>YMT Panel</title>
<script>
(function(){const t=localStorage.getItem('ymt_theme')||'dark';document.documentElement.setAttribute('data-theme',t)})()
</script>
<style>
:root{transition:background .2s,color .2s}
[data-theme="dark"]{--bg:#0f0f12;--bg2:#1a1a24;--bg3:#2a2a38;--border:#3a3a48;--text:#e0e0e0;--text2:#aaa;--text3:#666;--accent:#3b82f6;--accent-hover:#2563eb;--danger:#ef4444;--success:#22c55e}
[data-theme="light"]{--bg:#f5f5f7;--bg2:#ffffff;--bg3:#e8e8ed;--border:#d1d1d6;--text:#1d1d1f;--text2:#6e6e73;--text3:#aeaeb2;--accent:#007aff;--accent-hover:#0056cc;--danger:#ff3b30;--success:#34c759}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;transition:background .2s,color .2s}
.sidebar{width:240px;background:var(--bg2);border-right:1px solid var(--border);padding:24px 16px;display:flex;flex-direction:column;flex-shrink:0}
.logo{font-size:18px;font-weight:700;color:var(--text);margin-bottom:24px;display:flex;align-items:center;gap:8px}
.logo span{color:var(--accent)}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:10px;color:var(--text2);text-decoration:none;cursor:pointer;margin-bottom:2px;font-size:14px;transition:.15s}
.nav-item:hover,.nav-item.active{background:var(--bg3);color:var(--text)}
.nav-item.active{font-weight:600}
.spacer{flex:1}
.sidebar-footer{border-top:1px solid var(--border);padding-top:12px;margin-top:12px}
.row{display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:10px;cursor:pointer;color:var(--text2);font-size:13px;transition:.15s}
.row:hover{background:var(--bg3)}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.topbar{display:flex;align-items:center;justify-content:space-between;padding:16px 32px;border-bottom:1px solid var(--border);background:var(--bg);flex-shrink:0}
.topbar h1{font-size:20px;font-weight:700}
.topbar-actions{display:flex;gap:8px;align-items:center}
.content{flex:1;overflow-y:auto;padding:24px 32px}
.page{display:none}.page.active{display:block}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:24px}
.stat-card{background:var(--bg2);border-radius:12px;padding:20px;border:1px solid var(--border)}
.stat-val{font-size:28px;font-weight:700;color:var(--text)}
.stat-lbl{font-size:12px;color:var(--text3);margin-top:4px}
.card{background:var(--bg2);border-radius:12px;padding:24px;margin-bottom:16px;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--border);font-size:13px}
th{color:var(--text3);font-weight:500}
td{color:var(--text)}
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:600}
.badge-on{background:#22c55e20;color:var(--success)}
.badge-off{background:#6e6e7320;color:var(--text3)}
.btn{padding:8px 16px;border-radius:8px;border:none;font-size:13px;cursor:pointer;font-weight:500;transition:.15s;display:inline-flex;align-items:center;gap:6px}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent-hover)}
.btn-danger{background:var(--danger);color:#fff}
.btn-danger:hover{opacity:.8}
.btn-ghost{background:transparent;color:var(--text2);border:1px solid var(--border)}
.btn-ghost:hover{background:var(--bg3)}
.btn-sm{padding:4px 10px;font-size:11px}
.btn-icon{padding:6px 10px;min-width:0}
.flex{display:flex;gap:10px;flex-wrap:wrap;align-items:end}
.form-group{display:flex;flex-direction:column;gap:4px}
.form-group label{font-size:12px;color:var(--text3)}
input,select{background:var(--bg3);border:1px solid var(--border);padding:8px 12px;border-radius:8px;color:var(--text);font-size:13px;transition:border .15s}
input:focus{border-color:var(--accent);outline:none}
.link-box{background:var(--bg3);padding:10px 14px;border-radius:8px;font-family:monospace;font-size:12px;word-break:break-all;color:var(--text2);margin-top:8px}
.toast{position:fixed;bottom:24px;right:24px;background:var(--bg2);color:var(--text);padding:12px 20px;border-radius:10px;border:1px solid var(--border);box-shadow:0 8px 30px rgba(0,0,0,.3);z-index:999;transform:translateY(100px);opacity:0;transition:.3s;font-size:13px}
.toast.show{transform:translateY(0);opacity:1}
.empty{text-align:center;padding:40px;color:var(--text3);font-size:14px}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:100;display:none;justify-content:center;align-items:center}
.modal-overlay.show{display:flex}
.modal{background:var(--bg2);border-radius:16px;padding:24px;width:520px;max-width:90vw;border:1px solid var(--border)}
.modal h3{font-size:18px;margin-bottom:16px}
@media(max-width:768px){.sidebar{display:none}.topbar{padding:12px 16px}.content{padding:12px 16px}}
</style>
</head><body>
<div class="sidebar">
<div class="logo">&#9812; <span>YMT</span> Server</div>
<div class="nav-item active" onclick="switchTab('dashboard')">&#9632; Dashboard</div>
<div class="nav-item" onclick="switchTab('users')">&#9644; Users</div>
<div class="nav-item" onclick="switchTab('settings')">&#9881; Settings</div>
<div class="spacer"></div>
<div class="sidebar-footer">
<div class="row" onclick="toggleTheme()">&#9788; <span id="themeLabel">Dark</span></div>
<div class="row" onclick="toggleLang()">&#127760; <span id="langLabel">RU</span></div>
<div class="row" onclick="logout()">&#10140; Logout</div>
</div>
</div>

<div class="main">
<div class="topbar">
<h1 id="pageTitle">Dashboard</h1>
<div class="topbar-actions">
<button class="btn btn-sm btn-ghost" onclick="refreshStats()">&#8634;</button>
</div>
</div>

<div class="content">

<div id="page-dashboard" class="page active">
<div class="stats">
<div class="stat-card"><div class="stat-val" id="s-online">0</div><div class="stat-lbl" data-i18n="online">Online</div></div>
<div class="stat-card"><div class="stat-val" id="s-up">0 B</div><div class="stat-lbl" data-i18n="upload">Upload</div></div>
<div class="stat-card"><div class="stat-val" id="s-down">0 B</div><div class="stat-lbl" data-i18n="download">Download</div></div>
<div class="stat-card"><div class="stat-val" id="s-uptime">-</div><div class="stat-lbl" data-i18n="uptime">Uptime</div></div>
</div>
<div class="card"><h2 data-i18n="quick_actions">Quick Actions</h2>
<button class="btn btn-primary" onclick="restartServer()">&#8635; <span data-i18n="restart_vpn">Restart VPN</span></button>
<div style="margin-top:12px;padding:12px;background:var(--bg3);border-radius:8px;font-size:12px;color:var(--text2)">
<strong data-i18n="server_info">Server:</strong> 2.27.123.198:9443</div>
</div>
</div>

<div id="page-users" class="page">
<div class="card">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
<h2 style="margin:0" data-i18n="users">Users</h2>
<button class="btn btn-sm btn-primary" onclick="showAddForm()">+ <span data-i18n="add">Add</span></button>
</div>
<table><thead><tr>
<th data-i18n="client_id">Client ID</th><th data-i18n="status">Status</th><th data-i18n="traffic">Traffic</th><th data-i18n="created">Created</th><th data-i18n="last_seen">Last Seen</th><th data-i18n="actions">Actions</th>
</tr></thead><tbody id="users-tbody"></tbody></table>
</div>

<div id="addFormCard" class="card" style="display:none">
<h2 data-i18n="add_user">Add User</h2>
<form id="addUserForm" onsubmit="addUser(event)">
<div class="flex">
<div class="form-group"><label data-i18n="client_id_lbl">Client ID</label><input name="client_id" placeholder="my-phone" required></div>
<div class="form-group"><label data-i18n="key_lbl">Key (empty = auto)</label><input name="key_hex" placeholder="64 hex chars"></div>
<button class="btn btn-primary" type="submit" style="margin-top:18px" data-i18n="create_btn">Create</button>
<button class="btn btn-ghost" type="button" style="margin-top:18px" onclick="hideAddForm()" data-i18n="cancel">Cancel</button>
</div>
</form>
</div>
</div>

<div id="page-settings" class="page">
<div class="card">
<h2 data-i18n="yandex_oauth">Yandex OAuth</h2>
<p style="font-size:13px;color:var(--text3);margin-bottom:12px" data-i18n="oauth_desc">Optional. Configure at oauth.yandex.ru, set redirect to http://2.27.123.198:8080/admin/oauth/callback</p>
<form id="oauthForm" onsubmit="saveOAuth(event)">
<div class="flex">
<div class="form-group" style="flex:1"><label>Client ID</label><input name="client_id" value="" style="width:100%"></div>
<button class="btn btn-primary" type="submit" style="margin-top:18px" data-i18n="save">Save</button>
</div>
</form>
</div>
<div class="card">
<h2 data-i18n="server_config">Server Config</h2>
<div style="font-size:13px;color:var(--text2);line-height:1.8">
<strong data-i18n="domain">Domain:</strong> 2.27.123.198<br>
<strong data-i18n="port">Port:</strong> 9443<br>
<strong data-i18n="admin_url">Admin:</strong> <a href="http://2.27.123.198:8080/admin" style="color:var(--accent)" target="_blank">http://2.27.123.198:8080/admin</a><br>
</div>
</div>
</div>

</div>
</div>

<div id="toast" class="toast"></div>
<div id="userModal" class="modal-overlay" onclick="if(event.target==this)closeModal()">
<div class="modal"><h3 id="modalTitle" data-i18n="user_config">User Config</h3>
<div id="modalBody"></div>
<button class="btn btn-ghost" onclick="closeModal()" style="margin-top:16px" data-i18n="close">Close</button>
</div>
</div>

<script>
// ─── i18n ───
const i18n = {
ru: {
online:'Online',upload:'Upload',download:'Download',uptime:'Uptime',
quick_actions:'Quick Actions',restart_vpn:'Restart VPN',server_info:'Server:',
users:'Users',add:'Add',client_id:'Client ID',status:'Status',traffic:'Traffic',
created:'Created',last_seen:'Last Seen',actions:'Actions',add_user:'Add User',
client_id_lbl:'Client ID',key_lbl:'Key (empty = auto)',create_btn:'Create',cancel:'Cancel',
yandex_oauth:'Yandex OAuth',oauth_desc:'Optional. Configure at oauth.yandex.ru',
save:'Save',server_config:'Server Config',domain:'Domain:',port:'Port:',
admin_url:'Admin:',user_config:'User Config',close:'Close',no_users:'No users',
offline:'Offline'},
en: {
online:'Online',upload:'Upload',download:'Download',uptime:'Uptime',
quick_actions:'Quick Actions',restart_vpn:'Restart VPN',server_info:'Server:',
users:'Users',add:'Add',client_id:'Client ID',status:'Status',traffic:'Traffic',
created:'Created',last_seen:'Last Seen',actions:'Actions',add_user:'Add User',
client_id_lbl:'Client ID',key_lbl:'Key (empty = auto)',create_btn:'Create',cancel:'Cancel',
yandex_oauth:'Yandex OAuth',oauth_desc:'Optional. Configure at oauth.yandex.ru',
save:'Save',server_config:'Server Config',domain:'Domain:',port:'Port:',
admin_url:'Admin:',user_config:'User Config',close:'Close',no_users:'No users',
offline:'Offline'}
}

let lang = localStorage.getItem('ymt_lang') || 'ru'

function applyLang(){
document.querySelectorAll('[data-i18n]').forEach(el=>{
const key=el.dataset.i18n
if(i18n[lang]&&i18n[lang][key])el.textContent=i18n[lang][key]
})
document.getElementById('langLabel').textContent=lang.toUpperCase()
document.documentElement.lang=lang
}
applyLang()

function toggleLang(){
lang=lang==='ru'?'en':'ru'
localStorage.setItem('ymt_lang',lang)
applyLang()
}

// ─── Theme ───
function toggleTheme(){
const html=document.documentElement
const cur=html.getAttribute('data-theme')
const next=cur==='dark'?'light':'dark'
html.setAttribute('data-theme',next)
localStorage.setItem('ymt_theme',next)
document.getElementById('themeLabel').textContent=next==='dark'?'Dark':'Light'
}
document.getElementById('themeLabel').textContent=document.documentElement.getAttribute('data-theme')==='dark'?'Dark':'Light'

// ─── Tabs ───
function switchTab(name){
document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'))
document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'))
document.getElementById('page-'+name).classList.add('active')
document.querySelector(`.nav-item[onclick*="'${name}'"]`).classList.add('active')
const titles={dashboard:'Dashboard',users:'Users',settings:'Settings'}
document.getElementById('pageTitle').textContent=titles[name]||name
if(name==='dashboard')refreshStats()
if(name==='users')loadUsers()
}

function showAddForm(){document.getElementById('addFormCard').style.display='block'}
function hideAddForm(){document.getElementById('addFormCard').style.display='none'}

function toast(msg){
const t=document.getElementById('toast');t.textContent=msg
t.classList.add('show');setTimeout(()=>t.classList.remove('show'),3000)
}

// ─── Stats ───
function refreshStats(){
fetch('/admin/api/stats').then(r=>r.json()).then(d=>{
document.getElementById('s-online').textContent=d.connections
document.getElementById('s-up').textContent=fmtBytes(d.bytes_up)
document.getElementById('s-down').textContent=fmtBytes(d.bytes_down)
const u=Math.floor(d.uptime_sec)
document.getElementById('s-uptime').textContent=Math.floor(u/3600)+'h '+Math.floor((u%3600)/60)+'m'
}).catch(()=>{})
}
setInterval(refreshStats,5000);refreshStats()

// ─── Users ───
function loadUsers(){
fetch('/admin/api/users').then(r=>r.json()).then(users=>{
const tbody=document.getElementById('users-tbody')
if(!users.length){
tbody.innerHTML='<tr><td colspan="6" class="empty" data-i18n="no_users">No users</td></tr>'
applyLang()
return
}
tbody.innerHTML=users.map(u=>'<tr><td>'+esc(u.client_id)+'</td>'+
'<td><span class="badge '+(u.online?'badge-on':'badge-off')+'">'+(u.online?'Online':'Offline')+'</span></td>'+
'<td>'+fmtBytes(u.max_bytes)+'</td>'+
'<td>'+fmtTime(u.created_at)+'</td>'+
'<td>'+(u.last_seen?fmtTime(u.last_seen):'-')+'</td>'+
'<td>'+
'<button class="btn btn-sm btn-primary btn-icon" onclick="showConfig(\''+u.client_id+'\')" title="Config">&#9881;</button> '+
'<button class="btn btn-sm btn-ghost btn-icon" onclick="disconnectUser(\''+u.client_id+'\')" title="Disconnect">&#9632;</button> '+
'<button class="btn btn-sm btn-danger btn-icon" onclick="deleteUser(\''+u.client_id+'\')" title="Delete">&#10005;</button>'+
'</td></tr>').join('')
}).catch(()=>tbody.innerHTML='<tr><td colspan="6" class="empty">Error loading users</td></tr>')
}

function addUser(e){
e.preventDefault()
const f=new FormData(e.target)
fetch('/admin/api/users',{method:'POST',
headers:{'Content-Type':'application/json'},
body:JSON.stringify({client_id:f.get('client_id'),key_hex:f.get('key_hex')||''})
}).then(r=>{
if(!r.ok)return r.text().then(t=>{throw new Error(t)})
return r.json()
}).then(d=>{
toast('User '+d.user.client_id+' created!')
showConfigModal(d.user.client_id,d.key_hex,d.link)
hideAddForm()
loadUsers()
}).catch(e=>toast('Error: '+e.message))
}

function deleteUser(id){
if(!confirm('Delete '+id+'?'))return
fetch('/admin/api/users/'+id,{method:'DELETE'}).then(()=>{loadUsers();toast('Deleted')})
}

function disconnectUser(id){
fetch('/admin/api/disconnect?client_id='+encodeURIComponent(id))
.then(()=>{loadUsers();toast('Disconnected')})
}

function showConfig(clientId){
fetch('/admin/api/config-link?client_id='+encodeURIComponent(clientId))
.then(r=>r.json()).then(d=>showConfigModal(clientId,'',d.link))
}

function showConfigModal(clientId,key,link){
const m=document.getElementById('modalBody')
const linkEsc=esc(link)
m.innerHTML='<div style="font-size:13px;line-height:1.8">'+
'<strong>Client ID:</strong> '+esc(clientId)+'<br>'+
(key?'<strong>Key:</strong> <code>'+esc(key)+'</code><br>':'')+
'<strong>Config Link:</strong>'+
'<div class="link-box">'+linkEsc+'</div>'+
'</div>'+
'<div style="margin-top:12px;display:flex;gap:8px">'+
'<button class="btn btn-sm btn-primary" onclick="copyText(\''+linkEsc.replace(/'/g,"\\'")+'\')">Copy</button> '+
'<button class="btn btn-sm btn-ghost" onclick="showQR(\''+linkEsc.replace(/'/g,"\\'")+'\')">QR</button>'+
'</div>'
document.getElementById('userModal').classList.add('show')
}

function showQR(data){
document.getElementById('modalBody').innerHTML='<img src="https://api.qrserver.com/v1/create-qr-code/?size=300x300&data='+encodeURIComponent(data)+'" style="width:280px;display:block;margin:0 auto;border-radius:8px">'
}

function closeModal(){
document.getElementById('userModal').classList.remove('show')
}

function copyText(t){
navigator.clipboard.writeText(t).then(()=>toast('Copied!')).catch(()=>{})
}

// ─── Settings ───
function saveOAuth(e){
e.preventDefault();const f=new FormData(e.target)
fetch('/admin/api/settings',{method:'POST',
headers:{'Content-Type':'application/json'},
body:JSON.stringify({key:'yandex_oauth_client_id',value:f.get('client_id')})
}).then(()=>toast('Saved'))
}

function restartServer(){
if(!confirm('Restart VPN?'))return
fetch('/admin/api/restart',{method:'POST'}).then(()=>toast('Restarting...'))
}

function logout(){
document.cookie='ymt_session=;expires=Thu,01 Jan 1970;path=/'
location='/admin/login'
}

// ─── Helpers ───
function esc(s){const d=document.createElement('div');d.appendChild(document.createTextNode(s));return d.innerHTML}
function fmtBytes(b){if(!b)return'0 B';const u=['B','KB','MB','GB'];let i=0;let v=b
while(v>=1024&&i<3){v/=1024;i++}
return v.toFixed(1)+' '+u[i]}
function fmtTime(t){if(!t)return'-';const d=new Date(t);return isNaN(d.getTime())?'-':d.toLocaleDateString()+' '+d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}

// ─── Init ───
refreshStats()
loadUsers()
</script>
</body></html>`

var _ = sync.Mutex{}
var _ = hmac.Equal
function fmtTime(t){if(!t)return'-';const d=new Date(t);return d.toLocaleDateString()+' '+d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}
</script>
</body></html>`

var _ = hmac.Equal
var _ = sync.WaitGroup{}