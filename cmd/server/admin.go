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

func init() {
	rand.Read(linkEncryptionKey[:])
}

func encryptConfigLink(payload *ConfigPayload) (string, error) {
	data, _ := json.Marshal(payload)
	aead, err := chacha20poly1305.NewX(linkEncryptionKey[:])
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 24)
	rand.Read(nonce)
	ciphertext := aead.Seal(nil, nonce, data, nil)
	combined := append(nonce, ciphertext...)
	return "ymt://" + base64.RawURLEncoding.EncodeToString(combined), nil
}

func decryptConfigLink(code string) (*ConfigPayload, error) {
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
		})
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
		Key:     "KEY_REDACTED", // actual key retrieval from secure storage
		Domain:  s.cfg.Domain,
	})
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
<html lang="ru"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>YMT Login</title>
<style>*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:linear-gradient(135deg,#0f0f12 0%,#1a1a24 100%);display:flex;
justify-content:center;align-items:center;height:100vh;color:#e0e0e0}
form{background:#1a1a24;padding:40px;border-radius:16px;width:380px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
h1{font-size:22px;margin-bottom:8px;color:#fff}
p{font-size:13px;color:#888;margin-bottom:28px}
input{width:100%;padding:12px 16px;background:#2a2a38;border:1px solid #3a3a48;
border-radius:10px;color:#fff;font-size:15px;margin-bottom:20px;
transition:border .2s}
input:focus{border-color:#3b82f6;outline:none}
button{width:100%;padding:12px;background:#3b82f6;color:#fff;border:none;
border-radius:10px;font-size:15px;cursor:pointer;font-weight:600}
button:hover{background:#2563eb}
</style></head><body>
<form method="post"><h1>YMT Server</h1><p>Введите пароль администратора</p>
<input type="password" name="password" placeholder="Пароль" required autofocus>
<button type="submit">Войти</button></form></body></html>`

const adminHTML = `<!DOCTYPE html>
<html lang="ru" id="html"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>YMT Panel</title>
<script>const _=document.documentElement;_.dataset.theme=localStorage.getItem('ymt_theme')||'dark'</script>
<style>
:root{[theme=dark]{--bg:#0f0f12;--bg2:#1a1a24;--bg3:#2a2a38;--border:#3a3a48;--text:#e0e0e0;--text2:#aaa;--text3:#666;--accent:#3b82f6;--accent-hover:#2563eb;--danger:#ef4444;--success:#22c55e}
[theme=light]{--bg:#f5f5f7;--bg2:#ffffff;--bg3:#e8e8ed;--border:#d1d1d6;--text:#1d1d1f;--text2:#6e6e73;--text3:#aeaeb2;--accent:#007aff;--accent-hover:#0056cc;--danger:#ff3b30;--success:#34c759}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:var(--bg);color:var(--text);min-height:100vh;display:flex;transition:.2s}
.sidebar{width:240px;background:var(--bg2);border-right:1px solid var(--border);
padding:24px 16px;display:flex;flex-direction:column;flex-shrink:0}
.logo{font-size:18px;font-weight:700;color:var(--text);margin-bottom:24px;display:flex;align-items:center;gap:8px}
.logo span{color:var(--accent)}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:10px;
color:var(--text2);text-decoration:none;cursor:pointer;margin-bottom:2px;font-size:14px;transition:.15s}
.nav-item:hover,.nav-item.active{background:var(--bg3);color:var(--text)}
.nav-item.active{font-weight:600}
.spacer{flex:1}
.theme-toggle{display:flex;align-items:center;gap:8px;padding:10px 12px;border-radius:10px;
cursor:pointer;color:var(--text2);font-size:13px;transition:.15s;margin-top:8px}
.theme-toggle:hover{background:var(--bg3)}
.main{flex:1;padding:32px;overflow-y:auto}
.page{display:none}.page.active{display:block}
h1{font-size:26px;margin-bottom:24px;font-weight:700}
h2{font-size:16px;color:var(--text2);margin-bottom:12px;font-weight:600;
display:flex;align-items:center;gap:8px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:24px}
.stat-card{background:var(--bg2);border-radius:12px;padding:20px;border:1px solid var(--border)}
.stat-val{font-size:28px;font-weight:700;color:var(--text)}
.stat-lbl{font-size:12px;color:var(--text3);margin-top:4px}
.card{background:var(--bg2);border-radius:12px;padding:24px;margin-bottom:16px;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--border);
font-size:13px}
th{color:var(--text3);font-weight:500}
td{color:var(--text)}
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:600}
.badge-on{background:#22c55e20;color:var(--success)}
.badge-off{background:#6e6e7320;color:var(--text3)}
.btn{padding:8px 16px;border-radius:8px;border:none;font-size:13px;
cursor:pointer;font-weight:500;transition:.15s;display:inline-flex;align-items:center;gap:6px}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent-hover)}
.btn-danger{background:var(--danger);color:#fff}
.btn-danger:hover{opacity:.8}
.btn-ghost{background:transparent;color:var(--text2);border:1px solid var(--border)}
.btn-ghost:hover{background:var(--bg3)}
.btn-sm{padding:4px 10px;font-size:11px}
form{display:flex;gap:10px;flex-wrap:wrap;align-items:end}
form label{font-size:12px;color:var(--text3);display:block;margin-bottom:4px}
input,select{background:var(--bg3);border:1px solid var(--border);padding:8px 12px;
border-radius:8px;color:var(--text);font-size:13px;transition:border .15s}
input:focus{border-color:var(--accent);outline:none}
.link-box{background:var(--bg3);padding:10px 14px;border-radius:8px;
font-family:monospace;font-size:12px;word-break:break-all;color:var(--text2);margin-top:8px}
.toast{position:fixed;bottom:24px;right:24px;background:var(--bg2);color:var(--text);
padding:12px 20px;border-radius:10px;border:1px solid var(--border);
box-shadow:0 8px 30px rgba(0,0,0,.3);z-index:999;transform:translateY(100px);
opacity:0;transition:.3s;font-size:13px}
.toast.show{transform:translateY(0);opacity:1}
.empty{text-align:center;padding:40px;color:var(--text3);font-size:14px}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:100;
display:none;justify-content:center;align-items:center}
.modal-overlay.show{display:flex}
.modal{background:var(--bg2);border-radius:16px;padding:24px;width:480px;max-width:90vw;border:1px solid var(--border)}
.modal h3{font-size:18px;margin-bottom:16px}
@media(max-width:768px){.sidebar{display:none}.main{padding:16px}}
</style></head><body>
<div class="sidebar">
<div class="logo">&#9812; <span>YMT</span> Server</div>
<div class="nav-item active" data-tab="dashboard" onclick="switchTab('dashboard')">
&#9632; Dashboard</div>
<div class="nav-item" data-tab="users" onclick="switchTab('users')">
&#9644; Users</div>
<div class="nav-item" data-tab="settings" onclick="switchTab('settings')">
&#9881; Settings</div>
<div class="spacer"></div>
<div class="theme-toggle" onclick="toggleTheme()">
&#9788; <span id="themeLabel">Dark</span></div>
<div class="nav-item" onclick="logout()">&#10140; Logout</div>
</div>

<div class="main">
<div id="page-dashboard" class="page active">
<h1>Dashboard</h1>
<div class="stats">
<div class="stat-card"><div class="stat-val" id="s-online">0</div><div class="stat-lbl">Online</div></div>
<div class="stat-card"><div class="stat-val" id="s-up">0 B</div><div class="stat-lbl">Upload</div></div>
<div class="stat-card"><div class="stat-val" id="s-down">0 B</div><div class="stat-lbl">Download</div></div>
<div class="stat-card"><div class="stat-val" id="s-uptime">-</div><div class="stat-lbl">Uptime</div></div>
</div>
<div class="card"><h2>&#9654; Quick Actions</h2>
<button class="btn btn-primary" onclick="restartServer()">&#8635; Restart VPN</button>
<button class="btn btn-ghost" onclick="refreshStats()">&#8634; Refresh</button>
</div>
</div>

<div id="page-users" class="page">
<h1>Users</h1>
<div class="card">
<table><thead><tr>
<th>Client ID</th><th>Status</th><th>Traffic</th><th>Created</th><th>Last Seen</th><th>Actions</th>
</tr></thead><tbody id="users-tbody"></tbody></table>
</div>
<div class="card">
<h2>&#43; Add User</h2>
<form id="addUserForm" onsubmit="addUser(event)">
<div><label>Client ID</label><input name="client_id" placeholder="my-phone" required></div>
<div><label>Key (empty = auto)</label><input name="key_hex" placeholder="64 hex chars"></div>
<button class="btn btn-primary" type="submit">Create</button>
</form>
</div>
</div>

<div id="page-settings" class="page">
<h1>Settings</h1>
<div class="card">
<h2>&#9881; Yandex OAuth</h2>
<p style="font-size:13px;color:var(--text3);margin-bottom:12px">
Настройте OAuth приложение в <a href="https://oauth.yandex.ru" target="_blank" style="color:var(--accent)">oauth.yandex.ru</a>,
укажите Redirect URI: <code style="background:var(--bg3);padding:2px 6px;border-radius:4px">http://2.27.123.198:8080/admin/oauth/callback</code></p>
<form id="oauthForm" onsubmit="saveOAuth(event)">
<div><label>Client ID</label><input name="client_id" value="" style="width:300px"></div>
<button class="btn btn-primary" type="submit">Save</button>
</form>
<div style="margin-top:12px">
<button class="btn btn-ghost" onclick="getYandexToken()">&#127910; Get Token</button>
<span id="tokenStatus" style="font-size:12px;color:var(--text3);margin-left:8px"></span>
</div>
</div>
<div class="card">
<h2>&#9881; Server Config</h2>
<div style="font-size:13px;color:var(--text2);line-height:1.6">
<strong>Domain:</strong> 2.27.123.198<br>
<strong>Port:</strong> 9443<br>
<strong>Admin:</strong> http://2.27.123.198:8080/admin<br>
</div>
</div>
</div>
</div>

<div id="toast" class="toast"></div>

<div id="userModal" class="modal-overlay" onclick="if(event.target==this)closeModal()">
<div class="modal">
<h3 id="modalTitle">User Config</h3>
<div id="modalBody"></div>
<button class="btn btn-ghost" onclick="closeModal()" style="margin-top:12px">Close</button>
</div>
</div>

<script>
let theme = localStorage.getItem('ymt_theme')||'dark'
function toggleTheme(){
theme=theme==='dark'?'light':'dark'
document.documentElement.dataset.theme=theme
localStorage.setItem('ymt_theme',theme)
document.getElementById('themeLabel').textContent=theme==='dark'?'Dark':'Light'
}
document.getElementById('themeLabel').textContent=theme==='dark'?'Dark':'Light'

function switchTab(name){
document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'))
document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'))
document.getElementById('page-'+name).classList.add('active')
document.querySelector('[data-tab="'+name+'"]').classList.add('active')
if(name==='dashboard')refreshStats()
if(name==='users')loadUsers()
}

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
if(!users.length){tbody.innerHTML='<tr><td colspan="6" class="empty">No users</td></tr>';return}
tbody.innerHTML=users.map(u=>'<tr><td>'+esc(u.client_id)+'</td>'+
'<td><span class="badge '+(u.online?'badge-on':'badge-off')+'">'+(u.online?'Online':'Offline')+'</span></td>'+
'<td>'+fmtBytes(u.max_bytes)+'</td>'+
'<td>'+fmtTime(u.created_at)+'</td>'+
'<td>'+(u.last_seen?fmtTime(u.last_seen):'never')+'</td>'+
'<td>'+
'<button class="btn btn-sm btn-primary" onclick="showConfig(\''+u.client_id+'\')">&#128179;</button> '+
'<button class="btn btn-sm btn-ghost" onclick="disconnectUser(\''+u.client_id+'\')">&#9632;</button> '+
'<button class="btn btn-sm btn-danger" onclick="deleteUser(\''+u.client_id+'\')">&#10005;</button>'+
'</td></tr>').join('')
})
}

function addUser(e){
e.preventDefault();const f=new FormData(e.target)
fetch('/admin/api/users',{method:'POST',
headers:{'Content-Type':'application/json'},
body:JSON.stringify({client_id:f.get('client_id'),key_hex:f.get('key_hex')||''})
}).then(r=>r.ok?r.json():Promise.reject()).then(d=>{
toast('User created!')
showConfigModal(d.user.client_id,d.key_hex,d.link)
loadUsers()
}).catch(()=>toast('Error creating user'))
}

function deleteUser(id){
if(!confirm('Delete '+id+'?'))return
fetch('/admin/api/users/'+id,{method:'DELETE'}).then(()=>{loadUsers();toast('Deleted')})
}

function disconnectUser(id){
fetch('/admin/api/disconnect?client_id='+id).then(()=>{loadUsers();toast('Disconnected')})
}

function showConfig(clientId){
fetch('/admin/api/config-link?client_id='+clientId)
.then(r=>r.json()).then(d=>showConfigModal(clientId,'',d.link))
}

function showConfigModal(clientId,key,link){
const m=document.getElementById('modalBody')
m.innerHTML='<div style="font-size:13px;line-height:1.6">'+
'<strong>Client ID:</strong> '+esc(clientId)+'<br>'+
(key?'<strong>Key:</strong> <code>'+esc(key)+'</code><br>':'')+
'<strong>Config Link:</strong><div class="link-box">'+esc(link)+'</div>'+
'</div>'+
'<button class="btn btn-sm btn-primary" onclick="copyText(\''+link+'\')">Copy Link</button> '+
'<button class="btn btn-sm btn-ghost" onclick="showQR(\''+link+'\')">QR Code</button>'
document.getElementById('userModal').classList.add('show')
}

function showQR(data){
const m=document.getElementById('modalBody')
const qr='https://api.qrserver.com/v1/create-qr-code/?size=300x300&data='+encodeURIComponent(data)
m.innerHTML='<img src="'+qr+'" style="width:300px;display:block;margin:0 auto;border-radius:8px">'+
'<div style="margin-top:12px;font-size:12px;color:var(--text3)">Scan with YMT client app</div>'
}

function closeModal(){
document.getElementById('userModal').classList.remove('show')
}

function copyText(t){
navigator.clipboard.writeText(t).then(()=>toast('Copied!')).catch(()=>toast('Copy failed'))
}

// ─── Settings ───
function saveOAuth(e){
e.preventDefault();const f=new FormData(e.target)
fetch('/admin/api/settings',{method:'POST',
headers:{'Content-Type':'application/json'},
body:JSON.stringify({key:'yandex_oauth_client_id',value:f.get('client_id')})
}).then(()=>toast('OAuth settings saved')).catch(()=>toast('Error'))
}

function getYandexToken(){
fetch('/admin/api/settings').then(r=>r.json()).then(s=>{
if(!s.yandex_oauth_client_id){toast('Set OAuth Client ID first');return}
const u='https://oauth.yandex.ru/authorize?response_type=code&client_id='+
s.yandex_oauth_client_id+'&redirect_uri=http://2.27.123.198:8080/admin/oauth/callback'
window.open(u,'_blank')
document.getElementById('tokenStatus').textContent='After auth, you\'ll be redirected back'
}).catch(()=>toast('Error loading settings'))
}

function restartServer(){
if(!confirm('Restart VPN server?'))return
fetch('/admin/api/restart',{method:'POST'}).then(()=>toast('Restarting...'))
}

function logout(){
document.cookie='ymt_session=;expires=Thu,01 Jan 1970;path=/'
location='/admin/login'
}

// ─── Helpers ───
function esc(s){return document.createElement('span').appendChild(document.createTextNode(s)).parentNode.innerHTML}
function fmtBytes(b){if(!b)return'0 B';const u=['B','KB','MB','GB'];let i=0;let v=b
while(v>=1024&&i<3){v/=1024;i++}
return v.toFixed(1)+' '+u[i]}
function fmtTime(t){if(!t)return'-';const d=new Date(t);return d.toLocaleDateString()+' '+d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}
</script>
</body></html>`

var _ = hmac.Equal
var _ = sync.WaitGroup{}