package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

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
}

type Setting struct {
	Key   string
	Value string
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
	return user, nil
}

func (u *UserDB) CreateUser(clientID, keyHex string) (*User, error) {
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid key hex: %w", err)
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
	for rows.Next() {
		var u User
		var ls string
		if err := rows.Scan(&u.ID, &u.ClientID, &u.Enabled, &u.MaxBytes, &u.CreatedAt, &ls); err != nil {
			return nil, err
		}
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

func (u *UserDB) Stats() (users int, sessions int) {
	u.db.QueryRow(`SELECT COUNT(*) FROM users WHERE enabled=1`).Scan(&users)
	u.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessions)
	return
}

// Admin routes
func (s *Server) registerAdminRoutes(mux *http.ServeMux) {
	// Auth middleware
	auth := func(next http.HandlerFunc) http.HandlerFunc {
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

	mux.HandleFunc("/admin/login", s.loginPage)
	mux.HandleFunc("/admin", auth(s.adminPage))
	mux.HandleFunc("/admin/api/stats", auth(s.apiStats))
	mux.HandleFunc("/admin/api/users", auth(s.apiUsers))
	mux.HandleFunc("/admin/api/users/", auth(s.apiUserByID))
	mux.HandleFunc("/admin/api/config", auth(s.apiConfig))
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
	w.Write([]byte(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>YMT Login</title>
<style>*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,sans-serif;background:#0f0f12;display:flex;justify-content:center;align-items:center;height:100vh}
form{background:#1a1a24;padding:32px;border-radius:12px;width:360px}
h1{color:#fff;font-size:20px;margin-bottom:24px}
input{width:100%;padding:10px 12px;background:#2a2a38;border:1px solid #3a3a48;border-radius:6px;color:#fff;font-size:14px;margin-bottom:16px}
button{width:100%;padding:10px;background:#3b82f6;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer}
</style></head><body>
<form method="post"><h1>YMT Panel</h1>
<input type="password" name="password" placeholder="Admin password" required>
<button type="submit">Login</button></form></body></html>`))
}

func (s *Server) adminPage(w http.ResponseWriter, r *http.Request) {
	users, _ := s.db.ListUsers()
	s.mu.Lock()
	stats := map[string]interface{}{
		"connections": s.connCount,
		"bytes_up":    s.bytesUp,
		"bytes_down":  s.bytesDown,
		"uptime":      time.Since(s.startedAt).Round(time.Second).String(),
		"listen":      s.cfg.Listen,
	}
	s.mu.Unlock()

	tmpl := template.Must(template.New("admin").Parse(`<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>YMT Panel</title>
<style>*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,sans-serif;background:#0f0f12;color:#e0e0e0;padding:24px}
h1{color:#fff;font-size:22px;margin-bottom:16px}
h2{color:#aaa;font-size:14px;margin-bottom:8px;margin-top:24px}
.row{display:flex;gap:12px;flex-wrap:wrap}
.card{background:#1a1a24;border-radius:10px;padding:20px;flex:1;min-width:140px}
.card .v{font-size:26px;font-weight:600;color:#fff}
.card .l{font-size:11px;color:#666;margin-top:4px}
table{width:100%;border-collapse:collapse;margin-top:8px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a2a38;font-size:13px}
th{color:#666;font-weight:500}td{color:#ccc}
form{display:flex;gap:8px;flex-wrap:wrap;align-items:end;margin-top:12px}
form input{background:#2a2a38;border:1px solid #3a3a48;padding:8px 10px;border-radius:6px;color:#fff;font-size:13px}
form label{font-size:11px;color:#666;display:block;margin-bottom:4px}
.btn{display:inline-block;padding:8px 14px;background:#3b82f6;color:#fff;border:none;border-radius:6px;font-size:13px;cursor:pointer}
.btn:hover{background:#2563eb}.btn-sm{padding:4px 10px;font-size:11px}.btn-del{background:#ef4444}.btn-del:hover{background:#dc2626}
.url-box{background:#2a2a38;padding:10px 12px;border-radius:6px;font-family:monospace;font-size:12px;word-break:break-all;color:#9ca3af;margin-top:4px}
</style></head><body>
<h1>⚡ YMT Server</h1>
<div class="row">
<div class="card"><div class="v">{{.Stats.connections}}</div><div class="l">Active connections</div></div>
<div class="card"><div class="v">{{.Stats.uptime}}</div><div class="l">Uptime</div></div>
<div class="card"><div class="v">{{.Stats.listen}}</div><div class="l">Listen addr</div></div>
</div>

<h2>Users</h2>
<table><thead><tr><th>Client ID</th><th>Created</th><th>Last Seen</th><th>Key</th><th></th></tr></thead><tbody>
{{range .Users}}
<tr><td>{{.ClientID}}</td><td>{{.CreatedAt.Format "Jan 2 15:04"}}</td><td>{{.LastSeen.Format "Jan 2 15:04"}}</td>
<td><button class="btn btn-sm" onclick="copyKey('{{.ID}}')">Copy</button></td>
<td><button class="btn btn-sm btn-del" onclick="deleteUser('{{.ClientID}}')">Delete</button></td></tr>
{{end}}</tbody></table>

<form id="add-form"><div><label>Client ID</label><input name="client_id" placeholder="my-phone" required></div>
<div><label>Key (64 hex)</label><input name="key_hex" placeholder="autogenerate" value="{{.NewKey}}"></div>
<button class="btn" type="submit">Add User</button></form>

<h2>New Client Config</h2>
<p style="font-size:12px;color:#666;margin-bottom:8px">Give this to the user. They run it on their device.</p>
<div class="url-box" id="client-config">ymt://{{.Domain}}:443?key=YOUR_KEY_HERE&name=YOUR_NAME</div>

<script>
async function addUser(e){e.preventDefault();const f=new FormData(e.target);const r=await fetch('/admin/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:f.get('client_id'),key_hex:f.get('key_hex')||''})});if(r.ok)location.reload();else alert('Error: '+(await r.text()))}
document.getElementById('add-form').addEventListener('submit',addUser);
async function deleteUser(id){if(!confirm('Delete '+id+'?'))return;await fetch('/admin/api/users/'+id,{method:'DELETE'});location.reload()}
function copyKey(id){alert('Key hidden for security. Use admin API to retrieve.')}
</script>
</body></html>`))

	w.Header().Set("Content-Type", "text/html")
	tmpl.Execute(w, map[string]interface{}{
		"Stats":  stats,
		"Users":  users,
		"Domain": s.cfg.Domain,
		"NewKey": randomHex(32),
	})
}

func (s *Server) apiStats(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	stats := map[string]interface{}{
		"connections": s.connCount,
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
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user":     user,
			"key_hex":  req.KeyHex,
			"connect":  fmt.Sprintf("ymt://%s:%s@%s/%s", req.ClientID, req.KeyHex, s.cfg.Domain, s.cfg.Listen),
		})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (s *Server) apiUserByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/api/users/")
	if r.Method == "DELETE" {
		s.db.DeleteUser(id)
		w.Write([]byte(`{"status":"deleted"}`))
		return
	}
	http.Error(w, "method not allowed", 405)
}

func (s *Server) apiConfig(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"listen": s.cfg.Listen,
		"domain": s.cfg.Domain,
		"version": 1,
	})
}

// Need hex and io — already imported above
var _ = io.Copy