package server

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
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

func openUserDB(path string) (*UserDB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := createTables(db); err != nil {
		return nil, fmt.Errorf("create tables: %w", err)
	}

	return &UserDB{db: db}, nil
}

func (u *UserDB) migrate() {
	// Future migrations placeholder
}

func createTables(db *sql.DB) error {
	_, err := db.Exec(`
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

		CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
	`)
	return err
}

func (u *UserDB) GetUserByClientID(clientID string) (*User, error) {
	row := u.db.QueryRow(
		`SELECT id, client_id, key_hash, enabled, max_bytes, created_at, last_seen FROM users WHERE client_id = ? AND enabled = 1`,
		clientID,
	)

	user := &User{}
	var lastSeen string
	err := row.Scan(&user.ID, &user.ClientID, &user.KeyHash, &user.Enabled, &user.MaxBytes, &user.CreatedAt, &lastSeen)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	return user, nil
}

func (u *UserDB) createUser(clientID string, keyHash []byte) (*User, error) {
	id := fmt.Sprintf("%x", sha256.Sum256([]byte(clientID+time.Now().String())))[:16]
	now := time.Now().UTC().Format(time.RFC3339)

	_, err := u.db.Exec(
		`INSERT INTO users (id, client_id, key_hash, created_at) VALUES (?, ?, ?, ?)`,
		id, clientID, keyHash, now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}

	return u.getUserByClientID(clientID)
}

func (u *UserDB) deleteUser(clientID string) error {
	_, err := u.db.Exec(`DELETE FROM users WHERE client_id = ?`, clientID)
	return err
}

func (u *UserDB) listUsers() ([]User, error) {
	rows, err := u.db.Query(
		`SELECT id, client_id, key_hash, enabled, max_bytes, created_at, last_seen FROM users ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		var lastSeen string
		if err := rows.Scan(&user.ID, &user.ClientID, &user.KeyHash, &user.Enabled, &user.MaxBytes, &user.CreatedAt, &lastSeen); err != nil {
			return nil, err
		}
		user.KeyHash = make([]byte, 32) // sanitize output
		users = append(users, user)
	}
	return users, nil
}

func (u *UserDB) ListUsers() ([]User, error) {
	return u.listUsers()
}

func (u *UserDB) CreateUser(clientID string, keyHex []byte) (*User, error) {
	hash := HashKeyForStorage(keyHex)
	return u.createUser(clientID, hash)
}

func (u *UserDB) DeleteUser(clientID string) error {
	return u.deleteUser(clientID)
}

func (u *UserDB) close() error {
	return u.db.Close()
}

// HashKeyForStorage returns SHA-256 of the proof (what we store, never the raw key)
func HashKeyForStorage(masterKey []byte) []byte {
	h := sha256.Sum256(masterKey)
	return h[:]
}

// GenerateClientID generates a URL-safe client ID from base input
func GenerateClientID(base string) string {
	h := sha256.Sum256([]byte(base + time.Now().String()))
	return hex.EncodeToString(h[:8])
}