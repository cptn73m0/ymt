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

// ... rest of the file below will be preserved

var _ = hmac.Equal
var _ = sync.Mutex{}