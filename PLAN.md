# YMT — Yandex Music Tunnel: Complete Implementation Plan

## Vision

A VPN/proxy protocol that masquerades all tunnel traffic as legitimate Yandex Music API requests. DPI sees TLS 1.3 + HTTP/2 conversations indistinguishable from the real `api.music.yandex.net` — same JA3 fingerprint, same SETTINGS frames, same timing patterns, same payload structure. Inside the HTTP/2 body rides an encrypted (XChaCha20-Poly1305) smux-multiplexed tunnel.

Architecture inspired by olcRTC (tunnel inside video calls) but applied to Yandex Music's REST/HTTP/2 surface instead of WebRTC.

---

## Phase 0: Reverse Engineering — Yandex Music Fingerprint

**Goal:** Capture the exact TLS fingerprint, HTTP/2 parameters, header patterns, and timing of the real Yandex Music client.

### 0.1 TLS Fingerprint (JA3/JA4)

| Step | Action | Tool |
|------|--------|------|
| 0.1.1 | Install official Yandex Music Android app on device | Play Store |
| 0.1.2 | Capture pcap of app talking to `api.music.yandex.net` | PCAPdroid + tcpdump |
| 0.1.3 | Extract ClientHello bytes → JA3 string | `ja3` python script |
| 0.1.4 | Note: cipher suites, TLS versions, extensions order, curves, signature algs | Wireshark |
| 0.1.5 | Same for Yandex Music desktop (Electron) app | tcpdump + Wireshark |
| 0.1.6 | Verify with JA4 fingerprinting (more granular) | ja4-py |

### 0.2 HTTP/2 Framing

| Step | Action | Tool |
|------|--------|------|
| 0.2.1 | Capture HTTP/2 frames from real app | Wireshark / h2dump |
| 0.2.2 | Log SETTINGS frames (HEADER_TABLE_SIZE, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE) | Custom capture script |
| 0.2.3 | Log PING interval | Wireshark |
| 0.2.4 | Log WINDOW_UPDATE frequency | Wireshark |
| 0.2.5 | Log typical RTT and inter-packet gaps | Wireshark IO graph |

### 0.3 HTTP Headers & Body

| Step | Action | Tool |
|------|--------|------|
| 0.3.1 | Capture full request/response pairs: `/tracks`, `/playlists`, `/albums`, `/search` | mitmproxy / charles |
| 0.3.2 | Document exact header order, User-Agent, Accept, Authorization format, X-Yandex-* | MarshalX source + capture |
| 0.3.3 | Measure typical response body sizes (min/max/avg) for each endpoint | Statistical analysis |
| 0.3.4 | Document cookie/X-Token flow | MarshalX source |

### 0.4 Timing Patterns

| Step | Action | Tool |
|------|--------|------|
| 0.4.1 | Burst analysis: how many packets in a burst, pause between bursts | Wireshark + custom scripts |
| 0.4.2 | Keepalive interval: how often does real YM app send PING or new request | Long-duration pcap |
| 0.4.3 | Connection lifetime: how long does a single TLS connection live before reconnect | Long-duration pcap |

> **Deliverable:** `docs/fingerprint.md` with exact JA3 string, SETTINGS, headers template, timing stats.

---

## Phase 1: Server Core — Protocol Implementation

### 1.1 Project Structure

```
ymt/
├── cmd/
│   ├── server/          # Server entrypoint
│   │   └── main.go
│   └── client/          # Client entrypoint
│       └── main.go
├── internal/
│   ├── server/          # Server logic
│   │   ├── server.go    # TLS listener, accept loop
│   │   ├── peer.go      # Per-connection peer handler
│   │   ├── tunnel.go    # Tunnel → smux → internet forwarding
│   │   └── router.go    # HTTP routes for web UI
│   ├── client/          # Client logic
│   │   ├── client.go    # Connects to server
│   │   ├── vpn.go       # TUN device management
│   │   └── socks.go     # SOCKS5 proxy
│   ├── protocol/        # Shared protocol layer
│   │   ├── tls.go       # utls-based fingerprint imitation
│   │   ├── http2.go     # Custom HTTP/2 framer (or x/net/http2 wrapper)
│   │   ├── masquerade.go # Request/response envelope construction
│   │   ├── crypto.go    # XChaCha20-Poly1305 AEAD
│   │   └── tunnel.go    # smux multiplexing layer
│   ├── api/             # REST API for web UI
│   │   ├── auth.go      # Token auth
│   │   ├── users.go     # User CRUD
│   │   └── stats.go     # Traffic stats
│   ├── db/              # Persistence
│   │   ├── sqlite.go    # SQLite storage
│   │   └── models.go    # User, Session, Stats schemas
│   └── web/             # Web UI
│       ├── handler.go   # Serves HTML templates
│       ├── templates/   # HTML templates (Go template or htmx)
│       └── static/      # CSS/JS for web UI
├── docs/
│   ├── fingerprint.md   # Captured Yandex Music fingerprints
│   ├── architecture.md  # Architecture diagrams
│   └── protocol.md      # Wire protocol spec
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

### 1.2 TLS Listener (utls)

```
┌─────────────────────────────────────────────────────────┐
│  ymt-server                                             │
│                                                         │
│  TLS listener :443                                      │
│  ├─ utls.Config with YM fingerprints                     │
│  ├─ Accept loop → per-connection goroutine               │
│  │  ├─ TLS handshake (imitating YM client → server)      │
│  │  ├─ Downgrade check: reject non-utls fingerprint      │
│  │  └─ Create Peer handler                               │
│  └─ HTTP/2 framer on top of TLS                          │
│     ├─ Server responds with YM-like SETTINGS             │
│     ├─ PING every 45s                                    │
│     └─ Stream multiplex (each stream = masqueraded req)  │
└─────────────────────────────────────────────────────────┘
```

- Use `github.com/refraction-networking/utls` for fingerprint emulation
- Server acts as TLS **server** but emulates the server side of YM's TLS handshake
- After TLS, attach `golang.org/x/net/http2` with custom SETTINGS
- Reject connections whose ClientHello doesn't match expected fingerprint range

### 1.3 Masquerade Layer

Each tunnel packet is wrapped in a structure that looks like a Yandex Music API response:

```
HTTP/2 Response HEADERS:
  :status → 200
  content-type → application/json
  date → [RFC1123 date]
  x-content-type-options → nosniff
  ...

HTTP/2 DATA frame:
  {
    "result": {
      "tunnel_data": "<base64-encoded AEAD ciphertext>",
      "_padding": "<random padding to match expected size>"
    }
  }
```

- Real YM response has `{"result": {...}}` envelope — we reuse the same JSON shape
- `tunnel_data` field holds the actual encrypted payload
- `_padding` adjusts total body size to statistically match real YM response distribution
- On the client side, the library parses the JSON, extracts `tunnel_data`, decodes base64, decrypts AEAD

### 1.4 smux Multiplexing

- Use `github.com/xtaci/smux` (same as olcRTC uses)
- Each SOCKS5/TUN TCP connection becomes a smux stream
- Multiple smux streams share one TLS+HTTP/2 connection
- Smux streams are wrapped in the masquerade envelope before transmission

### 1.5 Encryption

- XChaCha20-Poly1305 with 24-byte nonce (random, prefixed to ciphertext)
- 32-byte key derived per-user: `HKDF-SHA256( master_key, salt("ymt-v1") || client_id )`
- Each direction has its own key (separate data/control AAD as in olcRTC)

### 1.6 Crypto Self-Check

- After generating key: encrypt a zero vector, decrypt it, compare
- On each connection: send encrypted nonce+hello, server decrypts and echoes back
- Verify AES-NI / hardware crypto available at startup

---

## Phase 2: Client Implementation

### 2.1 Client Modes

| Mode | Description | Priority |
|------|-------------|----------|
| SOCKS5 | Lightweight, no root, per-app proxy | P0 |
| TUN | Full VPN, all traffic routed through tunnel | P0 |
| Smart split | Only non-Yandex traffic through tunnel, YM traffic direct | P1 |

### 2.2 Client Architecture

```
┌──────────────────────────────────────────┐
│  ymt-client                               │
│                                           │
│  Input: config (server IP, port, key)     │
│                                           │
│  States:                                  │
│  1. Dial TCP → server:port                │
│  2. TLS handshake (utls, YM fingerprint)  │
│  3. HTTP/2 connection setup               │
│  4. Send auth stream (client_id + proof)  │
│  5. Receive OK → tunnel established       │
│  6. Start SOCKS5 :1080 or TUN :tun0       │
│  7. Each app connection → smux stream     │
│     → masquerade → AEAD → write to h2     │
│                                           │
│  Keepalive: PING every 45s                │
│  Reconnect: on failure, backoff 1-30s     │
└──────────────────────────────────────────┘
```

### 2.3 TUN Device (gvisor)

- Use `gvisor.dev/gvisor/pkg/tcpip/stack` + `water` for TUN
- Route all traffic (except server IP) through TUN
- DNS: hijack `:53` → route through tunnel
- IPv4 only for v1, IPv6 later

### 2.4 SOCKS5

- Standard SOCKS5 on `127.0.0.1:1080`
- UDP ASSOCIATE support (for DNS over tunnel)
- Auth: no-auth only (v1), username/password later

---

## Phase 3: Web Management UI

### 3.1 Frontend

| Page | Purpose |
|------|---------|
| `/login` | Admin auth |
| `/dashboard` | Live stats: active connections, total traffic, speed |
| `/users` | User list: create, delete, limit speed/bytes |
| `/users/:id` | Per-user stats, connection log |
| `/settings` | Server config: port, TLS, fingerprint overrides |

Tech: Go `html/template` + htmx + Tailwind CDN.

### 3.2 REST API (internal)

```
GET    /api/stats            → server status, active peers, throughput
GET    /api/users            → list users
POST   /api/users            → create user (generates key)
DELETE /api/users/:id        → delete user
GET    /api/users/:id/stats  → per-user traffic stats
```

Auth: Bearer token (set in server config).

### 3.3 Database

Table: `users`
- `id TEXT PRIMARY KEY` (uuid)
- `client_id TEXT UNIQUE`
- `key_hash BLOB` (SHA-256 of derived key — we never store raw key)
- `enabled INTEGER DEFAULT 1`
- `max_bytes INTEGER DEFAULT 0` (0 = unlimited)
- `created_at TEXT`
- `last_seen TEXT`

Table: `sessions`
- `id TEXT PRIMARY KEY`
- `user_id TEXT REFERENCES users(id)`
- `ip TEXT`
- `connected_at TEXT`
- `disconnected_at TEXT`
- `bytes_up INTEGER`
- `bytes_down INTEGER`

---

## Phase 4: Self-Checks & Testing

### 4.1 Unit Tests

| Suite | What it tests |
|-------|---------------|
| `crypto_test.go` | AEAD encrypt/decrypt round-trip, key derivation, replay protection |
| `masquerade_test.go` | JSON envelope construction/parsing, padding size validation |
| `tunnel_test.go` | smux stream creation, close, data transfer |
| `tls_test.go` | utls fingerprint matches expected JA3 |

### 4.2 Integration Tests

| Test | Description |
|------|-------------|
| `server → client echo` | Server + client on localhost, send data, verify decryption |
| `SOCKS5 curl` | Start client with SOCKS5, `curl --socks5` through tunnel, verify response |
| `TUN ping` | TUN mode, ping `8.8.8.8` through tunnel |
| `DPI simulation` | Run pcap capture of tunnel traffic, verify it doesn't match known VPN signatures |
| `Fingerprint verification` | Third-party JA3 checker confirms our fingerprint matches real YM |

### 4.3 Build Verification

```bash
make build      # builds server + client binaries
make cross      # cross-compiles for linux/amd64, linux/arm64, darwin/amd64, windows/amd64
make test       # runs all tests
make lint       # golangci-lint
make mobile     # gomobile bindings for Android
```

---

## Phase 5: Deployment

### 5.1 Server (VPS)

Requirements: Linux, Go 1.22+, single binary.

```bash
# Quick install
curl -fsSL https://raw.githubusercontent.com/cptn73m0/ymt/main/install.sh | bash

# Or manual
./ymt-server -config config.yaml
```

Config file:

```yaml
listen: ":443"
tls_cert: "/path/to/fullchain.pem"
tls_key: "/path/to/privkey.pem"
admin_token: "your-admin-token"
db_path: "/var/lib/ymt/users.db"
fingerprint: "ja3_ym_music"  # built-in preset
```

### 5.2 Client

Supported: Linux, macOS, Windows (CLI), Android (gomobile).

```bash
./ymt-client -server ym.myserver.com:443 -key user-key-here -mode socks5
./ymt-client -server ym.myserver.com:443 -key user-key-here -mode tun
```

---

## Milestone Summary

| Phase | Tasks | Timeline |
|-------|-------|----------|
| 0 | Reverse engineering fingerprints | 2-3 days |
| 1 | Server core (TLS, h2, smux, masquerade, crypto) | 5-7 days |
| 2 | Client (SOCKS5 + TUN) | 4-5 days |
| 3 | Web UI + REST API | 3-4 days |
| 4 | Tests + self-checks | 2-3 days |
| 5 | Deployment scripts | 1 day |
| **Total** | **First working prototype** | **~2-3 weeks** |

---

## Risk Register

| Risk | Mitigation |
|------|------------|
| Yandex changes TLS fingerprint | Configurable fingerprint preset; periodic re-capture |
| TSPU blocks all UDP-based protocols | Our protocol runs over TCP (TLS 1.3 + HTTP/2) |
| ML DPI detects masquerade via traffic analysis | Add padding, timing jitter, keepalive mimicking real YM |
| utls breaks on new Go version | Pin utls version, vendor dependencies |
| gvisor TUN not available (non-Linux) | SOCKS5 mode as fallback; `water` TUN on macOS/Windows |

---

## Appendix: Fingerprint Template (to fill after Phase 0)

```yaml
ja3: "771,4866-4867-4865-...-23,..."
ja4: "t13d..."
http2_settings:
  header_table_size: 4096
  max_concurrent_streams: 100
  initial_window_size: 65535
  max_frame_size: 16384
http2_ping_interval: 45s
headers:
  user_agent: "Yandex-Music/5.24.0 (Android 14; ru.yandex.music; Google SM-S928B)"
  accept: "application/json"
  authorization: "OAuth <token>"
  x_yandex_music_client: "Android"
  x_requested_with: "XMLHttpRequest"
timing:
  burst_size_packets: 8-12
  burst_pause_ms: 50-150
  keepalive_s: 45
```