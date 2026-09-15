package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cptn73m0/ymt/internal/protocol"
	"golang.org/x/net/http2"
)

type Server struct {
	cfg        Config
	adminToken string
	adminPass  string
	db         *UserDB
	startedAt  time.Time

	mu        sync.Mutex
	connCount int
	bytesUp   int64
	bytesDown int64
}

type Config struct {
	Listen       string
	AdminAddr    string
	AdminPass    string
	DataDir      string
	Domain       string
	TLSCert      string
	TLSKey       string
}

func main() {
	cfg := Config{}
	flag.StringVar(&cfg.Listen, "listen", ":443", "Tunnel listen address")
	flag.StringVar(&cfg.AdminAddr, "admin", "0.0.0.0:8080", "Admin UI listen address")
	flag.StringVar(&cfg.AdminPass, "admin-pass", "", "Admin UI password (auto-generated if empty)")
	flag.StringVar(&cfg.DataDir, "data", "/var/lib/ymt", "Data directory")
	flag.StringVar(&cfg.Domain, "domain", "", "Domain name")
	flag.StringVar(&cfg.TLSCert, "cert", "", "TLS cert file")
	flag.StringVar(&cfg.TLSKey, "key", "", "TLS key file")
	flag.Parse()

	os.MkdirAll(cfg.DataDir, 0700)

	if err := protocol.VerifyDecrypt(); err != nil {
		log.Fatalf("crypto: %v", err)
	}
	log.Printf("crypto OK")

	srv := &Server{
		cfg:       cfg,
		db:       openDB(filepath.Join(cfg.DataDir, "ymt.db")),
		startedAt: time.Now(),
	}

	if srv.db.GetSetting("admin_token") == "" {
		token := randomHex(32)
		pass := randomHex(8)
		srv.db.SetSetting("admin_token", token)
		srv.db.SetSetting("admin_password", pass)
		log.Println("=== FIRST RUN ===")
		log.Printf("Admin panel: http://%s/admin", cfg.AdminAddr)
		log.Printf("Login: admin / %s", pass)
		log.Printf("API token: %s", token)
		log.Println("=================")
	}
	srv.adminToken = srv.db.GetSetting("admin_token")
	srv.adminPass = srv.db.GetSetting("admin_password")
	if cfg.AdminPass != "" {
		srv.adminPass = cfg.AdminPass
		srv.db.SetSetting("admin_password", cfg.AdminPass)
	}

	// Admin web server
	adminMux := http.NewServeMux()
	srv.registerAdminRoutes(adminMux)
	adminSrv := &http.Server{Addr: cfg.AdminAddr, Handler: adminMux}
	go func() {
		log.Printf("Admin UI on http://%s/admin", cfg.AdminAddr)
		adminSrv.ListenAndServe()
	}()

	// Tunnel listener
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.Listen, err)
	}
	defer ln.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shut down")
		ln.Close()
		adminSrv.Close()
		os.Exit(0)
	}()

	log.Printf("YMT server on %s", cfg.Listen)

	for {
		conn, err := ln.Accept()
		if err != nil {
			break
		}
		go srv.handleConn(conn)
	}
}

func (s *Server) handleConn(raw net.Conn) {
	defer raw.Close()

	tlsConn, err := protocol.ServerTLSHandshake(raw, "")
	if err != nil {
		log.Printf("tls fail: %v", err)
		return
	}
	defer tlsConn.Close()

	s.mu.Lock()
	s.connCount++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.connCount--
		s.mu.Unlock()
	}()

	framer := http2.NewFramer(tlsConn, tlsConn)

	framer.WriteSettings(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 4096},
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65535},
		http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384},
	)

	// read client settings + ack
	framer.ReadFrame()
	framer.ReadFrame()
	framer.WriteSettingsAck()

	// read auth on stream 1
	var authBuf []byte
	for {
		f, err := framer.ReadFrame()
		if err != nil {
			return
		}
		if df, ok := f.(*http2.DataFrame); ok && df.StreamID == 1 {
			authBuf = append(authBuf, df.Data()...)
			if df.StreamEnded() {
				break
			}
		}
		if pp, ok := f.(*http2.PingFrame); ok && !pp.IsAck() {
			framer.WritePing(true, pp.Data)
		}
	}

	var req protocol.AuthRequest
	if err := json.Unmarshal(authBuf, &req); err != nil {
		return
	}

	user, err := s.db.GetUser(req.ClientID)
	if err != nil || !protocol.VerifyKey(req.KeyProof, user.KeyHash) {
		resp, _ := json.Marshal(protocol.AuthResponse{Status: "error", Reason: "auth fail"})
		framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, EndStream: false})
		framer.WriteData(1, true, resp)
		return
	}

	resp, _ := json.Marshal(protocol.AuthResponse{Status: "ok", Version: 1})
	framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, EndStream: false})
	framer.WriteData(1, true, resp)

	s.db.TouchUser(req.ClientID)
	log.Printf("auth: %s", req.ClientID)

	// tunnel: relay stream 3 data bidirectionally via TCP proxy
	// Simple mode: read 4-byte addr len + addr + 2-byte port from stream 3,
	// connect, then bi-directional copy
	for {
		f, err := framer.ReadFrame()
		if err != nil {
			return
		}
		if df, ok := f.(*http2.DataFrame); ok && df.StreamID == 3 {
			s.proxyData(framer, df.Data())
		}
		if pp, ok := f.(*http2.PingFrame); ok && !pp.IsAck() {
			framer.WritePing(true, pp.Data)
		}
	}
}

func (s *Server) proxyData(framer *http2.Framer, data []byte) {
	// Format: [4-byte addr len][addr bytes][2-byte port][payload...]
	if len(data) < 7 {
		return
	}
	alen := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if alen < 1 || alen > 255 || len(data) < 4+alen+2 {
		return
	}
	addr := string(data[4 : 4+alen])
	port := int(data[4+alen])<<8 | int(data[4+alen+1])
	payload := data[4+alen+2:]

	dst := fmt.Sprintf("%s:%d", addr, port)
	target, err := net.DialTimeout("tcp", dst, 10*time.Second)
	if err != nil {
		return
	}
	defer target.Close()

	if len(payload) > 0 {
		target.Write(payload)
	}

	// bi-directional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		stream3 := &h2StreamReader{framer: framer, id: 3}
		n, _ := io.CopyBuffer(target, stream3, buf)
		s.mu.Lock()
		s.bytesUp += n
		s.mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		n, _ := io.CopyBuffer(&h2StreamWriter{framer, 3}, target, buf)
		s.mu.Lock()
		s.bytesDown += n
		s.mu.Unlock()
	}()

	wg.Wait()
}

type h2StreamWriter struct {
	framer   *http2.Framer
	streamID uint32
}

func (w *h2StreamWriter) Write(b []byte) (int, error) {
	max := 16384
	written := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > max {
			chunk = chunk[:max]
		}
		end := len(b) <= max
		if err := w.framer.WriteData(w.streamID, end, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		b = b[len(chunk):]
	}
	return written, nil
}

type h2StreamReader struct {
	framer *http2.Framer
	id     uint32
}

func (r *h2StreamReader) Read(b []byte) (int, error) {
	for {
		f, err := r.framer.ReadFrame()
		if err != nil {
			return 0, err
		}
		if df, ok := f.(*http2.DataFrame); ok && df.StreamID == r.id {
			n := copy(b, df.Data())
			if len(df.Data()) > n {
				return n, io.EOF // simplified; real code needs buffer
			}
			if df.StreamEnded() {
				return n, io.EOF
			}
			return n, nil
		}
		if pp, ok := f.(*http2.PingFrame); ok && !pp.IsAck() {
			r.framer.WritePing(true, pp.Data)
		}
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}