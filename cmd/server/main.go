package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cptn73m0/ymt/internal/protocol"
	"github.com/xtaci/smux"
	"golang.org/x/net/http2"
)

type Server struct {
	cfg        Config
	adminToken string
	adminPass  string
	db         *UserDB
	startedAt  time.Time

	// stats
	mu         sync.Mutex
	connCount  int
	bytesUp    int64
	bytesDown  int64
}

type Config struct {
	Listen    string
	DataDir   string
	Domain    string
	LetsEncrypt bool
	TLSCert   string
	TLSKey    string
}

func main() {
	cfg := Config{}
	flag.StringVar(&cfg.Listen, "listen", ":443", "Listen address")
	flag.StringVar(&cfg.DataDir, "data", "/var/lib/ymt", "Data directory")
	flag.StringVar(&cfg.Domain, "domain", "", "Domain for auto TLS")
	flag.BoolVar(&cfg.LetsEncrypt, "auto-tls", false, "Auto Let's Encrypt")
	flag.StringVar(&cfg.TLSCert, "cert", "", "TLS cert file")
	flag.StringVar(&cfg.TLSKey, "key", "", "TLS key file")
	flag.Parse()

	os.MkdirAll(cfg.DataDir, 0700)

	if err := protocol.VerifyDecrypt(); err != nil {
		log.Fatalf("crypto self-test: %v", err)
	}
	log.Printf("crypto self-test OK")

	srv := &Server{
		cfg:       cfg,
		db:       openDB(filepath.Join(cfg.DataDir, "ymt.db")),
		startedAt: time.Now(),
	}

	// First-run: generate admin credentials
	if srv.db.GetSetting("admin_token") == "" {
		token := randomHex(32)
		pass := randomHex(8)
		srv.db.SetSetting("admin_token", token)
		srv.db.SetSetting("admin_password", pass)
		log.Printf("=== FIRST RUN ===")
		log.Printf("Admin panel: http://localhost:8080/admin (or via tunnel)")
		log.Printf("Login: admin / %s", pass)
		log.Printf("API token: %s", token)
		log.Printf("=================")
	}
	srv.adminToken = srv.db.GetSetting("admin_token")
	srv.adminPass = srv.db.GetSetting("admin_password")

	// Start tunnel listener
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.Listen, err)
	}
	defer ln.Close()

	// HTTP admin server (internal)
	adminMux := http.NewServeMux()
	srv.registerAdminRoutes(adminMux)
	adminSrv := &http.Server{Addr: "127.0.0.1:8080", Handler: adminMux}
	go adminSrv.ListenAndServe()

	// Main accept loop
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Printf("shutting down...")
		ln.Close()
		adminSrv.Close()
		os.Exit(0)
	}()

	log.Printf("YMT server listening on %s", cfg.Listen)

	for {
		conn, err := ln.Accept()
		if err != nil {
			break
		}
		go srv.handleConn(conn)
	}
}

func (s *Server) handleConn(rawConn net.Conn) {
	defer rawConn.Close()

	tlsConn, err := protocol.ServerTLSHandshake(rawConn, "")
	if err != nil {
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

	framer.ReadFrame() // client settings
	framer.ReadFrame() // settings ack
	framer.WriteSettingsAck()

	// Auth
	var authData []byte
	for {
		f, err := framer.ReadFrame()
		if err != nil {
			return
		}
		if df, ok := f.(*http2.DataFrame); ok && df.StreamID == 1 {
			authData = append(authData, df.Data()...)
			if df.StreamEnded() {
				break
			}
		}
		if pp, ok := f.(*http2.PingFrame); ok && !pp.IsAck() {
			framer.WritePing(true, pp.Data())
		}
	}

	var req protocol.AuthRequest
	if err := json.Unmarshal(authData, &req); err != nil {
		return
	}

	user, err := s.db.GetUser(req.ClientID)
	if err != nil {
		// Auth failed response
		resp, _ := json.Marshal(protocol.AuthResponse{Status: "error", Reason: "invalid credentials"})
		framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, EndStream: false})
		framer.WriteData(1, true, resp)
		return
	}

	if !protocol.VerifyKey(req.KeyProof, user.KeyHash) {
		resp, _ := json.Marshal(protocol.AuthResponse{Status: "error", Reason: "auth failed"})
		framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, EndStream: false})
		framer.WriteData(1, true, resp)
		return
	}

	resp, _ := json.Marshal(protocol.AuthResponse{Status: "ok", Version: 1})
	framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, EndStream: false})
	framer.WriteData(1, true, resp)

	// smux on stream 3
	sc := &h2StreamConn{framer: framer, streamID: 3}
	session, err := smux.Server(sc, smux.DefaultConfig())
	if err != nil {
		return
	}
	defer session.Close()

	s.db.TouchUser(req.ClientID)

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}
		go s.proxyStream(stream)
	}
}

func (s *Server) proxyStream(stream *smux.Stream) {
	defer stream.Close()

	// Read 4-byte addr len + addr + 2-byte port
	var addrLen [4]byte
	if _, err := stream.Read(addrLen[:]); err != nil {
		return
	}
	alen := int(addrLen[0])<<24 | int(addrLen[1])<<16 | int(addrLen[2])<<8 | int(addrLen[3])
	if alen > 256 {
		return
	}
	addr := make([]byte, alen)
	if _, err := stream.Read(addr); err != nil {
		return
	}
	var port [2]byte
	if _, err := stream.Read(port[:]); err != nil {
		return
	}
	dst := fmt.Sprintf("%s:%d", string(addr), int(port[0])<<8|int(port[1]))

	target, err := net.DialTimeout("tcp", dst, 10*time.Second)
	if err != nil {
		return
	}
	defer target.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		n, _ := io.Copy(target, stream)
		s.mu.Lock()
		s.bytesDown += n
		s.mu.Unlock()
		wg.Done()
	}()
	go func() {
		n, _ := io.Copy(stream, target)
		s.mu.Lock()
		s.bytesUp += n
		s.mu.Unlock()
		wg.Done()
	}()
	wg.Wait()
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// h2StreamConn is a net.Conn over HTTP/2 data frames
type h2StreamConn struct {
	framer   *http2.Framer
	streamID uint32
	rbuf     []byte
	rmu      sync.Mutex
	wmu      sync.Mutex
}

func (c *h2StreamConn) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.rbuf) > 0 {
		n := copy(b, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	for {
		f, err := c.framer.ReadFrame()
		if err != nil {
			return 0, err
		}
		if df, ok := f.(*http2.DataFrame); ok && df.StreamID == c.streamID {
			n := copy(b, df.Data())
			if len(df.Data()) > n {
				c.rbuf = append(c.rbuf, df.Data()[n:]...)
			}
			if df.StreamEnded() {
				return n, io.EOF
			}
			return n, nil
		}
		if pp, ok := f.(*http2.PingFrame); ok && !pp.IsAck() {
			c.framer.WritePing(true, pp.Data())
		}
	}
}

func (c *h2StreamConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	maxSize := 16384
	written := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxSize {
			chunk = chunk[:maxSize]
		}
		end := len(b) <= maxSize
		if err := c.framer.WriteData(c.streamID, end, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		b = b[len(chunk):]
	}
	return written, nil
}

func (c *h2StreamConn) Close() error {
	return c.framer.WriteData(c.streamID, true, nil)
}
func (c *h2StreamConn) LocalAddr() net.Addr              { return nil }
func (c *h2StreamConn) RemoteAddr() net.Addr             { return nil }
func (c *h2StreamConn) SetDeadline(t time.Time) error    { return nil }
func (c *h2StreamConn) SetReadDeadline(t time.Time) error { return nil }
func (c *h2StreamConn) SetWriteDeadline(t time.Time) error { return nil }