package server

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/cptn73m0/ymt/internal/protocol"
	"github.com/xtaci/smux"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type Config struct {
	ListenAddr    string
	TLSCertFile   string
	TLSKeyFile    string
	Fingerprint   string
	AdminToken    string
	UserDBPath    string
}

type Server struct {
	cfg        Config
	ln         net.Listener
	http2      *http2.Framer
	peers      sync.Map
	db         *userDB
	stopCh     chan struct{}
	adminToken string
}

func New(cfg Config) *Server {
	return &Server{
		cfg:        cfg,
		stopCh:     make(chan struct{}),
		adminToken: cfg.AdminToken,
	}
}

func (s *Server) AdminToken() string { return s.adminToken }

func (s *Server) Start() error {
	var err error
	s.ln, err = net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	s.db, err = openUserDB(s.cfg.UserDBPath)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	s.db.migrate()

	log.Printf("YMT server listening on %s", s.cfg.ListenAddr)

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return nil
			default:
				log.Printf("accept error: %v", err)
				continue
			}
		}
		go s.handleConn(conn)
	}
}

func (s *Server) Stop() {
	close(s.stopCh)
	s.ln.Close()
}

func (s *Server) handleConn(rawConn net.Conn) {
	defer rawConn.Close()

	// Step 1: TLS handshake with Yandex Music fingerprint emulation
	tlsConn, err := protocol.ServerTLSHandshake(rawConn, s.cfg.Fingerprint)
	if err != nil {
		log.Printf("tls handshake failed: %v", err)
		return
	}
	defer tlsConn.Close()

	// Step 2: HTTP/2 framer setup
	framer := http2.NewFramer(tlsConn, tlsConn)
	
	// Send server SETTINGS mimicking Yandex Music
	settings := []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 4096},
		{ID: http2.SettingMaxConcurrentStreams, Val: 100},
		{ID: http2.SettingInitialWindowSize, Val: 65535},
		{ID: http2.SettingMaxFrameSize, Val: 16384},
	}
	if err := framer.WriteSettings(settings...); err != nil {
		log.Printf("write settings: %v", err)
		return
	}

	// Expect client SETTINGS
	framer.ReadFrame() // settings
	framer.ReadFrame() // settings ack

	// Send SETTINGS ACK
	framer.WriteSettingsAck()

	// Step 3: Auth handshake — read client's auth stream
	streamCh := make(chan *smux.Session, 1)
	go s.readStreams(framer, streamCh)

	select {
	case session := <-streamCh:
		if session == nil {
			return
		}
		s.handleSession(session)
	case <-time.After(30 * time.Second):
		log.Printf("auth timeout")
	}
}

func (s *Server) readStreams(framer *http2.Framer, resultCh chan<- *smux.Session) {
	var buf []byte
	var session *smux.Session

	for {
		f, err := framer.ReadFrame()
		if err != nil {
			log.Printf("read frame: %v", err)
			resultCh <- nil
			return
		}

		switch f := f.(type) {
		case *http2.HeadersFrame:
			// End of headers, possibly start of data
		case *http2.DataFrame:
			buf = append(buf, f.Data()...)
			if f.StreamEnded() {
				session = s.handleAuthMessage(buf)
				resultCh <- session
				return
			}
		case *http2.PingFrame:
			handlePing(framer, f)
		case *http2.RSTStreamFrame:
			log.Printf("stream %d reset", f.StreamID)
		case *http2.GoAwayFrame:
			log.Printf("goaway: %v", f.ErrCode)
			resultCh <- nil
			return
		}
	}
}

func handlePing(framer *http2.Framer, f *http2.PingFrame) {
	if !f.IsAck() {
		framer.WritePing(true, f.Data())
	}
}

func (s *Server) handleAuthMessage(data []byte) *smux.Session {
	var authReq protocol.AuthRequest
	if err := json.Unmarshal(data, &authReq); err != nil {
		log.Printf("bad auth json: %v", err)
		return nil
	}

	user, err := s.db.getUserByClientID(authReq.ClientID)
	if err != nil {
		log.Printf("user not found: %s", authReq.ClientID)
		return nil
	}

	if !protocol.VerifyKey(authReq.KeyProof, user.KeyHash) {
		log.Printf("auth failed for %s", authReq.ClientID)
		return nil
	}

	// Create smux session on top of the h2 stream
	// Actually: smux runs on top of the HTTP/2 DATA frames
	// For MVP: use a raw stream within h2
	conn := &h2StreamConn{framer: s.framerForSession(), streamID: 3}
	session, err := smux.Server(conn, &smux.Config{
		Version:           2,
		KeepAliveInterval: 30 * time.Second,
		KeepAliveTimeout:  10 * time.Second,
	})
	if err != nil {
		log.Printf("smux server: %v", err)
		return nil
	}

	log.Printf("user authenticated: %s", authReq.ClientID)
	return session
}

func (s *Server) handleSession(session *smux.Session) {
	defer session.Close()

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			log.Printf("accept stream: %v", err)
			return
		}
		go s.proxyStream(stream)
	}
}

func (s *Server) proxyStream(stream *smux.Stream) {
	defer stream.Close()

	// Read SOCKS5-like destination from stream
	// For v1: simple TCP connect proxy
	var dst [4]byte
	if _, err := io.ReadFull(stream, dst[:]); err != nil {
		return
	}

	// Connect to destination
	target, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", net.IP(dst[:]).String(), 0), 10*time.Second)
	if err != nil {
		return
	}
	defer target.Close()

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { io.Copy(target, stream); wg.Done() }()
	go func() { io.Copy(stream, target); wg.Done() }()
	wg.Wait()
}

// For the MVP, every connection gets its own framer for simplicity.
// In production, multiplex sessions over one h2 connection.
func (s *Server) framerForSession() *http2.Framer {
	return nil // placeholder — will be refactored
}

// h2StreamConn implements net.Conn over an HTTP/2 stream
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
		if pp, ok := f.(*http2.PingFrame); ok {
			handlePing(c.framer, pp)
		}
	}
}

func (c *h2StreamConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	maxFrameSize := 16384
	written := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxFrameSize {
			chunk = chunk[:maxFrameSize]
		}
		endStream := len(b) <= maxFrameSize
		if err := c.framer.WriteData(c.streamID, endStream, chunk); err != nil {
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

func (c *h2StreamConn) LocalAddr() net.Addr                { return nil }
func (c *h2StreamConn) RemoteAddr() net.Addr               { return nil }
func (c *h2StreamConn) SetDeadline(t time.Time) error       { return nil }
func (c *h2StreamConn) SetReadDeadline(t time.Time) error   { return nil }
func (c *h2StreamConn) SetWriteDeadline(t time.Time) error  { return nil }