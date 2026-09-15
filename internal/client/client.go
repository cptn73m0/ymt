package client

import (
	"crypto/rand"
	"encoding/base64"
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
)

type Mode int

const (
	ModeSOCKS5 Mode = iota
	ModeTUN
)

type Config struct {
	ServerAddr string
	ServerName string
	ClientID   string
	MasterKey  []byte
	Mode       Mode
	SOCKS5Port int
	TUNName    string
}

type Client struct {
	cfg     Config
	conn    net.Conn
	framer  *http2.Framer
	session *smux.Session
	stopCh  chan struct{}
}

func New(cfg Config) *Client {
	return &Client{
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}
}

func (c *Client) Start() error {
	conn, err := net.DialTimeout("tcp", c.cfg.ServerAddr, 15*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	c.conn = conn

	tlsConn, err := protocol.ClientTLSHandshake(conn, c.cfg.ServerName, "android")
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	c.conn = tlsConn

	framer := http2.NewFramer(tlsConn, tlsConn)

	f, err := framer.ReadFrame()
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
	}
	if _, ok := f.(*http2.SettingsFrame); !ok {
		return fmt.Errorf("expected settings, got %T", f)
	}

	settings := []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 4096},
		{ID: http2.SettingMaxConcurrentStreams, Val: 100},
		{ID: http2.SettingInitialWindowSize, Val: 65535},
		{ID: http2.SettingMaxFrameSize, Val: 16384},
	}
	if err := framer.WriteSettings(settings...); err != nil {
		return fmt.Errorf("write settings: %w", err)
	}

	framer.ReadFrame()
	framer.WriteSettingsAck()

	c.framer = framer

	nonce := make([]byte, 32)
	rand.Read(nonce)
	proof := protocol.GenerateKeyProof(c.cfg.MasterKey, nonce)

	authReq := protocol.AuthRequest{
		ClientID: c.cfg.ClientID,
		KeyProof: base64.StdEncoding.EncodeToString(proof),
		Nonce:    base64.StdEncoding.EncodeToString(nonce),
	}

	authData, _ := json.Marshal(authReq)

	framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:   1,
		EndHeaders: true,
		EndStream:  false,
	})
	framer.WriteData(1, true, authData)

	f, err = framer.ReadFrame()
	if err != nil {
		return fmt.Errorf("auth response: %w", err)
	}

	if df, ok := f.(*http2.DataFrame); ok {
		var resp protocol.AuthResponse
		if err := json.Unmarshal(df.Data(), &resp); err != nil {
			return fmt.Errorf("auth json: %w", err)
		}
		if resp.Status != "ok" {
			return fmt.Errorf("auth denied: %s", resp.Reason)
		}
		log.Printf("authenticated as %s (v%d)", c.cfg.ClientID, resp.Version)
	}

	streamConn := &h2StreamConn{framer: framer, streamID: 3}
	c.session, err = smux.Client(streamConn, &smux.Config{
		Version:           2,
		KeepAliveInterval: 30 * time.Second,
		KeepAliveTimeout:  10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("smux: %w", err)
	}

	switch c.cfg.Mode {
	case ModeSOCKS5:
		return c.runSOCKS5()
	case ModeTUN:
		return c.runTUN()
	}
	return nil
}

func (c *Client) Stop() {
	close(c.stopCh)
	if c.session != nil {
		c.session.Close()
	}
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *Client) runSOCKS5() error {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", c.cfg.SOCKS5Port))
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy on 127.0.0.1:%d", c.cfg.SOCKS5Port)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			select {
			case <-c.stopCh:
				return nil
			default:
				log.Printf("socks5 accept: %v", err)
				continue
			}
		}
		go c.handleSOCKS5(clientConn)
	}
}

func (c *Client) handleSOCKS5(clientConn net.Conn) {
	defer clientConn.Close()

	buf := make([]byte, 256)
	if _, err := clientConn.Read(buf); err != nil {
		return
	}
	clientConn.Write([]byte{0x05, 0x00})

	if _, err := clientConn.Read(buf); err != nil {
		return
	}

	if buf[1] != 0x01 {
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	dstAddr, dstPort := extractDest(buf)

	stream, err := c.session.OpenStream()
	if err != nil {
		log.Printf("open stream: %v", err)
		return
	}
	defer stream.Close()

	stream.Write(dstAddr)
	stream.Write(dstPort)

	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { io.Copy(stream, clientConn); wg.Done() }()
	go func() { io.Copy(clientConn, stream); wg.Done() }()
	wg.Wait()
}

func (c *Client) runTUN() error {
	log.Printf("TUN mode not yet implemented, falling back to SOCKS5")
	return c.runSOCKS5()
}

func extractDest(buf []byte) ([]byte, []byte) {
	switch buf[3] {
	case 0x01:
		return buf[4:8], buf[8:10]
	case 0x03:
		length := buf[4]
		return buf[5 : 5+length], buf[5+length : 5+length+2]
	default:
		return []byte{0, 0, 0, 0}, []byte{0, 0}
	}
}

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

func (c *h2StreamConn) LocalAddr() net.Addr             { return nil }
func (c *h2StreamConn) RemoteAddr() net.Addr            { return nil }
func (c *h2StreamConn) SetDeadline(t time.Time) error    { return nil }
func (c *h2StreamConn) SetReadDeadline(t time.Time) error { return nil }
func (c *h2StreamConn) SetWriteDeadline(t time.Time) error { return nil }