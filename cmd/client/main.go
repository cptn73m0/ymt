package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cptn73m0/ymt/internal/protocol"
	"golang.org/x/net/http2"
)

func main() {
	server := flag.String("server", "", "Server address (host:port)")
	clientID := flag.String("client-id", "", "Client identifier")
	keyHex := flag.String("key", "", "Master key in hex (32 bytes = 64 hex chars)")
	mode := flag.String("mode", "socks5", "Proxy mode: socks5 or tun")
	socksPort := flag.Int("socks-port", 1080, "SOCKS5 listen port")
	flag.Parse()

	if *server == "" || *keyHex == "" || *clientID == "" {
		log.Fatal("--server, --client-id and --key are required")
	}

	if err := protocol.VerifyDecrypt(); err != nil {
		log.Fatalf("crypto: %v", err)
	}

	key, err := hex.DecodeString(*keyHex)
	if err != nil {
		log.Fatalf("key hex: %v", err)
	}

	parts := strings.Split(*server, ":")
	host := parts[0]
	port := "443"
	if len(parts) > 1 {
		port = parts[1]
	}

	// Connect loop with reconnect
	for {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 15*time.Second)
		if err != nil {
			log.Printf("dial: %v, retry in 5s", err)
			time.Sleep(5 * time.Second)
			continue
		}

		tlsConn, err := protocol.ClientTLSHandshake(conn, host, "android")
		if err != nil {
			log.Printf("tls: %v", err)
			conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		err = runSession(tlsConn, *clientID, key, *mode, *socksPort)
		tlsConn.Close()
		if err != nil {
			log.Printf("session: %v, reconnect", err)
		}
		time.Sleep(3 * time.Second)
	}
}

func runSession(tlsConn net.Conn, clientID string, key []byte, mode string, socksPort int) error {
	framer := http2.NewFramer(tlsConn, tlsConn)

	// Read server SETTINGS
	f, err := framer.ReadFrame()
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
	}
	if _, ok := f.(*http2.SettingsFrame); !ok {
		return fmt.Errorf("expected settings, got %T", f)
	}

	// Client SETTINGS
	framer.WriteSettings(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 4096},
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65535},
		http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384},
	)
	framer.ReadFrame() // settings ack
	framer.WriteSettingsAck()

	// Auth
	nonce := make([]byte, 32)
	rand.Read(nonce)
	proof := protocol.GenerateKeyProof(key, nonce)
	authReq := protocol.AuthRequest{
		ClientID: clientID,
		KeyProof: base64.StdEncoding.EncodeToString(proof),
		Nonce:    base64.StdEncoding.EncodeToString(nonce),
	}
	authData, _ := json.Marshal(authReq)

	framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, EndStream: false})
	framer.WriteData(1, true, authData)

	// Read auth response
	f, err = framer.ReadFrame()
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	if df, ok := f.(*http2.DataFrame); ok {
		var resp protocol.AuthResponse
		json.Unmarshal(df.Data(), &resp)
		if resp.Status != "ok" {
			return fmt.Errorf("auth denied: %s", resp.Reason)
		}
		log.Printf("authenticated as %s", clientID)
	}

	// Tunnel mode
	switch mode {
	case "socks5":
		return runSOCKS5(framer, socksPort)
	case "tun":
		return fmt.Errorf("TUN mode not implemented")
	}
	return nil
}

func runSOCKS5(framer *http2.Framer, port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Printf("SOCKS5 proxy on 127.0.0.1:%d", port)

	for {
		client, err := listener.Accept()
		if err != nil {
			return err
		}
		go handleSOCKS5(client, framer)
	}
}

func handleSOCKS5(client net.Conn, framer *http2.Framer) {
	defer client.Close()

	buf := make([]byte, 256)
	if _, err := client.Read(buf); err != nil {
		return
	}
	client.Write([]byte{0x05, 0x00})

	if _, err := client.Read(buf); err != nil {
		return
	}
	if buf[1] != 0x01 { // Only CONNECT
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// Extract destination
	var dstAddr []byte
	var dstPort []byte
	switch buf[3] {
	case 0x01:
		dstAddr = buf[4:8]
		dstPort = buf[8:10]
	case 0x03:
		length := buf[4]
		dstAddr = buf[5 : 5+length]
		dstPort = buf[5+length : 5+length+2]
	default:
		return
	}

	// Build proxy request for server: [4-byte addr len][addr][2-byte port]
	var proxyReq []byte
	alen := make([]byte, 4)
	alen[0] = byte(len(dstAddr) >> 24)
	alen[1] = byte(len(dstAddr) >> 16)
	alen[2] = byte(len(dstAddr) >> 8)
	alen[3] = byte(len(dstAddr))
	proxyReq = append(proxyReq, alen...)
	proxyReq = append(proxyReq, dstAddr...)
	proxyReq = append(proxyReq, dstPort...)

	// Send on stream 3
	if err := framer.WriteData(3, false, proxyReq); err != nil {
		return
	}

	// SOCKS5 response: granted
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Bidirectional relay
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(client, &h2StreamReader3{framer: framer})
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, err := client.Read(buf)
			if err != nil {
				return
			}
			framer.WriteData(3, false, buf[:n])
		}
	}()
	wg.Wait()
}

type h2StreamReader3 struct {
	framer *http2.Framer
}

func (r *h2StreamReader3) Read(b []byte) (int, error) {
	for {
		f, err := r.framer.ReadFrame()
		if err != nil {
			return 0, err
		}
		if df, ok := f.(*http2.DataFrame); ok && df.StreamID == 3 {
			n := copy(b, df.Data())
			if len(df.Data()) > n {
				return n, io.EOF
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

func base64Encode(data []byte) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var result strings.Builder
	for _, b := range data {
		result.WriteByte(chars[b%64])
	}
	return result.String()
}