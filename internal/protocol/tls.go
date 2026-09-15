package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	ProtocolVersion = 1
	KeySize         = 32
	NonceSize       = 24
	SaltCTX         = "ymt-v1"
)

// AuthRequest sent by client after TLS connection
type AuthRequest struct {
	ClientID string `json:"client_id"`
	KeyProof string `json:"key_proof"` // HMAC-SHA256(nonce, key)
	Nonce    string `json:"nonce"`     // base64 random
}

type AuthResponse struct {
	Status string `json:"status"` // "ok" or "error"
	Reason string `json:"reason,omitempty"`
	Version int    `json:"version"`
}

// MasqueradeEnvelope wraps tunnel data inside Yandex Music-like JSON
type MasqueradeEnvelope struct {
	Result struct {
		TunnelData string `json:"tunnel_data"` // base64 AEAD ciphertext
		Padding    string `json:"_padding"`
	} `json:"result"`
}

// KeyMaterial holds per-user cryptographic keys
type KeyMaterial struct {
	ServerWrite Key `json:"-"`
	ServerRead  Key `json:"-"`
	ClientWrite Key `json:"-"`
	ClientRead  Key `json:"-"`
}

type Key struct {
	Bytes [32]byte
}

// DefaultFingerprint is a preset mimicking Yandex Music Android
func DefaultFingerprint() *utls.ClientHelloID {
	return &utls.HelloAndroid_11_Chrome_96
	// Will be customized after Phase 0 reverse engineering
}

// ServerTLSHandshake performs TLS handshake as server, emulating YM server fingerprint
func ServerTLSHandshake(conn net.Conn, fingerprint string) (*utls.UConn, error) {
	tcpConn := conn.(*net.TCPConn)
	if tcpConn != nil {
		tcpConn.SetNoDelay(true)
	}

	// Use default Android Chrome fingerprint as baseline
	// After Phase 0, this will be customized with real YM fingerprint
	config := &utls.Config{
		Certificates: []utls.Certificate{
			// In production, load from tls_cert/tls_key files
		},
		PreferServerCipherSuites: true,
	}

	uconn := utls.Server(conn, config)

	if err := uconn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	return uconn, nil
}

// ClientTLSHandshake connects to server with YM-like TLS fingerprint
func ClientTLSHandshake(conn net.Conn, serverName string, fingerprint string) (*utls.UConn, error) {
	tcpConn := conn.(*net.TCPConn)
	if tcpConn != nil {
		tcpConn.SetNoDelay(true)
	}

	helloID := DefaultFingerprint()

	config := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: false,
	}

	uconn := utls.UClient(conn, config, *helloID)

	if err := uconn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	return uconn, nil
}

// DeriveKeys generates per-direction keys using HKDF
func DeriveKeys(masterKey []byte, clientID string) (*KeyMaterial, error) {
	if len(masterKey) != KeySize {
		return nil, errors.New("master key must be 32 bytes")
	}

	km := &KeyMaterial{}
	salt := []byte(SaltCTX)

	for _, dir := range []struct {
		info []byte
		dst  *Key
	}{
		{[]byte("server-write"), &km.ServerWrite},
		{[]byte("server-read"), &km.ServerRead},
		{[]byte("client-write"), &km.ClientWrite},
		{[]byte("client-read"), &km.ClientRead},
	} {
		kdf := hkdf.New(sha256.New, masterKey, salt, dir.info)
		if _, err := io.ReadFull(kdf, dir.dst.Bytes[:]); err != nil {
			return nil, fmt.Errorf("hkdf %s: %w", dir.info, err)
		}
	}

	return km, nil
}

// Encrypt encrypts plaintext with XChaCha20-Poly1305 AEAD
func Encrypt(key *Key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key.Bytes[:])
	if err != nil {
		return nil, fmt.Errorf("new xchacha20: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts XChaCha20-Poly1305 AEAD ciphertext
func Decrypt(key *Key, data []byte) ([]byte, error) {
	if len(data) < NonceSize {
		return nil, errors.New("ciphertext too short")
	}

	aead, err := chacha20poly1305.NewX(key.Bytes[:])
	if err != nil {
		return nil, fmt.Errorf("new xchacha20: %w", err)
	}

	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// GenerateKeyProof creates HMAC proof of key possession
func GenerateKeyProof(key []byte, nonce []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	return mac.Sum(nil)
}

// VerifyKey checks that the HMAC proof matches stored key hash
func VerifyKey(proof string, expectedHash []byte) bool {
	proofBytes, err := base64.StdEncoding.DecodeString(proof)
	if err != nil {
		return false
	}

	// hash the proof and compare with stored hash
	hash := sha256.Sum256(proofBytes)
	return hmac.Equal(hash[:], expectedHash)
}

// VerifyDecrypt is a self-test: encrypt + decrypt a known value
func VerifyDecrypt() error {
	key := &Key{}
	for i := range key.Bytes {
		key.Bytes[i] = byte(i)
	}

	original := []byte("YMT crypto self-test vector")
	encrypted, err := Encrypt(key, original)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	decrypted, err := Decrypt(key, encrypted)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	if string(decrypted) != string(original) {
		return errors.New("crypto round-trip mismatch")
	}

	return nil
}

// WriteVarLen writes a variable-length length-prefixed message
func WriteVarLen(w io.Writer, data []byte) error {
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// ReadVarLen reads a variable-length length-prefixed message
func ReadVarLen(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf)
	if length > 10*1024*1024 { // 10MB max
		return nil, errors.New("message too large")
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}

// MasqueradePayload wraps raw tunnel bytes in YM-like JSON envelope
func MasqueradePayload(ciphertext []byte) ([]byte, error) {
	env := MasqueradeEnvelope{}
	env.Result.TunnelData = base64.StdEncoding.EncodeToString(ciphertext)

	// Add padding to reach typical YM response size distribution
	// YM responses are typically 512-2048 bytes
	paddingLen := int(ciphertext[0] % 256) // deterministic from data
	pad := make([]byte, paddingLen)
	rand.Read(pad)
	env.Result.Padding = base64.StdEncoding.EncodeToString(pad)

	return json.Marshal(env)
}

// UnmasqueradePayload extracts raw ciphertext from YM-like JSON envelope
func UnmasqueradePayload(body []byte) ([]byte, error) {
	var env MasqueradeEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	data, err := base64.StdEncoding.DecodeString(env.Result.TunnelData)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}

	return data, nil
}

// randomized import guard
var _ = sync.Mutex{}
var _ = time.Now