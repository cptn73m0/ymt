package protocol

import (
	"testing"
)

func TestVerifyDecrypt(t *testing.T) {
	if err := VerifyDecrypt(); err != nil {
		t.Fatalf("VerifyDecrypt failed: %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	key := &Key{}
	for i := 0; i < 32; i++ {
		key.Bytes[i] = byte(i)
	}

	original := []byte("Hello, YMT tunnel!")
	encrypted, err := Encrypt(key, original)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decrypted, err := Decrypt(key, encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if string(decrypted) != string(original) {
		t.Fatalf("round trip: got %q, want %q", decrypted, original)
	}
}

func TestDeriveKeys(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := 0; i < 32; i++ {
		masterKey[i] = byte(i)
	}

	km, err := DeriveKeys(masterKey, "test-client")
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}

	if km.ServerWrite.Bytes == km.ServerRead.Bytes {
		t.Error("server write == server read — keys should differ")
	}
	if km.ClientWrite.Bytes == km.ClientRead.Bytes {
		t.Error("client write == client read — keys should differ")
	}
	if km.ServerWrite.Bytes == km.ClientWrite.Bytes {
		t.Error("server write == client write — keys should differ")
	}
}

func TestKeyProof(t *testing.T) {
	key := make([]byte, 32)
	nonce := []byte("test-nonce-12345678")

	proof := GenerateKeyProof(key, nonce)
	if len(proof) != 32 {
		t.Fatalf("proof length: got %d, want 32", len(proof))
	}
}

func TestMasquerade(t *testing.T) {
	payload := []byte("encrypted tunnel data here")
	wrapped, err := MasqueradePayload(payload)
	if err != nil {
		t.Fatalf("masquerade: %v", err)
	}

	unwrapped, err := UnmasqueradePayload(wrapped)
	if err != nil {
		t.Fatalf("unmasquerade: %v", err)
	}

	if string(unwrapped) != string(payload) {
		t.Fatalf("masquerade round trip: got %q, want %q", unwrapped, payload)
	}
}