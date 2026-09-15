package server

import (
	"testing"
)

func TestHashKeyForStorage(t *testing.T) {
	key := []byte("test-master-key-32-bytes-long!")
	hash := HashKeyForStorage(key)
	if len(hash) != 32 {
		t.Fatalf("hash len: got %d, want 32", len(hash))
	}
}

func TestGenerateClientID(t *testing.T) {
	id1 := GenerateClientID("alice")
	id2 := GenerateClientID("alice")
	if id1 == id2 {
		t.Error("two ids should differ (time-based)")
	}
}