package main

import (
	"encoding/hex"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cptn73m0/ymt/internal/client"
	"github.com/cptn73m0/ymt/internal/protocol"
)

func main() {
	server := flag.String("server", "", "Server address (host:port)")
	name := flag.String("name", "default", "Server SNI (for TLS)")
	clientID := flag.String("client-id", "", "Client identifier")
	keyHex := flag.String("key", "", "Master key in hex (32 bytes = 64 hex chars)")
	mode := flag.String("mode", "socks5", "Proxy mode: socks5 or tun")
	socksPort := flag.Int("socks-port", 1080, "SOCKS5 listen port")
	flag.Parse()

	if *server == "" || *keyHex == "" {
		log.Fatal("--server and --key are required")
	}

	if *clientID == "" {
		*clientID = strings.ToLower(*name)
	}

	if err := protocol.VerifyDecrypt(); err != nil {
		log.Fatalf("crypto self-test failed: %v", err)
	}

	key, err := hex.DecodeString(*keyHex)
	if err != nil {
		log.Fatalf("invalid key hex: %v", err)
	}

	runMode := client.ModeSOCKS5
	if *mode == "tun" {
		runMode = client.ModeTUN
	}

	c := client.New(client.Config{
		ServerAddr: *server,
		ServerName: *name,
		ClientID:   *clientID,
		MasterKey:  key,
		Mode:       runMode,
		SOCKS5Port: *socksPort,
	})

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Printf("shutting down...")
		c.Stop()
	}()

	if err := c.Start(); err != nil {
		log.Fatalf("client error: %v", err)
	}
}