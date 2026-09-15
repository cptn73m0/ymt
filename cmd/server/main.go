package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cptn73m0/ymt/internal/protocol"
	"github.com/cptn73m0/ymt/internal/server"
)

func main() {
	listen := flag.String("listen", ":443", "TCP listen address")
	certFile := flag.String("cert", "", "TLS certificate file")
	keyFile := flag.String("key", "", "TLS private key file")
	fingerprint := flag.String("fingerprint", "android", "Fingerprint preset")
	adminToken := flag.String("admin-token", os.Getenv("YMT_ADMIN_TOKEN"), "Admin API token")
	dbPath := flag.String("db", "/var/lib/ymt/users.db", "User database path")
	flag.Parse()

	if *adminToken == "" {
		log.Fatal("admin-token is required (set via --admin-token or YMT_ADMIN_TOKEN env)")
	}

	// Self-check: verify crypto works
	if err := protocol.VerifyDecrypt(); err != nil {
		log.Fatalf("crypto self-test failed: %v", err)
	}
	log.Printf("crypto self-test: OK")

	srv := server.New(server.Config{
		ListenAddr:    *listen,
		TLSCertFile:   *certFile,
		TLSKeyFile:    *keyFile,
		Fingerprint:   *fingerprint,
		AdminToken:    *adminToken,
		UserDBPath:    *dbPath,
	})

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Printf("shutting down...")
		srv.Stop()
	}()

	if err := srv.Start(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}