#!/usr/bin/env bash
set -euo pipefail

echo "=== YMT Quick Install ==="

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

# Check for Go
if ! command -v go &> /dev/null; then
  echo "Go not found. Install Go 1.22+ first: https://go.dev/dl/"
  exit 1
fi

echo "Building YMT for $OS/$ARCH..."

if [ ! -d "ymt" ]; then
  git clone https://github.com/cptn73m0/ymt.git
  cd ymt
else
  cd ymt
  git pull
fi

go build -o /usr/local/bin/ymt-server ./cmd/server
go build -o /usr/local/bin/ymt-client ./cmd/client

echo ""
echo "=== Done ==="
echo "Server: /usr/local/bin/ymt-server"
echo "Client: /usr/local/bin/ymt-client"
echo ""
echo "Quick start server:"
echo "  export YMT_ADMIN_TOKEN=\$(openssl rand -hex 16)"
echo "  ymt-server -listen :443 -cert cert.pem -key key.pem -admin-token \$YMT_ADMIN_TOKEN"
echo ""
echo "Quick start client:"
echo "  ymt-client -server your.server:443 -name your.server -client-id my-phone -key <hex-key> -mode socks5"