.PHONY: build build-server build-client test clean

build: build-server build-client

build-server:
	go build -o bin/ymt-server ./cmd/server

build-client:
	go build -o bin/ymt-client ./cmd/client

test:
	go test ./...

lint:
	golangci-lint run

clean:
	rm -rf bin/ tmp/

cross: build-server build-client
	GOOS=linux GOARCH=amd64 go build -o bin/ymt-server-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=arm64 go build -o bin/ymt-server-linux-arm64 ./cmd/server
	GOOS=darwin GOARCH=amd64 go build -o bin/ymt-client-darwin-amd64 ./cmd/client
	GOOS=windows GOARCH=amd64 go build -o bin/ymt-client-windows-amd64 ./cmd/client