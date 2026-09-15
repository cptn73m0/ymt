FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /ymt-server ./cmd/server

FROM alpine:3.19
RUN apk add --no-cache ca-certificates sqlite-libs
COPY --from=builder /ymt-server /usr/local/bin/ymt-server
EXPOSE 443
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/ymt-server"]
CMD ["-listen", ":443", "-data", "/data"]