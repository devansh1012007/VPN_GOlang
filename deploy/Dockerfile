# vpnd container — needs NET_ADMIN for netlink/iptables (ADR-006).
# Build: docker build -t vpnd -f deploy/Dockerfile .
# Run:   docker run --cap-add=NET_ADMIN --cap-add=NET_RAW \
#          -v $PWD/testdata/server.json:/etc/vpnd/server.json:ro \
#          -v vpnd-data:/var/lib/vpnd -p 51820:51820/udp vpnd
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /out/vpnd ./cmd/vpnd && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /out/vpnctl ./cmd/vpnctl

FROM alpine:3.20
RUN apk add --no-cache iptables iproute2 ca-certificates && \
    addgroup -S vpnd && adduser -S -G vpnd vpnd && \
    mkdir -p /var/lib/vpnd /etc/vpnd && chown vpnd:vpnd /var/lib/vpnd
COPY --from=build /out/vpnd /usr/local/sbin/vpnd
COPY --from=build /out/vpnctl /usr/local/bin/vpnctl
USER root   # NET_ADMIN capability required; see unit file for capability-bounded systemd alternative
EXPOSE 51820/udp
HEALTHCHECK --interval=30s --timeout=5s \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/api/v1/status || exit 1
ENTRYPOINT ["/usr/local/sbin/vpnd"]
CMD ["--config", "/etc/vpnd/server.json"]
