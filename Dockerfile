# Multi-stage build: static Go binary on distroless (includes CA certificates).
FROM golang:1.27@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/ ./cmd/bot-verify ./cmd/bot-verify-dns

# DNS verify zone: docker build --target dns. Nonroot cannot bind 53, so it
# listens on 5353; map the port (-p 53:5353/udp -p 53:5353/tcp).
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS dns
WORKDIR /app
COPY --from=builder /out/bot-verify-dns /app/bot-verify-dns
COPY bots.yaml /app/bots.yaml
USER nonroot
EXPOSE 5353/udp 5353/tcp
# The health check does not see the CMD's -zone, so it only checks that the
# server answers DNS at all.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/app/bot-verify-dns", "-probe"]
ENTRYPOINT ["/app/bot-verify-dns"]

# HTTP API, the default target: it stays the last stage.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
WORKDIR /app
COPY --from=builder /out/bot-verify /app/bot-verify
COPY bots.yaml /app/bots.yaml
USER nonroot
EXPOSE 8080
# Distroless has no shell or curl; the binary probes its own /healthz.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/app/bot-verify", "-probe"]
ENTRYPOINT ["/app/bot-verify"]
