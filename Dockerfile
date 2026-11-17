# Multi-stage build: static Go binary on distroless (includes CA certificates).
FROM golang:1.27 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/bot-verify ./cmd/bot-verify

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /out/bot-verify /app/bot-verify
COPY bots.yaml /app/bots.yaml
USER nonroot
EXPOSE 8080
# Distroless has no shell or curl; the binary probes its own /healthz.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/app/bot-verify", "-probe"]
ENTRYPOINT ["/app/bot-verify"]
