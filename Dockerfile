# ── Stage 1: build ──────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

ENV GOPROXY=https://goproxy.cn,direct
ENV GONOSUMDB=*
ENV CGO_ENABLED=0
ENV GOOS=linux

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -buildvcs=false -ldflags="-s -w" -o /lumen-oauth ./cmd/lumen-oauth

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S lumen && adduser -S lumen -G lumen

WORKDIR /app
COPY --from=builder /lumen-oauth .
COPY configs/ configs/
RUN mkdir -p /app/data && chown lumen:lumen /app/data

USER lumen

EXPOSE 9080
ENTRYPOINT ["./lumen-oauth"]
CMD ["--config", "configs/config.example.yaml"]
