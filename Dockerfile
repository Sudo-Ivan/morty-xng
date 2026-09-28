# syntax=docker/dockerfile:1

# STEP 1: build a static binary
FROM docker.io/library/golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS builder

WORKDIR /src

# download dependencies first for layer caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" -o /morty .

# STEP 2: minimal runtime image, non-root user
FROM docker.io/library/alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="morty-xng" \
      org.opencontainers.image.description="Web content sanitizer proxy for SearXNG (fork of asciimoo/morty)" \
      org.opencontainers.image.source="https://github.com/Sudo-Ivan/morty-xng" \
      org.opencontainers.image.url="https://github.com/Sudo-Ivan/morty-xng" \
      org.opencontainers.image.documentation="https://github.com/Sudo-Ivan/morty-xng#readme" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.vendor="Sudo-Ivan" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

RUN apk --no-cache add ca-certificates \
 && adduser -D -h /home/morty -s /sbin/nologin morty

USER morty

COPY --from=builder /morty /usr/local/bin/morty

EXPOSE 3000

# listen on all interfaces so other containers (e.g. searxng) can reach it
ENV DEBUG=false \
    MORTY_ADDRESS=0.0.0.0:3000

# busybox provides the wget applet used here
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:3000/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/morty"]
