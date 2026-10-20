# ---------- build stage ----------
FROM golang:1.22-alpine AS build
WORKDIR /src

# Cache dependencies separately from source for faster rebuilds
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Static binary; web UI is embedded via go:embed, so nothing else is needed
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /vault-server .

# ---------- runtime stage ----------
FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget \
 && adduser -D -H -u 10001 vault

WORKDIR /app
COPY --from=build /vault-server ./vault-server

ENV VAULT_DATA_DIR=/app/data \
    VAULT_ADDR=:8080

# Create the data dir owned by the non-root user (named volume inherits this)
RUN mkdir -p /app/data && chown -R vault:vault /app
USER vault

EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
  CMD wget -qO- http://127.0.0.1:8080/ >/dev/null || exit 1

ENTRYPOINT ["./vault-server"]