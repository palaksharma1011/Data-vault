# --- build stage ---
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
# Resolves dependencies and generates go.sum if it is missing
RUN go mod tidy && CGO_ENABLED=0 go build -o /vault-server .

# --- runtime stage ---
FROM alpine:3.20
RUN adduser -D -H vault
WORKDIR /app
COPY --from=build /vault-server ./vault-server
ENV VAULT_DATA_DIR=/app/data
ENV VAULT_ADDR=:8080
RUN mkdir -p /app/data && chown -R vault:vault /app
USER vault
EXPOSE 8080
ENTRYPOINT ["./vault-server"]
