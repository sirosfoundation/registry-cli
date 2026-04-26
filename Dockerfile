# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Install build dependencies (git for deps, gcc/musl for CGO/PKCS#11)
RUN apk add --no-cache git ca-certificates gcc musl-dev

# Copy go mod files first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with version information
# CGO required for PKCS#11 support via crypto11
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w -linkmode external -extldflags '-static' \
    -X github.com/sirosfoundation/registry-cli/cmd/registry-cli/cmd.Version=${VERSION} \
    -X github.com/sirosfoundation/registry-cli/cmd/registry-cli/cmd.Commit=${COMMIT} \
    -X github.com/sirosfoundation/registry-cli/cmd/registry-cli/cmd.BuildTime=${BUILD_DATE}" \
    -o registry-cli ./cmd/registry-cli

# Runtime stage
FROM alpine:3.23

WORKDIR /app

# Add ca-certificates for TLS, git for repo cloning, softhsm2 for signing
RUN apk add --no-cache ca-certificates git softhsm

# Copy binary from builder
COPY --from=builder /app/registry-cli /usr/local/bin/registry-cli

# Create directories for sources and output
RUN mkdir -p /data/sources /data/output /data/tokens

# Run as non-root user
RUN adduser -D -u 1000 registry
USER registry

VOLUME ["/data/sources", "/data/output", "/data/tokens"]

EXPOSE 8080

ENTRYPOINT ["registry-cli"]
CMD ["serve", "--addr", "0.0.0.0", "--port", "8080", "--sources", "/data/sources/sources.yaml", "--output", "/data/output"]
