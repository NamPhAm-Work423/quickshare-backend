# Build stage
FROM clux/muslrust:stable AS builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock* ./

# Copy source code
COPY src ./src

# Install build dependencies for musl target
# Note: clux/muslrust is Debian-based, so we use apt-get
# Install build essentials needed for vendored OpenSSL compilation
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    perl \
    && rm -rf /var/lib/apt/lists/*

# Build for release with musl (static binary)
# openssl-sys with vendored feature will compile OpenSSL from source
RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage
FROM gcr.io/distroless/cc:nonroot

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/quickshare-backend /app/quickshare-backend

# Expose port
EXPOSE 3001

# Run the binary
ENTRYPOINT ["/app/quickshare-backend"]
