# Build stage
FROM clux/muslrust:stable AS builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock* ./

# Copy source code
COPY src ./src

# Build for release with musl (static binary)
RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage
FROM gcr.io/distroless/cc:nonroot

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/nameshare-backend /app/nameshare-backend

# Expose port
EXPOSE 3001

# Run the binary
ENTRYPOINT ["/app/nameshare-backend"]
