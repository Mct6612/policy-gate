# ─── Stage 1: Builder ─────────────────────────────────────────────────────────
# Full Rust toolchain — only used for compilation, thrown away afterwards.
FROM rust:1.78-slim-bookworm AS builder

WORKDIR /build

# Install only what's needed for native TLS (windows-style vs linux)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the workspace manifests first so Docker can cache dependency compilation
# separately from source code changes.
COPY Cargo.toml Cargo.lock ./
COPY crates/firewall-core/Cargo.toml crates/firewall-core/
COPY crates/firewall-proxy/Cargo.toml crates/firewall-proxy/

# Build a dummy binary to cache all dependencies
RUN mkdir -p crates/firewall-core/src crates/firewall-proxy/src \
    && echo "fn main() {}" > crates/firewall-proxy/src/main.rs \
    && echo "" > crates/firewall-core/src/lib.rs \
    && cargo build --release -p firewall-proxy \
    && rm -rf crates/firewall-core/src crates/firewall-proxy/src

# Now copy actual source and rebuild (only the changed crates are recompiled)
COPY crates/ crates/

# Build-time init token — MUST be supplied at build time (SA-073)
ARG POLICY_GATE_INIT_TOKEN
RUN test -n "$POLICY_GATE_INIT_TOKEN" \
    || (echo "ERROR: POLICY_GATE_INIT_TOKEN must be set at build time (SA-073)" && exit 1)

RUN cargo build --release -p firewall-proxy

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
# Minimal Debian image — no Rust toolchain, no build tools, no shell in prod.
FROM debian:bookworm-slim AS runtime

# Install CA certificates so the proxy can reach HTTPS upstreams (OpenAI etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for container security hardening
RUN useradd --system --no-create-home --uid 1001 firewall
USER firewall

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /build/target/release/firewall-proxy /app/firewall-proxy

# Optional: copy a default firewall.toml (overridden by ConfigMap in Kubernetes)
# COPY firewall.example.toml /app/firewall.toml

# ─── Runtime configuration ────────────────────────────────────────────────────
# All values can be overridden via environment variables at container launch.
ENV PORT=8080 \
    UPSTREAM_URL="https://api.openai.com/v1/chat/completions" \
    CONFIG_RELOAD_INTERVAL_SECS=30

EXPOSE 8080

# Prometheus metrics also served on the same port at /metrics
# Health check: GET /health returns "OK"
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/firewall-proxy"]
