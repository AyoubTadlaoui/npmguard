# syntax=docker/dockerfile:1.7
#
# Dockerfile for npmguard-mcp — the MCP server binary only.
#
# This image exists for MCP-catalog compatibility (Glama, awesome-mcp-servers,
# future OCI submission to modelcontextprotocol/registry). The primary install
# path remains the native binaries on GitHub Releases — see README.md.
#
# Build:
#   docker build -t ghcr.io/ayoubtadlaoui/npmguard-mcp:dev .
#
# Run (stdio, for MCP host integration):
#   docker run --rm -i ghcr.io/ayoubtadlaoui/npmguard-mcp:dev
#
# The container has no exposed ports (stdio transport), no health check, and
# no CMD beyond the entrypoint. MCP hosts invoke it directly.

# ----------------------------------------------------------------------------
# Stage 1 — build the binary against a pinned Rust toolchain
# ----------------------------------------------------------------------------
FROM rust:1.96-bookworm AS builder
WORKDIR /src

# Copy the workspace manifests first so layer caching can reuse dependency
# compilation when only source files change.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

# Build only the MCP bin; we don't need the CLI inside the container.
RUN cargo build --release --bin npmguard-mcp \
 && strip target/release/npmguard-mcp

# ----------------------------------------------------------------------------
# Stage 2 — minimal runtime
# ----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# rustls-based reqwest needs only the system CA bundle for HTTPS to OSV.dev,
# registry.npmjs.org, and api.github.com. No OpenSSL, no other native deps.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Non-root user. UID 10001 is a common convention for app users (well above
# system UIDs, well below the nobody/65534 range).
RUN groupadd --system --gid 10001 npmguard \
 && useradd --system --uid 10001 --gid npmguard --no-create-home \
            --shell /usr/sbin/nologin npmguard

COPY --from=builder /src/target/release/npmguard-mcp /usr/local/bin/npmguard-mcp

USER npmguard

ENTRYPOINT ["/usr/local/bin/npmguard-mcp"]

# OCI image labels — drives metadata on GHCR + MCP catalogs.
LABEL org.opencontainers.image.title="npmguard-mcp"
LABEL org.opencontainers.image.description="MCP server exposing npmguard's pre-install risk gate to AI coding agents."
LABEL org.opencontainers.image.url="https://github.com/AyoubTadlaoui/npmguard"
LABEL org.opencontainers.image.source="https://github.com/AyoubTadlaoui/npmguard"
LABEL org.opencontainers.image.documentation="https://github.com/AyoubTadlaoui/npmguard/blob/main/README.md"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.authors="Ayoub Tadlaoui"
LABEL org.opencontainers.image.vendor="AyoubTadlaoui"

# MCP-specific label, required by the official registry's OCI verification.
# Value MUST match the server name from server.json — namespaced form
# `io.github.<owner>/<server>`, lowercase per OCI convention.
LABEL io.modelcontextprotocol.server.name="io.github.ayoubtadlaoui/npmguard"
