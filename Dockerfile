# Build stage — Bookworm matches Debian slim runtime (glibc).
FROM rust:1-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Bump CACHE_BUST (or use `docker compose build --no-cache api`) after route/path changes
# so Docker does not reuse an old `cargo build` layer.
ARG CACHE_BUST=2
RUN echo "cache=$CACHE_BUST" && cargo build --release

# Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 appuser

WORKDIR /app

COPY --from=builder /app/target/release/lufai_api /app/lufai_api
COPY casbin_model.conf casbin_policy.csv /app/

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 3000

ENV PORT=3000

ENTRYPOINT ["/app/lufai_api"]
