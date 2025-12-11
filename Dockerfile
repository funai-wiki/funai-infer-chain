 # syntax=docker/dockerfile:1.6
FROM rust:alpine AS build

ARG STACKS_NODE_VERSION="No Version Info"
ARG GIT_BRANCH='No Branch Info'
ARG GIT_COMMIT='No Commit Info'

WORKDIR /src

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    zlib-dev \
    zlib-static \
    pkgconfig \
    perl \
    make \
    g++

# Copy source code
COPY . .

RUN mkdir /out

# Use release-lite profile for faster builds (less LTO)
# Limit parallel jobs to avoid memory issues and show progress
# Reuse cargo registry/git/target caches across builds (requires BuildKit)
# Build and copy in one step so binary is present even when the layer is cached
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    set -e; \
    CARGO_BUILD_JOBS=4 cargo build --bin infer-node --features monitoring_prom,slog_json --profile release-lite 2>&1 | tee /tmp/build.log || (cat /tmp/build.log && exit 1); \
    bin_path=$(find target -type f \( -path "*/release-lite/infer-node" -o -path "*/release/infer-node" \) | head -n1); \
    if [ -z "$bin_path" ]; then echo "infer-node binary not found" && exit 1; fi; \
    cp "$bin_path" /out/infer-node

FROM alpine

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libgcc

COPY --from=build /out/infer-node /bin/infer-node

# Copy configuration file
COPY testnet/funai-node/conf/fai-testnet-miner-conf.toml.not_commit /etc/infer-chain/fai-testnet-miner-conf.toml

# Set environment variables
ENV STACKS_LOG_INFO=1
ENV BLOCKSTACK_DB_TRACE=0

CMD ["infer-node", "start", "--config", "/etc/infer-chain/fai-testnet-miner-conf.toml"]
