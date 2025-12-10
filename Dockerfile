FROM rust:alpine AS build

ARG STACKS_NODE_VERSION="No Version Info"
ARG GIT_BRANCH='No Branch Info'
ARG GIT_COMMIT='No Commit Info'

WORKDIR /src

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    pkgconfig \
    perl \
    make \
    g++

COPY . .

RUN mkdir /out

RUN cargo build --bin infer-node --features monitoring_prom,slog_json --release

RUN cp target/release/infer-node /out

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
