FROM rust:1.75-slim-bookworm as builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev build-essential

WORKDIR /usr/src/app
COPY . .

RUN cargo build --release --bin infer-node

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/release/infer-node /usr/local/bin/infer-node

ENTRYPOINT ["infer-node"]

