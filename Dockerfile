FROM rust:1.81-slim-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock* config.example.toml ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && mkdir -p .cargo
RUN cargo build --release 2>/dev/null || true
COPY src ./src
RUN cargo build --release --bin aether
RUN cargo build --release --bin aether-gui

FROM debian:bookworm-slim AS aether-cli
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/aether /usr/local/bin/aether
COPY --from=builder /app/config.example.toml /etc/aether/config.toml
RUN mkdir /data
EXPOSE 25565 9933
VOLUME ["/data"]
ENV RUST_LOG=info
ENTRYPOINT ["aether"]
CMD ["--node-type", "miner", "--data-dir", "/data", "--p2p-port", "25565", "--rpc-port", "9933"]

FROM debian:bookworm-slim AS aether-gui
RUN apt-get update && apt-get install -y --no-install-recommends libgtk-3-0 libglib2.0-0 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/aether-gui /usr/local/bin/aether-gui
COPY --from=builder /app/config.example.toml /etc/aether/config.toml
EXPOSE 25565 9933
ENV RUST_LOG=info
ENTRYPOINT ["aether-gui"]
