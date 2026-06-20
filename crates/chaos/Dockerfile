FROM rust:1.75-slim as builder

WORKDIR /app

COPY . .

RUN cargo build --release --bin chaos-agent

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/chaos-agent /usr/local/bin/

ENTRYPOINT ["chaos-agent"]
