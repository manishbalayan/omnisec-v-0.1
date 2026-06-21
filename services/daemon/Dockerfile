FROM rust:1.91-slim as builder

WORKDIR /app

COPY . .

RUN cargo build --release --bin omnisec-daemon

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/omnisec-daemon /usr/local/bin/

CMD ["omnisec-daemon"]
