FROM rust:1-bookworm
WORKDIR /src
COPY Cargo.toml .
COPY src ./src
RUN cargo build --release && cp target/release/client /usr/local/bin/client
