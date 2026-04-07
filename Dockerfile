FROM rust:1.86 as builder

WORKDIR /work
COPY Cargo.toml Cargo.toml
COPY src src

RUN rustup target add wasm32-wasip1
RUN cargo build --release --target wasm32-wasip1

FROM scratch
COPY --from=builder /work/target/wasm32-wasip1/release/istio_keycloak_wasm_plugin.wasm /plugin.wasm