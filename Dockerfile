# The vault node's image. Everything in it is pinned (base images by digest, Rust crates by Cargo.lock), and its
# files get one fixed timestamp (build.sh), so the same commit always gives the same enclave measurements (PCR0-2).
#
#   --target sidecar  the node as a container next to the bot (docker-compose service "vault"): no Rust needed.
#   (default)         the image build.sh turns into the Nitro Enclave image (enclave.eif).

FROM docker.io/library/rust:1.97.0-slim-bookworm@sha256:6d220bf85c74e842a79da63997af8d2e74455c0b8847d8bb3a5888572334991d AS io
WORKDIR /build
COPY io/Cargo.toml io/Cargo.lock ./
COPY io/src ./src
ENV RUSTFLAGS="--remap-path-prefix=/build=. --remap-path-prefix=/usr/local/cargo=/cargo -C link-arg=-Wl,--build-id=none" \
    SOURCE_DATE_EPOCH=0
RUN cargo build --release --locked && cp target/release/enclave-io /enclave-io

FROM docker.io/library/node:22.22.0-bookworm-slim@sha256:dd9d21971ec4395903fa6143c2b9267d048ae01ca6d3ea96f16cb30df6187d94 AS sidecar
WORKDIR /node
# Only the node's own code: no npm packages at all (Node's built-in crypto, http and https).
COPY src ./src
COPY start.sh ./start.sh
ARG BYME_VAULT_VERSION=dev
ENV BYME_VAULT_VERSION=${BYME_VAULT_VERSION} NODE_ENV=production
CMD ["/bin/sh", "/node/start.sh"]

FROM sidecar AS enclave
COPY --from=io /enclave-io /usr/local/bin/enclave-io
ENV VAULT_NODE_NITRO=1
