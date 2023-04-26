FROM rust:1.68.2-slim-bullseye as build

# Install build dependancies
RUN apt-get update && apt-get -y install git build-essential m4 llvm libclang-dev diffutils curl

WORKDIR /zenotta

COPY Cargo.toml Cargo.lock ./

# Ideally we should build our dependancies first so they will cache
# This is quite an active topic atm:
# https://github.com/rust-lang/cargo/issues/2644
# https://hackmd.io/jgkoQ24YRW6i0xWd73S64A?view#Current-workarounds

# Copy the source so we can build in the container
COPY ./src ./src

# Copy settings as we will be removing the source
COPY ./src/bin/node_settings_local_raft_1.toml node-settings.toml

# Clone dependancies
RUN git clone https://github.com/Zenotta/keccak-prime.git /keccak-prime && git clone -b develop https://github.com/Zenotta/naom.git /naom

# Build for release
RUN cargo build --release

# Remove src
RUN rm -Rvf src
    
# Use a multi-stage build and a distroless image for less attack vectors and a small image
# At the time of testing its about 75MB
FROM gcr.io/distroless/cc-debian11

COPY --from=build /zenotta/target/release/node /usr/local/bin/
COPY --from=build /zenotta/node-settings.toml /etc/zenotta.toml

COPY ./src/bin/initial_block.json ./src/bin/tls_certificates.json ./src/bin/api_config.json /etc/

ENV RUST_LOG=warp

# Override the CMD to start different NodeTypes
CMD ["node compute --config=/etc/zenotta.toml --tls_config=/etc/tls_certificates.json --initial_block_config=/etc/initial_block.json --api_config=/etc/api_config.json"]