FROM rust:1.94.0-bookworm AS build
WORKDIR /source
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY migrations ./migrations
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 signal-node \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin signal-node \
    && mkdir -p /var/lib/signal-node /etc/signal-node /run/secrets \
    && chown 10001:10001 /var/lib/signal-node
COPY --from=build /source/target/release/signal-node /usr/local/bin/signal-node
USER 10001:10001
WORKDIR /var/lib/signal-node
EXPOSE 8787
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/signal-node"]
CMD ["--config", "/etc/signal-node/signal-node.toml"]
