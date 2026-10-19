# Always-on Yasecret peer. Build from the repository root:
#   docker build -f deploy/relay/Dockerfile -t yasecret-relay .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p yasecret

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data relay \
 && mkdir /data && chown relay /data
COPY --from=build /src/target/release/yasecret /usr/local/bin/yasecret
USER relay
ENV YASECRET_RELAY_DIR=/data
VOLUME /data
ENTRYPOINT ["yasecret", "relay"]
