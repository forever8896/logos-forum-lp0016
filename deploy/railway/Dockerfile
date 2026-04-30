# ─── Stage 1: build sequencer + wallet from logos-execution-zone v0.2.0-rc1 ───
#
# We build the sequencer with `--features standalone` (sequencer_core/mock)
# so it runs without the Bedrock L1 + Indexer triplet — that's how
# logos-scaffold's `localnet start` runs it locally and what the LP-0016
# evaluator-facing demo expects.
#
# We also download the logos-blockchain-circuits release tarball that LEZ's
# transitive `logos-blockchain-pol` build script needs, otherwise the build
# panics with "Could not find logos-blockchain-circuits directory".

FROM rust:1.94-bookworm AS builder

ARG LEZ_TAG=v0.2.0-rc1
ARG CIRCUITS_VERSION=v0.4.2

# System deps for building LEZ.
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        libclang-dev \
        libssl-dev \
        pkg-config \
        cmake \
        build-essential \
        ca-certificates \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

# Install r0vm (RISC0's RISC-V execution server). The sequencer launches it
# as a subprocess to execute every transaction's guest program — without it,
# the mandatory clock TX in each block silently fails and the main loop
# exits with "Main loop exited unexpectedly".
RUN curl -L https://risczero.com/install | bash \
    && /root/.risc0/bin/rzup install r0vm 3.0.5 \
    && find /root/.risc0 -name r0vm -type f -executable 2>/dev/null \
    && cp "$(find /root/.risc0 -name r0vm -type f -executable | head -1)" /usr/local/bin/r0vm \
    && /usr/local/bin/r0vm --version

# Logos circuits release (transitive build-time dep of nssa).
RUN mkdir -p /root/.logos-blockchain-circuits \
    && curl -sSL -o /tmp/circuits.tar.gz \
        "https://github.com/logos-blockchain/logos-blockchain-circuits/releases/download/${CIRCUITS_VERSION}/logos-blockchain-circuits-${CIRCUITS_VERSION}-linux-x86_64.tar.gz" \
    && tar -xzf /tmp/circuits.tar.gz -C /root/.logos-blockchain-circuits --strip-components=1 \
    && rm /tmp/circuits.tar.gz

# Clone the pinned LEZ source.
WORKDIR /src
RUN git clone --depth 1 --branch "${LEZ_TAG}" \
        https://github.com/logos-blockchain/logos-execution-zone.git lez
WORKDIR /src/lez

# Pre-fetch deps (cacheable layer).
RUN cargo fetch

# Build sequencer (standalone) + wallet — release, single-codegen-unit for
# smaller binaries.
RUN cargo build --release --features standalone -p sequencer_service \
    && cargo build --release -p wallet \
    && strip target/release/sequencer_service target/release/wallet

# Capture sequencer's default standalone config (we'll templatize the port
# at runtime via the entrypoint).
RUN cp sequencer/service/configs/debug/sequencer_config.json /tmp/sequencer_config.json


# ─── Stage 2: minimal runtime image ───────────────────────────────────────────

FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/anonymous/logos-forum"
LABEL org.opencontainers.image.description="LEZ standalone sequencer for the LP-0016 forum_registry program"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

# Runtime deps only: libssl3 + ca-certs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates \
        jq \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries.
COPY --from=builder /src/lez/target/release/sequencer_service /usr/local/bin/sequencer_service
COPY --from=builder /src/lez/target/release/wallet            /usr/local/bin/wallet
# r0vm — RISC-V VM server the sequencer subprocess-spawns to execute every
# guest transaction (including the mandatory per-block clock TX).
COPY --from=builder /usr/local/bin/r0vm                       /usr/local/bin/r0vm

# Copy the logos-blockchain-circuits release the sequencer needs at runtime
# (zk/circuits/utils looks here when proofs are verified). Without it the
# sequencer panics on startup with "Could not find logos-blockchain-circuits
# directory".
COPY --from=builder /root/.logos-blockchain-circuits /root/.logos-blockchain-circuits

# Tell the sequencer where r0vm lives.
ENV RISC0_SERVER_PATH=/usr/local/bin/r0vm

# Copy default config + entrypoint that templatizes the port from $PORT.
COPY --from=builder /tmp/sequencer_config.json /etc/sequencer_service/sequencer_config.json
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Persistent data dir. Railway mounts a Railway Volume at this path
# (configured via `railway volume add` after first deploy). Note: a
# `VOLUME` directive is forbidden in Railway-built Dockerfiles, so we
# only `mkdir`.
RUN mkdir -p /var/lib/sequencer_service

# Railway sets $PORT dynamically; default to 3040 for local docker-run.
ENV PORT=3040
EXPOSE 3040

# Health-check: hit the JSON-RPC root and check we got *something* back.
# (`sequencer_service` doesn't expose a dedicated /health endpoint — any 200
# or 405 from the RPC server is enough to confirm the process is up.)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -sf "http://127.0.0.1:${PORT}/" -o /dev/null \
      || curl -sf -X POST "http://127.0.0.1:${PORT}/" -H 'content-type: application/json' \
            -d '{"jsonrpc":"2.0","method":"system_health","id":1}' -o /dev/null \
      || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
