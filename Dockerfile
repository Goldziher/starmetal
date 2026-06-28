# syntax=docker/dockerfile:1.7

ARG RUST_IMAGE=cgr.dev/chainguard/rust:latest-dev@sha256:da65b4401105bc6ba992ed22d6a43fc261e31fe73797cfbb7514e301f0295e9d
ARG RUNTIME_IMAGE=cgr.dev/chainguard/glibc-dynamic:latest@sha256:ea9eab0adc5716fb9937ab60155a31bce9cbc8b56e6f2e21fb9af9218be195b7

FROM ${RUST_IMAGE} AS builder
WORKDIR /work

ARG CARGO_FEATURES=full
ENV CARGO_TERM_COLOR=always

COPY --chown=65532:65532 . .
RUN --mount=type=cache,target=/home/nonroot/.cargo/registry,uid=65532,gid=65532 \
    --mount=type=cache,target=/home/nonroot/.cargo/git,uid=65532,gid=65532 \
    --mount=type=cache,target=/work/target,uid=65532,gid=65532 \
    cargo build --locked --release -p starmetal-cli --bin sm --no-default-features --features "${CARGO_FEATURES}" \
    && mkdir -p /work/out/var/lib/starmetal \
    && cp /work/target/release/sm /work/out/sm

FROM ${RUNTIME_IMAGE} AS runtime

COPY --from=builder --chown=65532:65532 /work/out/sm /usr/local/bin/sm
COPY --from=builder --chown=65532:65532 /work/out/var/lib/starmetal /var/lib/starmetal
COPY --chown=65532:65532 docker/starmetal.toml /etc/starmetal/starmetal.toml

ENV STARMETAL_CONFIG=/etc/starmetal/starmetal.toml
ENV RUST_LOG=info

VOLUME ["/var/lib/starmetal"]
EXPOSE 8080

USER 65532:65532

# One image covers both modes:
# - `docker run starmetal:local` starts the API server via `sm serve`.
# - `docker run starmetal:local <args>` runs the `sm` CLI/MCP command passed by the caller.
ENTRYPOINT ["/usr/local/bin/sm"]
CMD ["serve"]
