# syntax=docker/dockerfile:1.7

ARG RUST_IMAGE=cgr.dev/chainguard/rust:latest-dev@sha256:36c7dcdaf98640742966fa3b05c8896286268988e016c305ee038db28641ead4
ARG RUNTIME_IMAGE=cgr.dev/chainguard/glibc-dynamic:latest@sha256:709673274b417a48f56374da8a7633ef7b2f5b27e34612ce98a335737318cc94
# Git binary source. The Go/Zig/Swift proxies (ADR-0023) fetch through gix, which is built
# blocking-network-client only (no native transport) and shells out to `git upload-pack` for every
# fetch — including file:// and git:// — so the runtime image must ship a git binary or those
# ecosystems return 502. Same wolfi/glibc lineage as the runtime, so its shared objects load as-is.
ARG GIT_IMAGE=cgr.dev/chainguard/git:latest@sha256:9af245693971eacc8414e52060ddaab20387a50908bb72fb3f142ba0bcf5d003

FROM ${GIT_IMAGE} AS git

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

# Git for the git-sourced proxies (see GIT_IMAGE above). `git` plus its exec-path helpers
# (git-upload-pack lives here) and the two extra shared objects it needs beyond glibc — the runtime
# base already provides libc and the loader. No curl/openssl: gix only uses git for the local pack
# protocol, never HTTP.
COPY --from=git /usr/bin/git /usr/bin/git
COPY --from=git /usr/libexec/git-core /usr/libexec/git-core
COPY --from=git /usr/lib/libpcre2-8.so.0 /usr/lib/libz.so.1 /usr/lib/

ENV STARMETAL_CONFIG=/etc/starmetal/starmetal.toml
ENV RUST_LOG=info

VOLUME ["/var/lib/starmetal"]
EXPOSE 8080

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/sm"]
CMD ["serve"]
