# syntax=docker/dockerfile:1.7

ARG RUST_IMAGE=cgr.dev/chainguard/rust:latest-dev@sha256:da65b4401105bc6ba992ed22d6a43fc261e31fe73797cfbb7514e301f0295e9d
ARG RUNTIME_IMAGE=cgr.dev/chainguard/glibc-dynamic:latest@sha256:ea9eab0adc5716fb9937ab60155a31bce9cbc8b56e6f2e21fb9af9218be195b7
# Git binary source. The Go/Zig/Swift proxies (ADR-0023) fetch through gix, which is built
# blocking-network-client only (no native transport) and shells out to `git upload-pack` for every
# fetch — including file:// and git:// — so the runtime image must ship a git binary or those
# ecosystems return 502. Same wolfi/glibc lineage as the runtime, so its shared objects load as-is.
ARG GIT_IMAGE=cgr.dev/chainguard/git:latest@sha256:866f7a1d877f2d809df031d550088429c7f45c19fe390c94fcf99128fee12f16

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
