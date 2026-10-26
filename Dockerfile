# The relay image (ADR 0026): one image, one binary, one port (ADR 0013's
# self-host principle). The builder rides the repo's pinned toolchain —
# digest-pinned here, and CI asserts the tag matches mise.toml's Rust
# (ADR 0014: one version source) — on the SAME Debian release as the
# runtime, because a binary linked against a newer glibc must never meet
# an older one in production.
ARG RUST_IMAGE=docker.io/library/rust:1.99.1-bookworm@sha256:48b7f435b8fc6378ce43b44f15e3a47fd8919b2825f835c39bd4bd3da50af5b8

FROM ${RUST_IMAGE} AS build
WORKDIR /build
# Cargo.toml/lock + the whole apps tree: the workspace manifest must
# resolve, and --locked bakes exactly the reviewed graph.
COPY Cargo.toml Cargo.lock ./
COPY apps apps
RUN cargo build --locked --release -p pursecraft-api \
 && strip target/release/pursecraft-api \
 # the runtime's data directory, created here because distroless ships
 # no mkdir; ownership lands with the COPY below
 && mkdir -p /var/lib/pursecraft

# Runtime: distroless cc (glibc for the bookworm-built binary), nonroot
# (UID/GID 65532, no shell, no package manager — ADR 0026). The exec-form
# entrypoint keeps the relay PID 1 so SIGTERM reaches it unproxied.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
ARG REVISION=unknown
LABEL org.opencontainers.image.title=pursecraft \
      org.opencontainers.image.description="PurseCraft rendezvous sync relay" \
      org.opencontainers.image.source=https://github.com/fluxvale/pursecraft \
      org.opencontainers.image.licenses=FSL-1.1-ALv2 \
      org.opencontainers.image.revision=${REVISION}
COPY --from=build --chown=65532:65532 /build/target/release/pursecraft-api /usr/local/bin/pursecraft-api
COPY --from=build --chown=65532:65532 /var/lib/pursecraft /var/lib/pursecraft
# ADR 0024: the data directory is the relay's whole state — the volume
# mount point; env defaults per the runbook (dev defaults stay in-code).
ENV PURSECRAFT_DATA_DIR=/var/lib/pursecraft \
    PURSECRAFT_BIND=0.0.0.0:8080
VOLUME /var/lib/pursecraft
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/pursecraft-api"]
