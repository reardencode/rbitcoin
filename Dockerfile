# Operator image: the Release musl binaries on an empty base.
#
# Not a source build. The context is a staged directory with one
# subdirectory per Docker arch, each holding the static node and cli from
# ./scripts/stage-musl-artifacts.sh. release.yml builds it per arch, smokes
# it with ./scripts/docker-smoke.sh, and publishes the multi-arch manifest.
# There is no RUN, so assembling a foreign arch needs no emulation.
#
# Local (host arch; the subdirectory is Docker's amd64 or arm64):
#   ./scripts/repro-build.sh musl ./result
#   ./scripts/stage-musl-artifacts.sh ./result \
#     "./dist/docker/$(docker version -f '{{.Server.Arch}}')"
#   docker build -t rbitcoin:local -f Dockerfile ./dist/docker
#
# Node and cli both default to ./datadir, so the datadir is /data/datadir.
# Mount a volume on /data. Stop with `docker stop -t 300`: the node flushes
# the store on SIGTERM and Docker's 10 s default can cut that short.
# Contract: ./scripts/dockerfile.test.sh. Run docs: docs/operator/setup.md.

FROM scratch

ARG TARGETARCH
ARG VERSION=unknown
ARG REVISION=unknown

COPY --chmod=0755 ${TARGETARCH}/rbitcoin-node ${TARGETARCH}/rbitcoin-cli /usr/local/bin/

USER 10001:10001
WORKDIR /data
VOLUME ["/data"]

EXPOSE 8333
STOPSIGNAL SIGTERM

LABEL org.opencontainers.image.title="rbitcoin" \
      org.opencontainers.image.description="Experimental Bitcoin full node (rbitcoin-node) and CLI" \
      org.opencontainers.image.source="https://github.com/reardencode/rbitcoin" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

ENTRYPOINT ["/usr/local/bin/rbitcoin-node"]
