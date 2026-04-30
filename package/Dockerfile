ARG VULNDB_VERSION=4.148
ARG VULNDB_CHECKSUM=8781ee7a9c80db7f945d915584be5dcc7bb4e4440e49a3e21b77a6d77da83505
ARG GOVULNDB_CHECKSUM=be132d3a8f0405e0720e83c7b5921fb96b23b0478fda27761bf13a25198e8736
ARG SIGSTORE_VERSION=426a5b0c9dff026dbc1961c81e232509a7c335cb
#
# Builder
#
FROM registry.suse.com/bci/golang:1.26.2 AS builder
ARG VERSION
ARG VULNDB_CHECKSUM
ARG GOVULNDB_CHECKSUM
ARG SIGSTORE_VERSION

RUN zypper in -y wget

# Build controller
COPY common/ /src/common
COPY cvetools/ /src/cvetools
COPY data/ /src/data
COPY detectors/ /src/detectors
COPY monitor/ /src/monitor
COPY task/ /src/task
COPY vendor/ /src/vendor
COPY Makefile go.mod go.sum *.go genlic.sh /src/

WORKDIR /src
RUN git clone https://github.com/neuvector/sigstore-interface --single-branch sigstore-interface && cd sigstore-interface && git checkout ${SIGSTORE_VERSION} && make
RUN if [ -f "data/cvedb.regular" ]; then echo "using cvedb.regular"; echo "$VULNDB_CHECKSUM data/cvedb.regular" | sha256sum --check --status; else echo "using cvedb"; cp "data/cvedb" "data/cvedb.regular"; fi
RUN if [ -f "data/govulndb.zip" ]; then echo "using govulndb.zip"; echo "$GOVULNDB_CHECKSUM data/govulndb.zip" | sha256sum --check --status; else echo "using govulndb.zip.local"; cp "data/govulndb.zip.local" "data/govulndb.zip"; fi
RUN make slsa_all

#
# Base images
#
FROM registry.suse.com/bci/bci-micro:15.7 AS micro
FROM registry.suse.com/bci/bci-base:15.7 AS base

COPY --from=micro / /chroot/
RUN zypper refresh && zypper --installroot /chroot -n in --no-recommends \
  ca-certificates procps grep && \
  zypper --installroot /chroot clean -a && \
  rm -rf /chroot/var/log/

RUN cd /chroot/usr/bin/ && rm -rf basename chcon chgrp chmod chown chroot cksum dd df dircolors dirname du install install-info join locale localedef mkdir mkfifo mknod mktemp paste pathchk readlink realpath sync smidiff smidump smilink smiquery smistrip smixlate tee tiemout tload top truncate unlink watch

RUN mkdir -p /chroot/etc/neuvector/certs/internal/ && mkdir -p /chroot/share && touch /chroot/share/.nvcontainer
RUN chmod 770 /chroot/etc/neuvector/certs/internal/

#
# Artifact
#
FROM micro
WORKDIR /
COPY --from=base /chroot/ /
COPY --from=builder /src/stage /

ARG COMMIT
ARG VERSION
ARG VULNDB_VERSION
ARG SIGSTORE_VERSION

LABEL name="scanner" \
  vendor="SUSE Security" \
  version=${VERSION} \
  release=${VERSION} \
  neuvector.image="neuvector/scanner" \
  neuvector.role="scanner" \
  neuvector.rev="${COMMIT}" \
  neuvector.vuln_db="${VULNDB_VERSION}" \
  neuvector.sigstore="${SIGSTORE_VERSION}" \
  "io.artifacthub.package.logo-url"=https://avatars2.githubusercontent.com/u/19367275 \
  "io.artifacthub.package.readme-url"="https://raw.githubusercontent.com/neuvector/scanner/${VERSION}/README.md" \
  "org.opencontainers.image.description"="SUSE Security Scanner" \
  "org.opencontainers.image.title"="SUSE Security Scanner" \
  "org.opencontainers.image.source"="https://github.com/neuvector/scanner/" \
  "org.opencontainers.image.version"="${VERSION}" \
  "org.opensuse.reference"="neuvector/scanner:${VERSION}"

ENTRYPOINT ["/usr/local/bin/monitor"]
