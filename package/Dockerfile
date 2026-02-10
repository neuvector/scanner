ARG VULNDB_VERSION=4.070
ARG VULNDB_CHECKSUM=2c61d3a32dfd49404e4180f0c8a8aa23789fad13249bfaa90b88395f5e53b99e
ARG SIGSTORE_VERSION=7a92b9b39c0a095ce264980df4e7757ef9548efc
#
# Builder
#
FROM registry.suse.com/bci/golang:1.25 AS builder
ENV GOTOOLCHAIN=1.25.7
ARG VERSION
ARG VULNDB_CHECKSUM
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
