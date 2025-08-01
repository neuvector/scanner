ARG VULNDB_VERSION=3.879
ARG VULNDB_CHECKSUM=6d84a5c009bb45aca4d4927981cc8bf0e8b3422df0d0cad2cd3f69a5ae376b1f
ARG SIGSTORE_VERSION=838ee1133ca0020368f154adc40510a50a9c9d31
#
# Builder
#
FROM registry.suse.com/bci/golang:1.24 AS builder
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
