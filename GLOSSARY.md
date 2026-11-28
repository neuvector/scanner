# Scanner

The NeuVector image/container vulnerability scanner. It matches packages found in a scan target against a vulnerability database and reports CVEs, running either under a NeuVector controller or as a standalone CLI.

## Language

**cvedb**:
The vulnerability database the scanner matches packages against — one large (~175 MB) encrypted, compressed file. Volatile: it changes far more often than the scanner code.
_Avoid_: vulndb (reserve for the published artifact), vuln data, CVE data

**vulndb artifact**:
The cvedb published as a standalone, cosign-signed OCI artifact (`ghcr.io/<owner>/vul/cvedb:<version>`), produced by a separate pipeline (the `release` repo's `build-vuldbgen.yaml`). It is the source of truth the scanner pulls from.
_Avoid_: OCI db, db image

**baked-in db**:
A copy of the cvedb embedded into the scanner image at build time at `/etc/neuvector/db/cvedb`. The coupling this experiment removes.
_Avoid_: bundled db, embedded db

**slim scanner image**:
A scanner image shipping the binaries but no baked-in db; it performs db acquisition at runtime instead.
_Avoid_: dbless image, thin image

**db acquisition**:
The startup step by which a slim scanner obtains the cvedb — pulling the vulndb artifact from OCI, verifying its signature, and writing it to `/etc/neuvector/db/cvedb` — before loading it. The same path serves both standalone and orchestrated mode.
_Avoid_: db fetch, db pull, db download

**standalone mode**:
The scanner run as a CLI with no controller present (`cmd/scanner/standalone.go`). It performs its own db acquisition.
_Avoid_: CLI mode, offline mode

**controller push**:
The runtime path where the scanner, at registration, streams its cvedb **up to** the NeuVector controller over gRPC in chunks (`cmd/scanner/server.go`, `ScannerRegisterV3`). Flow is scanner → controller: the scanner is the source. No RPC delivers a cvedb *to* the scanner, which is why a slim scanner must perform db acquisition first.
_Avoid_: db sync, controller sync
