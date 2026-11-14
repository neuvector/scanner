# Experiment: release the cvedb and the scanner binary separately

Status: spec agreed via design review; prototype in progress on branch
`experiment/decoupled-cvedb` (`common/vulndb/`, scanner wiring, slim image).
The runtime pull + keyless verification path is implemented but not yet
validated end-to-end against the live signed artifact (needs network).

## Goal

Decouple the vulnerability database's release/update cadence from the scanner
image. The **cvedb** changes far more often than the scanner code; today it is
**baked into** the scanner image, so every db update forces a full image rebuild
and re-release. We want the scanner image to carry only code, and the db to be
pulled at runtime. Smaller images and independent version lifecycles are welcome
side effects, not the primary driver.

## Current state (as of this spec)

- One image, `neuvector/scanner:<tag>` (`package/Dockerfile`), bundles four
  binaries **plus** the ~175 MB cvedb at `/etc/neuvector/db/cvedb`.
- The cvedb is *already* published as a standalone, cosign-signed OCI artifact
  (`ghcr.io/<owner>/vul/cvedb:<version>`) by the `release` repo's
  `build-vuldbgen.yaml`. `scripts/ghcr-vulndb-artifact.sh` publishes / downloads
  / verifies it. The scanner release workflow downloads it **at image-build time**
  (pinned by `ARG VULNDB_VERSION`) and bakes it in.
- Scanner version is coupled to db version by convention (Makefile:
  "the version is also vulndb version"; `neuvector.vuln_db` image label).
- Runtime db flow is **scanner → controller**: at registration the scanner reads
  the baked-in db, extracts it, and streams it *up* to the controller
  (`cmd/scanner/server.go`, `ScannerRegisterV3`). No RPC delivers a db *to* the
  scanner — the scanner is the source. Standalone mode reads the same on-disk db.
- `github.com/google/go-containerregistry/pkg/v1/remote` is already vendored
  (used by sigstore today). In-process cosign verification already exists in
  `cmd/sigstore-interface` (cosign v3 libs, keyless + key-based).

## Design

### Acquisition (unified path)

A **slim scanner image** ships no baked-in db. At startup, before the existing
`dbExtract` / controller-registration flow, the scanner performs **db
acquisition** in-process:

1. Resolve the target artifact reference (registry + repo + version).
2. Resolve its digest; if the on-disk db already matches, skip the download.
3. Pull the artifact layer and extract the db file to `/etc/neuvector/db/cvedb`
   (the artifact's `db/cvedb.regular` is byte-identical to the baked-in
   `/etc/neuvector/db/cvedb`).
4. Verify the artifact signature (see below) before the db is used.
5. Proceed with the existing load/extract/registration flow unchanged.

The **same path serves standalone and orchestrated mode.** Pulling is done
in-process with the already-vendored `go-containerregistry/pkg/v1/remote`.

### Configuration knobs (env var / flag, with defaults)

- **Registry/repo**: default `ghcr.io/<owner>/vul/cvedb`, overridable so air-gap
  users can point at a mirror.
- **Version**: default `latest`, overridable to pin a version/digest.
- **Pull secret / auth**: optional; anonymous pull if none supplied.
- **Signer identity**: default to the known `build-vuldbgen` workflow identity +
  GitHub OIDC issuer; overridable.

### Verification

Verify the pulled artifact **in-process, keyless**, pinning the signer identity
(issuer `token.actions.githubusercontent.com`, subject = the `build-vuldbgen.yaml`
workflow). Verification uses `sigstore-go`'s `root.FetchTrustedRoot()`, a
**separate** trust path from `cmd/sigstore-interface` (whose embedded root is
expired, 2024) — this avoids that stale root rather than repairing it.

Signature discovery detail (learned from live testing — see the in-cluster run):
the cvedb artifact is signed with the **new sigstore bundle format**
(`application/vnd.dev.sigstore.bundle.v0.3+json`), stored as **OCI 1.1 referrers**
with no legacy `sha256-<digest>.sig` tag and no cosign artifactType on the
referrer index entries. Consequently cosign's legacy and `ExperimentalOCI11`
image-signature paths do **not** discover it, and vendored cosign v3.0.6's
`NewBundleFormat` image-signature path is unimplemented. The working path is
`cosign.GetBundles` (fetches the referrer bundles, unfiltered) + `sigstore-go`'s
`verify.Verifier` with an artifact-digest + certificate-identity policy. This is
what `common/vulndb/verify.go` does.

Important: this path is **online-only**. `FetchTrustedRoot()` bootstraps from
`sigstore-go`'s embedded root.json but then walks the live sigstore TUF CDN
(`tuf-repo-cdn.sigstore.dev`) and Rekor. The embedded bootstrap root.json is
*itself* already expired (2026-06-22), so verification succeeds only because the
live TUF walk fetches newer, still-valid root versions past the expired anchor.
It is fail-closed (an unreachable TUF/Rekor fails verification, not bypasses it),
but it does **not** work air-gapped on the vendored root alone — see Scope.

### Failure behavior — fail-closed

No db means no scanning. On pull or verify failure: retry with bounded backoff,
then **exit non-zero**. In a cluster, the orchestrator restarts the pod (pods
already restart daily); standalone surfaces a non-zero exit with a clear error.
No running dbless, no silent degradation, no stale fallback.

### Version decoupling

Remove the build-time scanner-version == vulndb-version coupling: drop
`ARG VULNDB_VERSION` / the download-and-bake step from the Dockerfile and release
workflow, and the `neuvector.vuln_db` image label. The db version is reported at
runtime from the extracted db's own version file
(`CheckExpandedDb` / `cvedbMeta`), which already works.

## Scope

**In scope (this repo only):** slim image build; in-process acquisition + keyless
verification; config knobs; fail-closed behavior; removing build-time version
coupling; standalone self-acquisition.

**Out of scope:** controller changes (none needed — scanner still pushes the db
up after acquiring it); init-container delivery (likely the production shape,
needs Helm changes in another repo); persistent db caching across pods; a full
air-gap story. Note air-gap needs more than "configurable registry + pinned
version": keyless verification currently reaches the live sigstore TUF/Rekor
endpoints, so an air-gapped deployment would also need a pinned/offline
`trusted_root.json` (or a mirror serving current sigstore TUF metadata), or a
switch to a private/key-based root of trust. Deferred.

## Open facts — resolved during live testing

- RESOLVED (YES): `ghcr.io/neuvector/vul/cvedb` is anonymously pullable. The
  artifact layer contains `db/cvedb.regular` (+ `db/VERSION`), matching the
  extractor. Auth remains configurable for private mirrors.
- RESOLVED: the signed cvedb verifies end-to-end. Confirmed both by `cosign verify`
  of the real artifact and by the in-cluster slim scanner (pull → verify → extract
  → load → scan). Signatures are new-format sigstore bundles via OCI referrers
  (see Verification).
- RESOLVED (NO): `sigstore-go`'s *embedded* TUF root is already expired
  (2026-06-22), so keyless verification depends on the live sigstore TUF CDN +
  Rekor being reachable at scanner startup (works online; not air-gap-capable on
  the vendored root alone).

## Verified in-cluster (EKS, 2 nodes)

Slim image (229 MB, no baked db) run as a standalone `Job` with
`SCANNER_CVEDB_PULL=true`:
- First run (pre-fix) proved **fail-closed**: 5 bounded retries, then non-zero
  exit, pod `Failed`, never ran dbless.
- Final run **succeeded**: logs show `verifying cvedb artifact signature
  bundles=2` → `cvedb installed` → `acquisition complete changed=true` → db
  loaded (`readCveDbMeta` across all OS families) → `alpine:3.19` scanned, 4 CVEs
  reported (incl. HIGH `musl CVE-2026-40200`).

## Success criteria

1. A slim scanner image builds with no cvedb inside (image size drops by ~175 MB).
2. On startup it pulls, verifies, and loads the cvedb, then registers with the
   controller and reports the correct db version — matching today's behavior with
   a baked-in db.
3. Standalone mode acquires the db itself and scans successfully.
4. A pull or verification failure causes a non-zero exit (fail-closed), not a
   dbless scan.
5. Publishing a new vulndb artifact version makes a restarted scanner pick it up
   with no image rebuild.
