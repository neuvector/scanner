# Acquire the cvedb at runtime from the OCI artifact instead of baking it into the scanner image

**Status:** proposed

The scanner image today bakes a ~175 MB **cvedb** in at build time, which forces a full image rebuild and re-release every time the far-more-volatile vulnerability data changes, and makes the scanner's version track the db's. We will instead ship a **slim scanner image** with no **baked-in db** and have the scanner pull the already-published, cosign-signed **vulndb artifact** (`ghcr.io/<owner>/vul/cvedb`) at startup, verify it, and write it to `/etc/neuvector/db/cvedb` before loading. Because scanner pods restart daily, a startup pull naturally refreshes the db daily without a new image.

## Considered Options

- **Keep a stale baked-in db as a fallback** — rejected for the experiment: it would mask pull/verify failures and muddy what we are measuring. Air-gap is handled separately via a configurable registry/mirror and pinned version, not a fallback.
- **Deliver the db to the scanner via the controller** — rejected: the gRPC flow is scanner → controller (the scanner is the *source*); no RPC delivers a db *to* the scanner, so this would require new controller-side work in another repo.
- **Pull via an init container into a shared volume** — deferred: likely the production shape, but it requires Helm/chart changes in another repo. In-process pull keeps the experiment within this repo and unifies standalone and orchestrated mode on one code path.

## Consequences

- The scanner gains a **new runtime dependency** on an OCI registry (default `ghcr.io`, configurable) and on sigstore infrastructure (Rekor / TUF trust root) for keyless signature verification. The deployment is **fail-closed**: on pull or verify failure the scanner retries with bounded backoff, then exits non-zero and lets the orchestrator restart it.
- The build-time coupling of scanner version to db version is removed (Makefile, Dockerfile `ARG VULNDB_VERSION`, `neuvector.vuln_db` label). The db version is reported at runtime from the extracted db's own version file, which already happens.
- In-process keyless verification uses `sigstore-go`'s `root.FetchTrustedRoot()`, a separate trust path from `cmd/sigstore-interface` (whose embedded root is expired, 2024). This path is online-only: it walks the live sigstore TUF CDN and Rekor at startup (the vendored bootstrap root is itself expired, 2026-06-22), so it is fail-closed but not air-gap-capable on the vendored root alone. An offline/air-gap deployment needs a pinned `trusted_root.json` or a private key-based root — deferred.
- The artifact's signatures are new-format sigstore bundles stored as OCI 1.1 referrers (no legacy `.sig` tag). cosign's legacy / `ExperimentalOCI11` image-signature discovery does not find them and vendored cosign v3.0.6 has no bundle image-signature path, so verification uses `cosign.GetBundles` + `sigstore-go`'s `verify.Verifier` directly. This couples us to that discovery shape; if the signing pipeline reverts to classic `.sig` tags, the verifier must adapt. Confirmed working end-to-end in-cluster.
