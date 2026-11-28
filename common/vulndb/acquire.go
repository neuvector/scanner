// Package vulndb acquires the cvedb (vulnerability database) at runtime from a
// cosign-signed OCI artifact, so the scanner image no longer has to bake it in.
// See docs/decoupled-cvedb-experiment.md.
package vulndb

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
)

// Default artifact coordinates and signer identity. These mirror
// scripts/ghcr-vulndb-artifact.sh and .github/workflows/release.yml.
const (
	defaultArtifactRef = "ghcr.io/neuvector/vul/cvedb"
	defaultVersion     = "latest"
	defaultCertIssuer  = "https://token.actions.githubusercontent.com"
	defaultCertSubject = "https://github.com/neuvector/release/.github/workflows/build-vuldbgen.yaml@refs/heads/master"

	digestMarkerName = "cvedb.digest"
)

// ErrPullDisabled is returned by ConfigFromEnv when runtime acquisition is not enabled.
var ErrPullDisabled = errors.New("cvedb runtime acquisition is not enabled")

// Config describes a single cvedb acquisition.
type Config struct {
	// ArtifactRef is the OCI repository (no tag), e.g. ghcr.io/neuvector/vul/cvedb.
	ArtifactRef string
	// Version is the tag to resolve, e.g. "latest" or "4.323".
	Version string
	// Username and Password are optional registry credentials; empty means anonymous.
	Username string
	Password string
	// PayloadName is the file inside the artifact's db/ directory to extract (cvedb.regular).
	PayloadName string
	// DestFile is where the extracted payload is written (/etc/neuvector/db/cvedb).
	DestFile string
	// DigestMarker records the digest of the last successfully installed artifact,
	// used to skip re-downloading an unchanged db.
	DigestMarker string
	// Verify enables cosign keyless signature verification before install.
	Verify bool
	// CertIssuer and CertSubject pin the keyless signer identity.
	CertIssuer  string
	CertSubject string
}

// ConfigFromEnv builds a Config from environment variables, defaulting to the
// published neuvector artifact. dbPath is the directory the scanner loads the db
// from (e.g. /etc/neuvector/db/). It returns ErrPullDisabled unless
// SCANNER_CVEDB_PULL is truthy, so existing (non-slim) images are unaffected.
func ConfigFromEnv(dbPath string) (Config, error) {
	if !truthy(os.Getenv("SCANNER_CVEDB_PULL")) {
		return Config{}, ErrPullDisabled
	}

	return Config{
		ArtifactRef:  envOr("SCANNER_CVEDB_ARTIFACT", defaultArtifactRef),
		Version:      envOr("SCANNER_CVEDB_VERSION", defaultVersion),
		Username:     os.Getenv("SCANNER_CVEDB_USERNAME"),
		Password:     os.Getenv("SCANNER_CVEDB_PASSWORD"),
		PayloadName:  share.RegularCVEDBName,
		DestFile:     filepath.Join(dbPath, share.DefaultCVEDBName),
		DigestMarker: filepath.Join(dbPath, digestMarkerName),
		Verify:       !truthy(os.Getenv("SCANNER_CVEDB_SKIP_VERIFY")),
		CertIssuer:   envOr("SCANNER_CVEDB_CERT_ISSUER", defaultCertIssuer),
		CertSubject:  envOr("SCANNER_CVEDB_CERT_IDENTITY", defaultCertSubject),
	}, nil
}

// verifier verifies a cosign keyless signature over the artifact at ref@digest.
// It is an interface so tests can substitute a fake. The production
// implementation lives in verify.go.
type verifier interface {
	Verify(ctx context.Context, ref name.Reference, cfg Config) error
}

// registrySource resolves and fetches the artifact. It is an interface so the
// acquisition orchestration can be unit-tested without a live registry.
type registrySource interface {
	// Digest resolves the configured tag to its manifest digest.
	Digest(ctx context.Context, cfg Config) (string, error)
	// Image fetches the artifact image pinned to digest.
	Image(ctx context.Context, cfg Config, digest string) (v1.Image, error)
}

// Acquire resolves the artifact, optionally verifies its signature, and installs
// the payload to cfg.DestFile. It returns whether the on-disk db changed and the
// resolved manifest digest. If the resolved digest already matches the marker and
// the destination exists, it skips the download (and verification).
func Acquire(ctx context.Context, cfg Config) (changed bool, digest string, err error) {
	return acquire(ctx, cfg, remoteSource{}, newKeylessVerifier())
}

func acquire(ctx context.Context, cfg Config, src registrySource, v verifier) (bool, string, error) {
	digest, err := src.Digest(ctx, cfg)
	if err != nil {
		return false, "", err
	}

	if cfg.DestFile != "" && digestUnchanged(cfg, digest) {
		if _, statErr := os.Stat(cfg.DestFile); statErr == nil {
			log.WithFields(log.Fields{"digest": digest}).Info("cvedb unchanged, skipping download")
			return false, digest, nil
		}
	}

	if cfg.Verify {
		ref, err := digestReference(cfg, digest)
		if err != nil {
			return false, digest, err
		}
		if err := v.Verify(ctx, ref, cfg); err != nil {
			return false, digest, fmt.Errorf("verify %s: %w", ref, err)
		}
	} else {
		log.Warn("cvedb signature verification is disabled")
	}

	img, err := src.Image(ctx, cfg, digest)
	if err != nil {
		return false, digest, err
	}

	if err := installPayload(img, cfg); err != nil {
		return false, digest, err
	}

	if err := writeMarker(cfg.DigestMarker, digest); err != nil {
		// Non-fatal: a missing marker only costs a redundant download next start.
		log.WithFields(log.Fields{"error": err}).Warn("failed to write cvedb digest marker")
	}

	log.WithFields(log.Fields{"digest": digest, "ref": cfg.ArtifactRef, "version": cfg.Version}).Info("cvedb installed")
	return true, digest, nil
}

// remoteSource is the production registrySource backed by go-containerregistry.
type remoteSource struct{}

func (remoteSource) Digest(ctx context.Context, cfg Config) (string, error) {
	tagRef, err := name.NewTag(fmt.Sprintf("%s:%s", cfg.ArtifactRef, cfg.Version))
	if err != nil {
		return "", fmt.Errorf("invalid artifact reference %q: %w", cfg.ArtifactRef, err)
	}
	desc, err := remote.Get(tagRef, remoteOptions(ctx, cfg)...)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", tagRef, err)
	}
	return desc.Digest.String(), nil
}

func (remoteSource) Image(ctx context.Context, cfg Config, digest string) (v1.Image, error) {
	ref, err := digestReference(cfg, digest)
	if err != nil {
		return nil, err
	}
	img, err := remote.Image(ref, remoteOptions(ctx, cfg)...)
	if err != nil {
		return nil, fmt.Errorf("pull %s: %w", ref, err)
	}
	return img, nil
}

// digestReference builds a digest-pinned reference for the configured artifact.
func digestReference(cfg Config, digest string) (name.Reference, error) {
	tagRef, err := name.NewTag(fmt.Sprintf("%s:%s", cfg.ArtifactRef, cfg.Version))
	if err != nil {
		return nil, fmt.Errorf("invalid artifact reference %q: %w", cfg.ArtifactRef, err)
	}
	return tagRef.Digest(digest), nil
}

// authOption returns the registry auth option for cfg: basic auth when
// credentials are supplied, otherwise the default keychain (anonymous pull).
// Shared by the layer pull and the cosign signature fetch so both authenticate
// identically against a private registry/mirror.
func authOption(cfg Config) remote.Option {
	if cfg.Username != "" || cfg.Password != "" {
		return remote.WithAuth(&authn.Basic{
			Username: cfg.Username,
			Password: cfg.Password,
		})
	}
	return remote.WithAuthFromKeychain(authn.DefaultKeychain)
}

func remoteOptions(ctx context.Context, cfg Config) []remote.Option {
	return []remote.Option{remote.WithContext(ctx), authOption(cfg)}
}

// installPayload extracts cfg.PayloadName from the artifact's single layer and
// writes it atomically to cfg.DestFile.
func installPayload(img v1.Image, cfg Config) error {
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("read layers: %w", err)
	}
	if len(layers) == 0 {
		return errors.New("artifact has no layers")
	}

	for _, layer := range layers {
		rc, err := layer.Uncompressed()
		if err != nil {
			return fmt.Errorf("open layer: %w", err)
		}

		found, err := func() (bool, error) {
			defer rc.Close()
			return extractPayload(rc, cfg.PayloadName, cfg.DestFile)
		}()
		if err != nil {
			return err
		}
		if found {
			return nil
		}
	}

	return fmt.Errorf("payload %q not found in artifact", cfg.PayloadName)
}

// extractPayload reads the (already de-gzipped) tar stream from a layer's
// Uncompressed() reader and writes the entry whose base name matches payloadName
// to destFile atomically. It returns whether the payload was found. It is pure
// and unit-tested.
func extractPayload(r io.Reader, payloadName, destFile string) (bool, error) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("read tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if filepath.Base(hdr.Name) != payloadName {
			continue
		}
		if err := writeAtomic(destFile, tr); err != nil {
			return false, err
		}
		return true, nil
	}
}

func writeAtomic(destFile string, r io.Reader) error {
	if dir := filepath.Dir(destFile); dir != "" {
		if err := os.MkdirAll(dir, 0760); err != nil {
			return fmt.Errorf("create dir %s: %w", dir, err)
		}
	}

	tmp, err := os.CreateTemp(filepath.Dir(destFile), "cvedb-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Best-effort cleanup if we failed before the rename.
		if _, statErr := os.Stat(tmpName); statErr == nil {
			_ = os.Remove(tmpName)
		}
	}()

	// Defense-in-depth against a decompression bomb. The signed artifact is
	// verified before extraction, so this is a backstop; the cvedb is ~175 MB.
	const maxPayloadBytes = 4 << 30 // 4 GiB
	n, err := io.Copy(tmp, io.LimitReader(r, maxPayloadBytes+1))
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if n > maxPayloadBytes {
		_ = tmp.Close()
		return fmt.Errorf("payload exceeds %d-byte safety cap", maxPayloadBytes)
	}
	// Match the readable perms the baked-in db had (installed via cp), rather
	// than CreateTemp's 0600, in case a different uid reads it.
	if err := tmp.Chmod(0644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, destFile); err != nil {
		return fmt.Errorf("install %s: %w", destFile, err)
	}
	return nil
}

func digestUnchanged(cfg Config, digest string) bool {
	if cfg.DigestMarker == "" {
		return false
	}
	b, err := os.ReadFile(cfg.DigestMarker)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == digest
}

func writeMarker(path, digest string) error {
	if path == "" {
		return nil
	}
	return os.WriteFile(path, []byte(digest+"\n"), 0644)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func truthy(v string) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	return err == nil && b
}
