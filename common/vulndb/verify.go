package vulndb

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	log "github.com/sirupsen/logrus"
)

// keylessVerifier verifies the cvedb artifact's cosign keyless signature
// in-process, pinning the signer identity (issuer + subject).
//
// The artifact is signed with the new sigstore bundle format
// (application/vnd.dev.sigstore.bundle.v0.3+json), stored as OCI 1.1 referrers
// (there is no legacy `.sig` tag). We therefore fetch the bundles with
// cosign.GetBundles and verify them with sigstore-go's SignedEntityVerifier,
// rather than cosign's legacy / artifactType-filtered image-signature paths
// (which do not discover these bundles).
//
// Trust material comes from sigstore-go's root.FetchTrustedRoot(), a separate
// trust path from cmd/sigstore-interface (whose embedded root is expired).
//
// NOTE: this is online-only. FetchTrustedRoot walks the live sigstore TUF CDN,
// and transparency-log verification contacts Rekor, so it needs network at
// startup and does not work air-gapped on the vendored root alone. It is
// fail-closed: unreachable TUF/Rekor or a non-matching identity fails
// verification, never bypasses it.
type keylessVerifier struct{}

func newKeylessVerifier() verifier { return keylessVerifier{} }

func (keylessVerifier) Verify(ctx context.Context, ref name.Reference, cfg Config) error {
	if cfg.CertIssuer == "" || cfg.CertSubject == "" {
		return fmt.Errorf("keyless verification requires both a certificate issuer and subject")
	}

	trustedRoot, err := root.FetchTrustedRoot()
	if err != nil {
		return fmt.Errorf("fetch sigstore trusted root: %w", err)
	}

	regOpts := []ociremote.Option{
		// Authenticate the signature fetch the same way as the layer pull.
		ociremote.WithRemoteOptions(remote.WithContext(ctx), authOption(cfg)),
	}

	bundles, hash, err := cosign.GetBundles(ctx, ref, regOpts)
	if err != nil {
		return fmt.Errorf("fetch signature bundles: %w", err)
	}
	if len(bundles) == 0 {
		return fmt.Errorf("no signature bundles found for %s", ref)
	}

	sev, err := verify.NewVerifier(trustedRoot,
		verify.WithObserverTimestamps(1),
		verify.WithTransparencyLog(1),
	)
	if err != nil {
		return fmt.Errorf("build signed-entity verifier: %w", err)
	}

	certID, err := verify.NewShortCertificateIdentity(cfg.CertIssuer, "", cfg.CertSubject, "")
	if err != nil {
		return fmt.Errorf("build certificate identity: %w", err)
	}

	digestBytes, err := hex.DecodeString(hash.Hex)
	if err != nil {
		return fmt.Errorf("decode artifact digest: %w", err)
	}
	policy := verify.NewPolicy(
		verify.WithArtifactDigest(hash.Algorithm, digestBytes),
		verify.WithCertificateIdentity(certID),
	)

	log.WithFields(log.Fields{
		"ref":     ref.String(),
		"issuer":  cfg.CertIssuer,
		"subject": cfg.CertSubject,
		"bundles": len(bundles),
	}).Info("verifying cvedb artifact signature")

	var lastErr error
	for _, b := range bundles {
		if _, err := sev.Verify(b, policy); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("no signature bundle matched the pinned identity: %w", lastErr)
}
