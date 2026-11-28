//go:build live

// Live, network-dependent diagnostics against the real cvedb artifact.
// Run explicitly: go test -tags live -run TestLive ./common/vulndb/ -v
package vulndb

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// TestLiveBundleVerify proves the new-format sigstore-bundle verification path.
func TestLiveBundleVerify(t *testing.T) {
	ctx := context.Background()
	cfg := liveCfg()
	digest, err := remoteSource{}.Digest(ctx, cfg)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	ref, _ := digestReference(cfg, digest)

	bundles, hash, err := cosign.GetBundles(ctx, ref, []ociremote.Option{
		ociremote.WithRemoteOptions(remote.WithContext(ctx)),
	})
	if err != nil {
		t.Fatalf("GetBundles: %v", err)
	}
	t.Logf("GetBundles returned %d bundles; signed hash=%s:%s", len(bundles), hash.Algorithm, hash.Hex)

	tr, err := root.FetchTrustedRoot()
	if err != nil {
		t.Fatalf("trusted root: %v", err)
	}
	sev, err := verify.NewSignedEntityVerifier(tr, verify.WithObserverTimestamps(1), verify.WithTransparencyLog(1))
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	certID, err := verify.NewShortCertificateIdentity(cfg.CertIssuer, "", cfg.CertSubject, "")
	if err != nil {
		t.Fatalf("cert identity: %v", err)
	}
	digestBytes, err := hex.DecodeString(hash.Hex)
	if err != nil {
		t.Fatalf("decode hash: %v", err)
	}
	policy := verify.NewPolicy(verify.WithArtifactDigest(hash.Algorithm, digestBytes), verify.WithCertificateIdentity(certID))

	verified := 0
	for i, b := range bundles {
		res, verr := sev.Verify(b, policy)
		if verr == nil {
			verified++
			t.Logf("bundle[%d] VERIFIED; identity=%+v", i, res.Signature)
		} else {
			t.Logf("bundle[%d] not verified: %v", i, verr)
		}
	}
	if verified == 0 {
		t.Fatalf("no bundle verified against pinned identity")
	}
	t.Logf("SUCCESS: %d/%d bundles verified", verified, len(bundles))
}

const liveRef = "ghcr.io/neuvector/vul/cvedb"
const liveTag = "latest"

func liveCfg() Config {
	return Config{
		ArtifactRef: liveRef,
		Version:     liveTag,
		Verify:      true,
		CertIssuer:  defaultCertIssuer,
		CertSubject: defaultCertSubject,
	}
}

// TestLiveReproduce reproduces the in-cluster failure path.
func TestLiveReproduce(t *testing.T) {
	cfg := liveCfg()
	digest, err := remoteSource{}.Digest(context.Background(), cfg)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	t.Logf("resolved digest: %s", digest)

	ref, _ := digestReference(cfg, digest)
	err = newKeylessVerifier().Verify(context.Background(), ref, cfg)
	t.Logf("current keylessVerifier.Verify err = %v", err)
}

// TestLiveVariants tries CheckOpts combinations to find one that discovers the
// signature stored under the referrers fallback tag.
func TestLiveVariants(t *testing.T) {
	ctx := context.Background()
	cfg := liveCfg()
	digest, err := remoteSource{}.Digest(ctx, cfg)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	ref, _ := digestReference(cfg, digest)
	tr, err := root.FetchTrustedRoot()
	if err != nil {
		t.Fatalf("trusted root: %v", err)
	}

	base := func() *cosign.CheckOpts {
		return &cosign.CheckOpts{
			TrustedMaterial: tr,
			ClaimVerifier:   cosign.SimpleClaimVerifier,
			Identities:      []cosign.Identity{{Issuer: cfg.CertIssuer, Subject: cfg.CertSubject}},
			RegistryClientOpts: []ociremote.Option{
				ociremote.WithRemoteOptions(remote.WithContext(ctx)),
			},
		}
	}

	variants := []struct {
		name  string
		mutfn func(*cosign.CheckOpts)
	}{
		{"experimentalOCI11", func(c *cosign.CheckOpts) { c.ExperimentalOCI11 = true }},
		{"plain", func(c *cosign.CheckOpts) {}},
	}
	for _, v := range variants {
		co := base()
		v.mutfn(co)
		sigs, _, err := cosign.VerifyImageSignatures(ctx, ref, co)
		t.Logf("variant %-18s -> sigs=%d err=%v", v.name, len(sigs), err)
	}
}

// TestLiveFallbackTag probes the referrers API vs the fallback tag directly.
func TestLiveFallbackTag(t *testing.T) {
	ctx := context.Background()
	cfg := liveCfg()
	digest, err := remoteSource{}.Digest(ctx, cfg)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	d, err := name.NewDigest(fmt.Sprintf("%s@%s", cfg.ArtifactRef, digest))
	if err != nil {
		t.Fatalf("parse digest ref: %v", err)
	}

	// Native referrers API.
	idx, err := remote.Referrers(d, remote.WithContext(ctx))
	if err != nil {
		t.Logf("remote.Referrers API err=%v", err)
	} else {
		im, _ := idx.IndexManifest()
		t.Logf("remote.Referrers API returned %d manifests", len(im.Manifests))
		for _, m := range im.Manifests {
			t.Logf("  api referrer: artifactType=%s digest=%s", m.ArtifactType, m.Digest)
		}
	}

	// Fallback tag sha256-<hex>.
	fb := d.Context().Tag("sha256-" + digest[len("sha256:"):])
	t.Logf("fallback tag: %s", fb.String())
	fbidx, err := remote.Index(fb, remote.WithContext(ctx))
	if err != nil {
		t.Logf("fallback tag Index err=%v", err)
		return
	}
	fbim, _ := fbidx.IndexManifest()
	t.Logf("fallback tag index has %d manifests", len(fbim.Manifests))
	for _, m := range fbim.Manifests {
		t.Logf("  fallback referrer: artifactType=%s digest=%s", m.ArtifactType, m.Digest)
	}
}
