package vulndb

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tarEntry struct {
	name string
	body string
	dir  bool
}

func makeTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0600, Size: int64(len(e.body))}
		if e.dir {
			hdr.Typeflag = tar.TypeDir
			hdr.Mode = 0700
			hdr.Size = 0
		} else {
			hdr.Typeflag = tar.TypeReg
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if !e.dir {
			_, err := tw.Write([]byte(e.body))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	return buf.Bytes()
}

func TestExtractPayload(t *testing.T) {
	cases := []struct {
		name      string
		build     func(t *testing.T) []byte
		payload   string
		wantFound bool
		wantBody  string
	}{
		{
			name: "plain tar with db-prefixed payload",
			build: func(t *testing.T) []byte {
				return makeTar(t, []tarEntry{
					{name: "db/", dir: true},
					{name: "db/cvedb.regular", body: "DBDATA"},
					{name: "db/cvedb.version", body: "4.323"},
				})
			},
			payload:   "cvedb.regular",
			wantFound: true,
			wantBody:  "DBDATA",
		},
		{
			name: "payload at archive root",
			build: func(t *testing.T) []byte {
				return makeTar(t, []tarEntry{{name: "cvedb.regular", body: "ROOT"}})
			},
			payload:   "cvedb.regular",
			wantFound: true,
			wantBody:  "ROOT",
		},
		{
			name: "payload missing",
			build: func(t *testing.T) []byte {
				return makeTar(t, []tarEntry{{name: "db/other.file", body: "x"}})
			},
			payload:   "cvedb.regular",
			wantFound: false,
		},
		{
			name: "directory entry with matching base is skipped",
			build: func(t *testing.T) []byte {
				return makeTar(t, []tarEntry{
					{name: "db/cvedb.regular/", dir: true},
					{name: "db/cvedb.regular", body: "FILE"},
				})
			},
			payload:   "cvedb.regular",
			wantFound: true,
			wantBody:  "FILE",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "cvedb")
			found, err := extractPayload(bytes.NewReader(c.build(t)), c.payload, dest)
			require.NoError(t, err)
			assert.Equal(t, c.wantFound, found)
			if c.wantFound {
				got, err := os.ReadFile(dest)
				require.NoError(t, err)
				assert.Equal(t, c.wantBody, string(got))
			} else {
				_, statErr := os.Stat(dest)
				assert.True(t, os.IsNotExist(statErr), "dest file must not be created when payload missing")
			}
		})
	}
}

// TestInstallPayload exercises the full layer -> extract path against a real
// in-process OCI image (no network), covering the core of runtime acquisition.
func TestInstallPayload(t *testing.T) {
	cases := []struct {
		name     string
		layerTar []byte
		payload  string
		wantErr  bool
		wantBody string
	}{
		{
			name:     "single layer carrying the db payload",
			layerTar: makeTar(t, []tarEntry{{name: "db/cvedb.regular", body: "PAYLOAD"}}),
			payload:  "cvedb.regular",
			wantBody: "PAYLOAD",
		},
		{
			name:     "payload absent from layer",
			layerTar: makeTar(t, []tarEntry{{name: "db/nope", body: "x"}}),
			payload:  "cvedb.regular",
			wantErr:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			layerTar := c.layerTar
			layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(layerTar)), nil
			})
			require.NoError(t, err)
			img, err := mutate.AppendLayers(empty.Image, layer)
			require.NoError(t, err)

			dest := filepath.Join(t.TempDir(), "cvedb")
			err = installPayload(img, Config{PayloadName: c.payload, DestFile: dest})
			if c.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			got, err := os.ReadFile(dest)
			require.NoError(t, err)
			assert.Equal(t, c.wantBody, string(got))
		})
	}
}

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fakeSource struct {
	digest     string
	digestErr  error
	img        v1.Image
	imgErr     error
	imageCalls int
}

func (f *fakeSource) Digest(_ context.Context, _ Config) (string, error) {
	return f.digest, f.digestErr
}

func (f *fakeSource) Image(_ context.Context, _ Config, _ string) (v1.Image, error) {
	f.imageCalls++
	return f.img, f.imgErr
}

type fakeVerifier struct {
	err    error
	calls  int
	gotRef name.Reference
}

func (f *fakeVerifier) Verify(_ context.Context, ref name.Reference, _ Config) error {
	f.calls++
	f.gotRef = ref
	return f.err
}

func imageWithPayload(t *testing.T, body string) v1.Image {
	t.Helper()
	layerTar := makeTar(t, []tarEntry{{name: "db/" + share.RegularCVEDBName, body: body}})
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layerTar)), nil
	})
	require.NoError(t, err)
	img, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)
	return img
}

func baseAcquireConfig(dir string) Config {
	return Config{
		ArtifactRef:  "ghcr.io/neuvector/vul/cvedb",
		Version:      "latest",
		PayloadName:  share.RegularCVEDBName,
		DestFile:     filepath.Join(dir, share.DefaultCVEDBName),
		DigestMarker: filepath.Join(dir, digestMarkerName),
		Verify:       true,
		CertIssuer:   defaultCertIssuer,
		CertSubject:  defaultCertSubject,
	}
}

func TestAcquire(t *testing.T) {
	t.Run("happy path verifies, installs, and marks", func(t *testing.T) {
		dir := t.TempDir()
		cfg := baseAcquireConfig(dir)
		src := &fakeSource{digest: testDigest, img: imageWithPayload(t, "NEWDB")}
		v := &fakeVerifier{}

		changed, digest, err := acquire(context.Background(), cfg, src, v)
		require.NoError(t, err)
		assert.True(t, changed)
		assert.Equal(t, testDigest, digest)

		assert.Equal(t, 1, v.calls, "signature must be verified")
		require.NotNil(t, v.gotRef)
		assert.Equal(t, testDigest, v.gotRef.Identifier(), "verification must target the resolved digest")

		got, err := os.ReadFile(cfg.DestFile)
		require.NoError(t, err)
		assert.Equal(t, "NEWDB", string(got))

		marker, err := os.ReadFile(cfg.DigestMarker)
		require.NoError(t, err)
		assert.Contains(t, string(marker), testDigest)
	})

	t.Run("skips download when digest unchanged and dest exists", func(t *testing.T) {
		dir := t.TempDir()
		cfg := baseAcquireConfig(dir)
		require.NoError(t, os.WriteFile(cfg.DestFile, []byte("OLD"), 0644))
		require.NoError(t, writeMarker(cfg.DigestMarker, testDigest))

		src := &fakeSource{digest: testDigest, img: imageWithPayload(t, "NEWDB")}
		v := &fakeVerifier{}

		changed, digest, err := acquire(context.Background(), cfg, src, v)
		require.NoError(t, err)
		assert.False(t, changed)
		assert.Equal(t, testDigest, digest)
		assert.Equal(t, 0, v.calls, "no verification on skip")
		assert.Equal(t, 0, src.imageCalls, "no download on skip")

		got, err := os.ReadFile(cfg.DestFile)
		require.NoError(t, err)
		assert.Equal(t, "OLD", string(got), "existing db untouched")
	})

	t.Run("re-downloads when marker matches but dest missing", func(t *testing.T) {
		dir := t.TempDir()
		cfg := baseAcquireConfig(dir)
		require.NoError(t, writeMarker(cfg.DigestMarker, testDigest))

		src := &fakeSource{digest: testDigest, img: imageWithPayload(t, "NEWDB")}
		v := &fakeVerifier{}

		changed, _, err := acquire(context.Background(), cfg, src, v)
		require.NoError(t, err)
		assert.True(t, changed)
		assert.Equal(t, 1, src.imageCalls)
	})

	t.Run("verification failure aborts before install", func(t *testing.T) {
		dir := t.TempDir()
		cfg := baseAcquireConfig(dir)
		src := &fakeSource{digest: testDigest, img: imageWithPayload(t, "NEWDB")}
		v := &fakeVerifier{err: errors.New("bad signature")}

		changed, _, err := acquire(context.Background(), cfg, src, v)
		require.Error(t, err)
		assert.False(t, changed)
		assert.Equal(t, 0, src.imageCalls, "must not download an unverified artifact")
		_, statErr := os.Stat(cfg.DestFile)
		assert.True(t, os.IsNotExist(statErr), "nothing installed on verify failure")
	})

	t.Run("verification skipped when disabled", func(t *testing.T) {
		dir := t.TempDir()
		cfg := baseAcquireConfig(dir)
		cfg.Verify = false
		src := &fakeSource{digest: testDigest, img: imageWithPayload(t, "NEWDB")}
		v := &fakeVerifier{}

		changed, _, err := acquire(context.Background(), cfg, src, v)
		require.NoError(t, err)
		assert.True(t, changed)
		assert.Equal(t, 0, v.calls)
	})

	t.Run("digest resolution error is returned", func(t *testing.T) {
		dir := t.TempDir()
		cfg := baseAcquireConfig(dir)
		src := &fakeSource{digestErr: errors.New("resolve failed")}
		v := &fakeVerifier{}

		_, _, err := acquire(context.Background(), cfg, src, v)
		require.Error(t, err)
		assert.Equal(t, 0, v.calls)
	})
}

func TestConfigFromEnv(t *testing.T) {
	cases := []struct {
		name     string
		env      map[string]string
		wantErr  error
		assertFn func(t *testing.T, c Config)
	}{
		{
			name:    "disabled by default",
			env:     map[string]string{},
			wantErr: ErrPullDisabled,
		},
		{
			name: "enabled with defaults",
			env:  map[string]string{"SCANNER_CVEDB_PULL": "true"},
			assertFn: func(t *testing.T, c Config) {
				assert.Equal(t, defaultArtifactRef, c.ArtifactRef)
				assert.Equal(t, defaultVersion, c.Version)
				assert.Equal(t, share.RegularCVEDBName, c.PayloadName)
				assert.Equal(t, filepath.Join("/etc/neuvector/db", share.DefaultCVEDBName), c.DestFile)
				assert.True(t, c.Verify)
				assert.Equal(t, defaultCertIssuer, c.CertIssuer)
				assert.Equal(t, defaultCertSubject, c.CertSubject)
			},
		},
		{
			name: "overrides and skip-verify",
			env: map[string]string{
				"SCANNER_CVEDB_PULL":        "1",
				"SCANNER_CVEDB_ARTIFACT":    "registry.example.com/mirror/cvedb",
				"SCANNER_CVEDB_VERSION":     "4.999",
				"SCANNER_CVEDB_USERNAME":    "u",
				"SCANNER_CVEDB_PASSWORD":    "p",
				"SCANNER_CVEDB_SKIP_VERIFY": "true",
			},
			assertFn: func(t *testing.T, c Config) {
				assert.Equal(t, "registry.example.com/mirror/cvedb", c.ArtifactRef)
				assert.Equal(t, "4.999", c.Version)
				assert.Equal(t, "u", c.Username)
				assert.Equal(t, "p", c.Password)
				assert.False(t, c.Verify)
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			cfg, err := ConfigFromEnv("/etc/neuvector/db")
			if c.wantErr != nil {
				require.ErrorIs(t, err, c.wantErr)
				return
			}
			require.NoError(t, err)
			c.assertFn(t, cfg)
		})
	}
}

func TestDigestMarker(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, digestMarkerName)
	cfg := Config{DigestMarker: marker}
	const digest = "sha256:abc123"

	assert.False(t, digestUnchanged(cfg, digest), "no marker file yet")

	require.NoError(t, writeMarker(marker, digest))
	assert.True(t, digestUnchanged(cfg, digest), "marker matches")
	assert.False(t, digestUnchanged(cfg, "sha256:different"), "marker mismatch")
}

func TestWriteAtomic(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "nested", "cvedb")
	require.NoError(t, writeAtomic(dest, io.NopCloser(bytes.NewReader([]byte("content")))))

	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "content", string(got))

	// No leftover temp files in the directory.
	entries, err := os.ReadDir(filepath.Dir(dest))
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}
