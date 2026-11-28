package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	//nolint:staticcheck // SA1019: the code under test uses the deprecated github.com/sigstore/sigstore/pkg/tuf types (forced by cosign v3's public API); remove once cosign migrates to sigstore-go/pkg/tuf.
	sigtuf "github.com/sigstore/sigstore/pkg/tuf"
	tuf "github.com/theupdateframework/go-tuf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTarget describes a single target to publish into the throwaway TUF repo.
type testTarget struct {
	name    string
	content []byte
	custom  json.RawMessage // nil => target published without custom metadata
}

// sigstoreCustom builds the sigstore custom-metadata JSON that
// GetSigstorePublicTufTargets parses, e.g. {"sigstore":{"usage":"Rekor","status":"Active"}}.
func sigstoreCustom(t *testing.T, usage sigtuf.UsageKind, status sigtuf.StatusKind) json.RawMessage {
	t.Helper()
	type cm struct {
		Usage  sigtuf.UsageKind  `json:"usage"`
		Status sigtuf.StatusKind `json:"status"`
	}
	type scm struct {
		Sigstore cm `json:"sigstore"`
	}
	b, err := json.Marshal(scm{Sigstore: cm{Usage: usage, Status: status}})
	require.NoError(t, err)
	return b
}

// newTestTufRepo builds a self-contained, consistent-snapshot TUF repo serving the
// given targets and returns an HTTPS test server plus its trusted root.json bytes.
//
// The repo is generated fresh per test run (so default metadata expiry is never a
// time-bomb) using go-tuf v1 as an independent fixture builder; this exercises the
// production code path the same way across the go-tuf v1->v2 client migration.
func newTestTufRepo(t *testing.T, targets []testTarget) (*httptest.Server, []byte) {
	t.Helper()
	td := t.TempDir()
	remote := tuf.FileSystemStore(td, nil)
	r, err := tuf.NewRepo(remote)
	require.NoError(t, err)
	require.NoError(t, r.Init(true)) // consistent snapshot, matches the production updater config

	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		_, err := r.GenKey(role)
		require.NoError(t, err)
	}

	stagedTargets := filepath.Join(td, "staged", "targets")
	require.NoError(t, os.MkdirAll(stagedTargets, 0o755))
	for _, tgt := range targets {
		require.NoError(t, os.WriteFile(filepath.Join(stagedTargets, tgt.name), tgt.content, 0o600))
		require.NoError(t, r.AddTarget(tgt.name, tgt.custom))
	}

	require.NoError(t, r.Snapshot())
	require.NoError(t, r.Timestamp())
	require.NoError(t, r.Commit())

	server := httptest.NewTLSServer(http.FileServer(http.Dir(filepath.Join(td, "repository"))))
	t.Cleanup(server.Close)

	meta, err := remote.GetMeta()
	require.NoError(t, err)
	rootBytes, ok := meta["root.json"]
	require.True(t, ok, "generated repo must contain root.json")

	return server, rootBytes
}

// TestGetSigstorePublicTufTargets is a hermetic characterization test for the TUF
// target retrieval. It pins the observable behavior (per-usage filtering, status
// propagation, downloaded bytes, and skipping of targets without/with invalid
// custom metadata) so it must stay green across the go-tuf v1->v2 client swap.
//
// Serving over httptest.NewTLSServer (self-signed cert) also exercises the
// InsecureSkipVerify transport path used when no proxy is configured.
func TestGetSigstorePublicTufTargets(t *testing.T) {
	rekorActive := []byte("rekor-active-key")
	rekorExpired := []byte("rekor-expired-key")
	fulcioActive := []byte("fulcio-active-cert")
	ctfeActive := []byte("ctfe-active-key")

	targets := []testTarget{
		{name: "rekor.pub", content: rekorActive, custom: sigstoreCustom(t, sigtuf.Rekor, sigtuf.Active)},
		{name: "rekor-old.pub", content: rekorExpired, custom: sigstoreCustom(t, sigtuf.Rekor, sigtuf.Expired)},
		{name: "fulcio.crt.pem", content: fulcioActive, custom: sigstoreCustom(t, sigtuf.Fulcio, sigtuf.Active)},
		{name: "ctfe.pub", content: ctfeActive, custom: sigstoreCustom(t, sigtuf.CTFE, sigtuf.Active)},
		{name: "no-custom.txt", content: []byte("ignored-no-custom"), custom: nil},
		{name: "bad-custom.txt", content: []byte("ignored-bad-custom"),
			custom: json.RawMessage(`{"sigstore":{"usage":"not-a-real-usage","status":"Active"}}`)},
	}

	server, rootBytes := newTestTufRepo(t, targets)

	type target struct {
		content []byte
		status  sigtuf.StatusKind
	}
	cases := []struct {
		name  string
		usage sigtuf.UsageKind
		want  []target
	}{
		{
			name:  "rekor returns both active and expired",
			usage: sigtuf.Rekor,
			want: []target{
				{content: rekorActive, status: sigtuf.Active},
				{content: rekorExpired, status: sigtuf.Expired},
			},
		},
		{
			name:  "fulcio returns active only",
			usage: sigtuf.Fulcio,
			want:  []target{{content: fulcioActive, status: sigtuf.Active}},
		},
		{
			name:  "ctfe returns active only",
			usage: sigtuf.CTFE,
			want:  []target{{content: ctfeActive, status: sigtuf.Active}},
		},
		{
			name:  "unused usage returns nothing",
			usage: sigtuf.TSA,
			want:  nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := getSigstorePublicTufTargets(c.usage, Proxy{}, server.URL, rootBytes)
			require.NoError(t, err)
			require.Len(t, got, len(c.want))

			// Compare order-independently on (content, status).
			type key struct {
				content string
				status  sigtuf.StatusKind
			}
			gotSet := map[key]int{}
			for _, g := range got {
				gotSet[key{string(g.Target), g.Status}]++
			}
			for _, w := range c.want {
				assert.Positive(t, gotSet[key{string(w.content), w.status}],
					"expected target (content=%q, status=%s) not returned", w.content, w.status)
			}
		})
	}
}
