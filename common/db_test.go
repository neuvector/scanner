package common

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/neuvector/neuvector/share"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	files      = append([]string(nil), fileList[1:]...)
	defaultVer = "1.000"
	wrongKey   = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	fakeTime   = time.Date(2025, 12, 12, 0, 0, 0, 0, time.UTC)
	mockTime   = time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)
)

// CreateMinimalFakeCveDb creates a minimal fake CVE database
func CreateMinimalFakeCveDb(dbFile, version string, encryptKey []byte, timestamp time.Time) error {
	tarBuf, fileShas, err := createMinimalTarArchive(timestamp)
	if err != nil {
		return fmt.Errorf("create tar archive: %v", err)
	}

	encryptedData, err := encryptData(tarBuf.Bytes(), encryptKey)
	if err != nil {
		return fmt.Errorf("encrypt tar: %v", err)
	}

	keyVer := KeyVersion{
		Version:    version,
		UpdateTime: timestamp.Format(time.RFC3339),
		Keys:       map[string]string{},
		Shas:       fileShas,
	}

	headerJSON, err := json.Marshal(keyVer)
	if err != nil {
		return fmt.Errorf("marshal key version: %v", err)
	}

	var finalBuf bytes.Buffer

	headerLen := int32(len(headerJSON))
	if err := binary.Write(&finalBuf, binary.BigEndian, headerLen); err != nil {
		return fmt.Errorf("write header length: %v", err)
	}

	finalBuf.Write(headerJSON)
	finalBuf.Write(encryptedData)

	return os.WriteFile(dbFile, finalBuf.Bytes(), 0644)
}

func createMinimalTarArchive(timestamp time.Time) (*bytes.Buffer, map[string]string, error) {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	defer tw.Close()

	fileShas := make(map[string]string)

	for _, filename := range files {
		var content []byte
		if filename == "rhel-cpe.map" {
			content = []byte("# RHEL CPE Map\n")
		} else {
			content = []byte("")
		}

		sha := sha256.Sum256(content)
		fileShas[filename] = fmt.Sprintf("%x", sha)

		header := &tar.Header{
			Name:    filename,
			Mode:    0644,
			Size:    int64(len(content)),
			ModTime: timestamp,
		}

		if err := tw.WriteHeader(header); err != nil {
			return nil, nil, err
		}

		if _, err := tw.Write(content); err != nil {
			return nil, nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, nil, err
	}

	return &tarBuf, fileShas, nil
}

// encryptData encrypts data using AES-GCM
func encryptData(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func prepareMockDbPaths(t *testing.T, encryptKey []byte, timestamp time.Time) (string, string) {
	t.Helper()
	dbRoot := t.TempDir()
	expandRoot := t.TempDir()
	dbPath := dbRoot + string(filepath.Separator)
	dbFile := filepath.Join(dbRoot, "cvedb")
	require.NoError(t, CreateMinimalFakeCveDb(dbFile, defaultVer, encryptKey, mockTime))
	return dbPath, expandRoot
}

func TestLoadCveDB(t *testing.T) {
	testCases := []struct {
		name        string
		setupFunc   func(t *testing.T) (dbPath, expandPath string)
		expectErr   error
		expectedVer string
		timestamp   time.Time
	}{
		{
			name: "db file not exist, expand path not exist",
			setupFunc: func(t *testing.T) (string, string) {
				return "not_exist/", t.TempDir()
			},
			expectErr: errors.New("read db file fail: open not_exist/cvedb: no such file or directory"),
		},
		{
			name: "db file exist, expand path not exist (first load)",
			setupFunc: func(t *testing.T) (string, string) {
				return prepareMockDbPaths(t, GetCVEDBEncryptKey(), mockTime)
			},
			expectedVer: defaultVer,
			timestamp:   mockTime,
		},
		{
			name: "db file exist, expand path exist with same version",
			setupFunc: func(t *testing.T) (string, string) {
				dbPath, expandPath := prepareMockDbPaths(t, GetCVEDBEncryptKey(), mockTime)
				// First load to expand the DB
				_, _, err := LoadCveDb(dbPath, expandPath, GetCVEDBEncryptKey())
				require.NoError(t, err)
				return dbPath, expandPath
			},
			expectedVer: defaultVer,
			timestamp:   mockTime,
		},
		{
			name: "db file exist with newer version",
			setupFunc: func(t *testing.T) (string, string) {
				// Create old expanded DB
				dbRoot1 := t.TempDir()
				expandPath := t.TempDir()
				dbPath1 := dbRoot1 + string(filepath.Separator)
				dbFile1 := filepath.Join(dbRoot1, "cvedb")
				require.NoError(t, CreateMinimalFakeCveDb(dbFile1, defaultVer, GetCVEDBEncryptKey(), mockTime))
				_, _, err := LoadCveDb(dbPath1, expandPath, GetCVEDBEncryptKey())
				require.NoError(t, err)

				// Create new DB with higher version
				dbRoot2 := t.TempDir()
				dbPath2 := dbRoot2 + string(filepath.Separator)
				dbFile2 := filepath.Join(dbRoot2, "cvedb")
				require.NoError(t, CreateMinimalFakeCveDb(dbFile2, "2.000", GetCVEDBEncryptKey(), mockTime))

				return dbPath2, expandPath
			},
			expectedVer: "2.000",
			timestamp:   mockTime,
		},
		{
			name: "invalid expand path (permission error)",
			setupFunc: func(t *testing.T) (string, string) {
				dbRoot := t.TempDir()
				dbPath := dbRoot + string(filepath.Separator)
				dbFile := filepath.Join(dbRoot, "cvedb")
				require.NoError(t, CreateMinimalFakeCveDb(dbFile, "1.000", GetCVEDBEncryptKey(), mockTime))
				return dbPath, "/dev/null/invalid"
			},
			expectErr: &fs.PathError{
				Op:   "open",
				Path: "/dev/null/invalidkeys",
				Err:  syscall.ENOTDIR,
			},
			timestamp: mockTime,
		},
		{
			name: "wrong encryption key",
			setupFunc: func(t *testing.T) (string, string) {
				return prepareMockDbPaths(t, wrongKey, fakeTime)
			},
			expectErr: errors.New("cipher: message authentication failed"),
			timestamp: fakeTime,
		},
		{
			name: "db with older version than expanded (use newer version)",
			setupFunc: func(t *testing.T) (string, string) {
				// Create new expanded DB (v2.0)
				dbRoot1 := t.TempDir()
				expandPath := t.TempDir()
				dbPath1 := dbRoot1 + string(filepath.Separator)
				dbFile1 := filepath.Join(dbRoot1, "cvedb")
				require.NoError(t, CreateMinimalFakeCveDb(dbFile1, "2.000", GetCVEDBEncryptKey(), mockTime))
				_, _, err := LoadCveDb(dbPath1, expandPath, GetCVEDBEncryptKey())
				require.NoError(t, err)

				// Create DB with lower version (v1.0)
				dbRoot2 := t.TempDir()
				dbPath2 := dbRoot2 + string(filepath.Separator)
				dbFile2 := filepath.Join(dbRoot2, "cvedb")
				require.NoError(t, CreateMinimalFakeCveDb(dbFile2, defaultVer, GetCVEDBEncryptKey(), mockTime))

				return dbPath2, expandPath
			},
			expectedVer: "2.000",
			timestamp:   mockTime,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dbPath, expandPath := tc.setupFunc(t)
			log.Info("Running testCase: ", tc.name)

			version, updateTime, err := LoadCveDb(dbPath, expandPath, GetCVEDBEncryptKey())
			require.Equal(t, tc.expectErr, err)

			if tc.expectErr == nil {
				require.Equal(t, tc.expectedVer, version)
				require.Equal(t, tc.timestamp.Format(time.RFC3339), updateTime)
			}
		})
	}
}

// writeTBLines writes NDJSON lines to path/name for use as a _full.tb or apps.tb fixture.
func writeTBLines(t *testing.T, dir, name string, lines []string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	require.NoError(t, err)
	defer f.Close()
	for _, line := range lines {
		_, err := fmt.Fprintln(f, line)
		require.NoError(t, err)
	}
}

func vulLine(name, ns, sev string) string {
	v := VulFull{Name: name, Namespace: ns, Severity: sev}
	b, _ := json.Marshal(v)
	return string(b)
}

func appLine(vulName, severity string) string {
	v := AppModuleVul{VulName: vulName, Severity: severity}
	b, _ := json.Marshal(v)
	return string(b)
}

func TestCountCveDbEntries(t *testing.T) {
	cases := []struct {
		name  string
		setup func(dir string)
		want  int
	}{
		{
			name:  "empty directory",
			setup: func(dir string) {},
			want:  0,
		},
		{
			name: "single OS file two entries",
			setup: func(dir string) {
				writeTBLines(t, dir, "ubuntu_full.tb", []string{
					vulLine("CVE-1", "ubuntu:22.04", "High"),
					vulLine("CVE-2", "ubuntu:22.04", "Medium"),
				})
			},
			want: 2,
		},
		{
			name: "same name in same OS file is deduplicated",
			setup: func(dir string) {
				writeTBLines(t, dir, "ubuntu_full.tb", []string{
					vulLine("CVE-1", "ubuntu:22.04", "High"),
					vulLine("CVE-1", "ubuntu:focal", "Low"), // different namespace, same osname key
				})
			},
			want: 1,
		},
		{
			name: "ubuntu upstream uses shared key across files",
			setup: func(dir string) {
				writeTBLines(t, dir, "ubuntu_full.tb", []string{
					vulLine("CVE-1", "ubuntu:upstream", "High"),
				})
				writeTBLines(t, dir, "debian_full.tb", []string{
					vulLine("CVE-1", "ubuntu:upstream", "High"), // same upstream key, deduplicated
					vulLine("CVE-2", "debian:11", "Low"),
				})
			},
			want: 2, // upstream:CVE-1, debian:CVE-2
		},
		{
			name: "apps entries counted",
			setup: func(dir string) {
				writeTBLines(t, dir, "apps.tb", []string{
					appLine("CVE-A", "High"),
					appLine("CVE-B", "Low"),
				})
			},
			want: 2,
		},
		{
			name: "mixed OS and apps",
			setup: func(dir string) {
				writeTBLines(t, dir, "ubuntu_full.tb", []string{
					vulLine("CVE-1", "ubuntu:22.04", "High"),
				})
				writeTBLines(t, dir, "debian_full.tb", []string{
					vulLine("CVE-2", "debian:11", "Medium"),
				})
				writeTBLines(t, dir, "apps.tb", []string{
					appLine("CVE-A", "Low"),
				})
			},
			want: 3,
		},
		{
			name: "invalid JSON lines skipped",
			setup: func(dir string) {
				writeTBLines(t, dir, "ubuntu_full.tb", []string{
					vulLine("CVE-1", "ubuntu:22.04", "High"),
					"not-valid-json",
					vulLine("CVE-2", "ubuntu:22.04", "Low"),
				})
			},
			want: 2,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			c.setup(dir)
			got, err := CountCveDbEntries(dir + "/")
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestStreamCveDbBatches(t *testing.T) {
	cases := []struct {
		name      string
		setup     func(dir string)
		batchSize int
		wantCount int
	}{
		{
			name:      "empty directory calls fn once with isLast",
			setup:     func(dir string) {},
			batchSize: 10,
			wantCount: 0,
		},
		{
			name: "fewer entries than batch size",
			setup: func(dir string) {
				writeTBLines(t, dir, "ubuntu_full.tb", []string{
					vulLine("CVE-1", "ubuntu:22.04", "High"),
				})
			},
			batchSize: 10,
			wantCount: 1,
		},
		{
			name: "multiple full batches plus remainder",
			setup: func(dir string) {
				lines := make([]string, 5)
				for i := range lines {
					lines[i] = vulLine(fmt.Sprintf("CVE-%d", i+1), "ubuntu:22.04", "High")
				}
				writeTBLines(t, dir, "ubuntu_full.tb", lines)
			},
			batchSize: 2,
			wantCount: 5,
		},
		{
			name: "mixed OS and apps across batches",
			setup: func(dir string) {
				writeTBLines(t, dir, "ubuntu_full.tb", []string{
					vulLine("CVE-1", "ubuntu:22.04", "High"),
					vulLine("CVE-2", "ubuntu:22.04", "Medium"),
				})
				writeTBLines(t, dir, "apps.tb", []string{
					appLine("CVE-A", "Low"),
				})
			},
			batchSize: 2,
			wantCount: 3,
		},
		{
			name: "deduplication across files",
			setup: func(dir string) {
				writeTBLines(t, dir, "ubuntu_full.tb", []string{
					vulLine("CVE-1", "ubuntu:upstream", "High"),
				})
				writeTBLines(t, dir, "debian_full.tb", []string{
					vulLine("CVE-1", "ubuntu:upstream", "High"), // duplicate via upstream key
				})
			},
			batchSize: 10,
			wantCount: 1,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			c.setup(dir)

			var lastCount int
			collected := make(map[string]*share.ScanVulnerability)

			err := StreamCveDbBatches(dir+"/", c.batchSize, func(batch map[string]*share.ScanVulnerability, isLast bool) error {
				if isLast {
					lastCount++
				} else {
					assert.Equal(t, c.batchSize, len(batch), "non-last batch must be exactly batchSize")
				}
				for k, v := range batch {
					collected[k] = v
				}
				return nil
			})

			require.NoError(t, err)
			assert.Equal(t, 1, lastCount, "isLast must be signaled exactly once")
			assert.Equal(t, c.wantCount, len(collected))

			// count and stream must agree
			count, err := CountCveDbEntries(dir + "/")
			require.NoError(t, err)
			assert.Equal(t, count, len(collected))
		})
	}
}
