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

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var (
	files = []string{
		"ubuntu_index.tb",
		"ubuntu_full.tb",
		"debian_index.tb",
		"debian_full.tb",
		"centos_index.tb",
		"centos_full.tb",
		"alpine_index.tb",
		"alpine_full.tb",
		"amazon_index.tb",
		"amazon_full.tb",
		"mariner_full.tb",
		"mariner_index.tb",
		"photon_full.tb",
		"photon_index.tb",
		"oracle_index.tb",
		"oracle_full.tb",
		"suse_index.tb",
		"suse_full.tb",
		"apps.tb",
		"rhel-cpe.map",
		"rocky_index.tb",
		"rocky_full.tb",
	}
	defaultVer = "1.000"
	wrongKey   = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
)

// CreateMinimalFakeCveDb creates a minimal fake CVE database
func CreateMinimalFakeCveDb(dbFile, version string, encryptKey []byte) error {
	tarBuf, fileShas, err := createMinimalTarArchive()
	if err != nil {
		return fmt.Errorf("create tar archive: %v", err)
	}

	encryptedData, err := encryptData(tarBuf.Bytes(), encryptKey)
	if err != nil {
		return fmt.Errorf("encrypt tar: %v", err)
	}

	keyVer := KeyVersion{
		Version:    version,
		UpdateTime: time.Now().Format(time.RFC3339),
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

func createMinimalTarArchive() (*bytes.Buffer, map[string]string, error) {
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
			ModTime: time.Now(),
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

func prepareMockDbPaths(t *testing.T, encryptKey []byte) (string, string) {
	t.Helper()
	dbRoot := t.TempDir()
	expandRoot := t.TempDir()
	dbPath := dbRoot + string(filepath.Separator)
	dbFile := filepath.Join(dbRoot, "cvedb")
	require.NoError(t, CreateMinimalFakeCveDb(dbFile, defaultVer, encryptKey))
	return dbPath, expandRoot
}

func TestLoadCveDB(t *testing.T) {
	testCases := []struct {
		name        string
		setupFunc   func(t *testing.T) (dbPath, expandPath string)
		expectErr   error
		expectedVer string
	}{
		{
			name: "db file not exist, expand path not exist",
			setupFunc: func(t *testing.T) (string, string) {
				return "not_exist/", t.TempDir()
			},
			expectErr: errors.New("Read db file fail: open not_exist/cvedb: no such file or directory"),
		},
		{
			name: "db file exist, expand path not exist (first load)",
			setupFunc: func(t *testing.T) (string, string) {
				return prepareMockDbPaths(t, GetCVEDBEncryptKey())
			},
			expectedVer: defaultVer,
		},
		{
			name: "db file exist, expand path exist with same version",
			setupFunc: func(t *testing.T) (string, string) {
				dbPath, expandPath := prepareMockDbPaths(t, GetCVEDBEncryptKey())
				// First load to expand the DB
				_, _, err := LoadCveDb(dbPath, expandPath, GetCVEDBEncryptKey())
				require.NoError(t, err)
				return dbPath, expandPath
			},
			expectedVer: defaultVer,
		},
		{
			name: "db file exist with newer version",
			setupFunc: func(t *testing.T) (string, string) {
				// Create old expanded DB
				dbRoot1 := t.TempDir()
				expandPath := t.TempDir()
				dbPath1 := dbRoot1 + string(filepath.Separator)
				dbFile1 := filepath.Join(dbRoot1, "cvedb")
				require.NoError(t, CreateMinimalFakeCveDb(dbFile1, defaultVer, GetCVEDBEncryptKey()))
				_, _, err := LoadCveDb(dbPath1, expandPath, GetCVEDBEncryptKey())
				require.NoError(t, err)

				// Create new DB with higher version
				dbRoot2 := t.TempDir()
				dbPath2 := dbRoot2 + string(filepath.Separator)
				dbFile2 := filepath.Join(dbRoot2, "cvedb")
				require.NoError(t, CreateMinimalFakeCveDb(dbFile2, "2.000", GetCVEDBEncryptKey()))

				return dbPath2, expandPath
			},
			expectedVer: "2.000",
		},
		{
			name: "invalid expand path (permission error)",
			setupFunc: func(t *testing.T) (string, string) {
				dbRoot := t.TempDir()
				dbPath := dbRoot + string(filepath.Separator)
				dbFile := filepath.Join(dbRoot, "cvedb")
				require.NoError(t, CreateMinimalFakeCveDb(dbFile, "1.000", GetCVEDBEncryptKey()))
				return dbPath, "/dev/null/invalid"
			},
			expectErr: &fs.PathError{
				Op:   "open",
				Path: "/dev/null/invalidkeys",
				Err:  syscall.ENOTDIR,
			},
		},
		{
			name: "wrong encryption key",
			setupFunc: func(t *testing.T) (string, string) {
				return prepareMockDbPaths(t, wrongKey)
			},
			expectErr: errors.New("cipher: message authentication failed"),
		},
		{
			name: "db with older version than expanded (use newer version)",
			setupFunc: func(t *testing.T) (string, string) {
				// Create new expanded DB (v2.0)
				dbRoot1 := t.TempDir()
				expandPath := t.TempDir()
				dbPath1 := dbRoot1 + string(filepath.Separator)
				dbFile1 := filepath.Join(dbRoot1, "cvedb")
				require.NoError(t, CreateMinimalFakeCveDb(dbFile1, "2.000", GetCVEDBEncryptKey()))
				_, _, err := LoadCveDb(dbPath1, expandPath, GetCVEDBEncryptKey())
				require.NoError(t, err)

				// Create DB with lower version (v1.0)
				dbRoot2 := t.TempDir()
				dbPath2 := dbRoot2 + string(filepath.Separator)
				dbFile2 := filepath.Join(dbRoot2, "cvedb")
				require.NoError(t, CreateMinimalFakeCveDb(dbFile2, defaultVer, GetCVEDBEncryptKey()))

				return dbPath2, expandPath
			},
			expectedVer: "2.000",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dbPath, expandPath := tc.setupFunc(t)
			log.Info("Running testCase: ", tc.name)

			version, updateTime, err := LoadCveDb(dbPath, expandPath, GetCVEDBEncryptKey())
			require.Equal(t, tc.expectErr, err)

			if tc.expectErr == nil {
				require.NotEmpty(t, updateTime)
				require.Equal(t, tc.expectedVer, version)
			}
		})
	}
}
