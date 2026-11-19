package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/neuvector/neuvector/share/system"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain clears the umask so mode assertions see exactly the permissions the code requests;
// otherwise a restrictive umask (e.g. 077) would mask a regression from 0600/0700 to 0644/0755.
func TestMain(m *testing.M) {
	old := syscall.Umask(0)
	code := m.Run()
	syscall.Umask(old)
	os.Exit(code)
}

func newTestTasker(t *testing.T) *Tasker {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	ts, err := newTasker("", "", false, system.NewSystemTools(), 0)
	require.NoError(t, err)
	return ts
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, want, string(data))
}

func TestTryWriteFile(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, dir, path string)
		wantErr error
		check   func(t *testing.T, dir, path string)
	}{
		{
			name:  "creates owner-only file",
			setup: func(t *testing.T, dir, path string) {},
			check: func(t *testing.T, dir, path string) {
				fi, err := os.Stat(path)
				require.NoError(t, err)
				assert.Equal(t, fs.FileMode(0600), fi.Mode().Perm())
				assertFileContent(t, path, "secret")
			},
		},
		{
			name: "existing file is not overwritten",
			setup: func(t *testing.T, dir, path string) {
				require.NoError(t, os.WriteFile(path, []byte("original"), 0644))
			},
			wantErr: fs.ErrExist,
			check: func(t *testing.T, dir, path string) {
				assertFileContent(t, path, "original")
			},
		},
		{
			name: "symlink is not followed",
			setup: func(t *testing.T, dir, path string) {
				target := filepath.Join(dir, "target")
				require.NoError(t, os.WriteFile(target, []byte("original"), 0644))
				require.NoError(t, os.Symlink(target, path))
			},
			wantErr: fs.ErrExist,
			check: func(t *testing.T, dir, path string) {
				fi, err := os.Lstat(path)
				require.NoError(t, err)
				assert.NotZero(t, fi.Mode()&fs.ModeSymlink, "path must still be the symlink")
				assertFileContent(t, filepath.Join(dir, "target"), "original")
			},
		},
		{
			name: "missing parent directory",
			setup: func(t *testing.T, dir, path string) {
				require.NoError(t, os.Remove(dir))
			},
			wantErr: fs.ErrNotExist,
			check: func(t *testing.T, dir, path string) {
				assert.NoDirExists(t, dir)
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "task")
			require.NoError(t, os.Mkdir(dir, 0700))
			path := filepath.Join(dir, "uid_i.json")
			c.setup(t, dir, path)

			err := TryWriteFile(path, []byte("secret"))

			if c.wantErr != nil {
				require.ErrorIs(t, err, c.wantErr)
			} else {
				require.NoError(t, err)
			}
			c.check(t, dir, path)
		})
	}
}

func TestNewTasker(t *testing.T) {
	cases := []struct {
		name    string
		tmpDir  func(t *testing.T) string
		wantErr error
	}{
		{
			name:   "creates private task directory",
			tmpDir: func(t *testing.T) string { return t.TempDir() },
		},
		{
			name:    "fails when the temp root does not exist",
			tmpDir:  func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") },
			wantErr: fs.ErrNotExist,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := c.tmpDir(t)
			t.Setenv("TMPDIR", root)

			ts, err := newTasker("", "", false, system.NewSystemTools(), 0)

			if c.wantErr != nil {
				require.ErrorIs(t, err, c.wantErr)
				assert.Nil(t, ts)
				return
			}
			require.NoError(t, err)
			defer ts.Close()
			assert.Equal(t, root, filepath.Dir(ts.taskDir))
			fi, err := os.Stat(ts.taskDir)
			require.NoError(t, err)
			assert.True(t, fi.IsDir())
			assert.Equal(t, fs.FileMode(0700), fi.Mode().Perm())
		})
	}
}

func TestClose(t *testing.T) {
	cases := []struct {
		name      string
		writeTask bool
	}{
		{name: "empty task directory"},
		{name: "task directory with leftover files", writeTask: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ts := newTestTasker(t)
			if c.writeTask {
				_, err := ts.writeInputFile([]byte("request"), []byte("PEM"))
				require.NoError(t, err)
			}

			ts.Close()

			assert.NoDirExists(t, ts.taskDir)
			assert.False(t, ts.bEnable)
		})
	}
}

func TestWriteInputFile(t *testing.T) {
	cases := []struct {
		name       string
		cacert     []byte
		wantCacert bool
	}{
		{name: "request only"},
		{name: "request and cacert", cacert: []byte("PEM"), wantCacert: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ts := newTestTasker(t)
			defer ts.Close()

			uid, err := ts.writeInputFile([]byte(`{"Password":"p"}`), c.cacert)
			require.NoError(t, err)

			req := ts.taskFile(uid, reqSuffix)
			assert.Equal(t, ts.taskDir, filepath.Dir(req))
			fi, err := os.Stat(req)
			require.NoError(t, err)
			assert.Equal(t, fs.FileMode(0600), fi.Mode().Perm())
			assertFileContent(t, req, `{"Password":"p"}`)

			cacert := ts.taskFile(uid, cacertSuffix)
			if !c.wantCacert {
				assert.NoFileExists(t, cacert)
				return
			}
			fi, err = os.Stat(cacert)
			require.NoError(t, err)
			assert.Equal(t, fs.FileMode(0600), fi.Mode().Perm())
			assertFileContent(t, cacert, "PEM")
		})
	}
}
