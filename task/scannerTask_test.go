package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadTaskFile(t *testing.T) {
	cases := []struct {
		name        string
		fileName    string
		suffix      string
		create      bool
		wantErr     error
		wantRemoved bool
	}{
		{
			name:        "scanner request file is read and removed",
			fileName:    "uid" + reqFileSuffix,
			suffix:      reqFileSuffix,
			create:      true,
			wantRemoved: true,
		},
		{
			name:        "scanner cacert file is read and removed",
			fileName:    "uid" + cacertFileSuffix,
			suffix:      cacertFileSuffix,
			create:      true,
			wantRemoved: true,
		},
		{
			name:     "manually supplied file is kept",
			fileName: "inputs.json",
			suffix:   reqFileSuffix,
			create:   true,
		},
		{
			name:     "suffix in parent directory name only is kept",
			fileName: filepath.Join("x"+reqFileSuffix, "inputs.json"),
			suffix:   reqFileSuffix,
			create:   true,
		},
		{
			name:     "missing file returns error",
			fileName: "uid" + reqFileSuffix,
			suffix:   reqFileSuffix,
			wantErr:  fs.ErrNotExist,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.fileName)
			if c.create {
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
				require.NoError(t, os.WriteFile(path, []byte("content"), 0600))
			}

			data, err := readTaskFile(path, c.suffix)

			if c.wantErr != nil {
				require.ErrorIs(t, err, c.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "content", string(data))
			_, err = os.Stat(path)
			if c.wantRemoved {
				assert.ErrorIs(t, err, fs.ErrNotExist)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
