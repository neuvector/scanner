package cvetools

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDockerImageSaveRef(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{
		{
			name: "bare sha256 digest",
			id:   strings.Repeat("a", 64),
			want: "sha256:" + strings.Repeat("a", 64),
		},
		{
			name: "prefixed sha256 digest",
			id:   "sha256:" + strings.Repeat("b", 64),
			want: "sha256:" + strings.Repeat("b", 64),
		},
		{
			name: "image name",
			id:   "nginx:latest",
			want: "nginx:latest",
		},
		{
			name: "invalid bare digest",
			id:   strings.Repeat("z", 64),
			want: strings.Repeat("z", 64),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, dockerImageSaveRef(tt.id))
		})
	}
}
