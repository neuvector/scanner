package cvetools

import "testing"

func TestDockerImageSaveID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{
		{
			name: "bare sha256",
			id:   "fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40",
			want: "sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40",
		},
		{
			name: "canonical sha256",
			id:   "sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40",
			want: "sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40",
		},
		{
			name: "short image ID",
			id:   "fd791d74b689",
			want: "fd791d74b689",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dockerImageSaveID(tt.id); got != tt.want {
				t.Fatalf("dockerImageSaveID(%q) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

