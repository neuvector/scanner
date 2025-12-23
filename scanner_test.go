package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestImageParsing(t *testing.T) {
	tests := []struct {
		input              string
		expectedRegistry   string
		expectedRepository string
		expectedRef        string
	}{
		{"alpine:3.17", "", "alpine", "3.17"},
		{"nginx:latest", "", "nginx", "latest"},
		{"nginx", "", "nginx", "latest"},
		{"nginx:", "", "nginx", ""},
		{"test/nginx", "", "test/nginx", "latest"},
		{"test/nginx:v2", "", "test/nginx", "v2"},
		{"example.com:5000", "https://example.com:5000", "", ""},
		{"example.com/test/nginx:v2", "https://example.com", "test/nginx", "v2"},
		{"example.com:5000/test/nginx:v2", "https://example.com:5000", "test/nginx", "v2"},
		{"http://example.com:5000/test/nginx:v2", "http://example.com:5000", "test/nginx", "v2"},
		{"http://example.com:5000/nginx:2.1", "http://example.com:5000", "nginx", "2.1"},
		{"registry.hub.docker.com/python:3.4", "https://registry.hub.docker.com", "library/python", "3.4"},
		{"registry.hub.docker.com/test/python:3.4", "https://registry.hub.docker.com", "test/python", "3.4"},
		{"alpine@sha256:abcd1234", "", "alpine", "sha256:abcd1234"},
		{"nginx@sha256:deadbeef", "", "nginx", "sha256:deadbeef"},
		{"test/nginx@sha256:cafebabe", "", "test/nginx", "sha256:cafebabe"},
		{"example.com/test/nginx@sha256:1a2b3c4d", "https://example.com", "test/nginx", "sha256:1a2b3c4d"},
		{"example.com:5000/test/nginx@sha256:5e6f7a8b", "https://example.com:5000", "test/nginx", "sha256:5e6f7a8b"},
		{"http://example.com:5000/test/nginx@sha256:9c8d7e6f", "http://example.com:5000", "test/nginx", "sha256:9c8d7e6f"},
		{"http://example.com:5000/nginx@sha256:fedcba98", "http://example.com:5000", "nginx", "sha256:fedcba98"},
		{"registry.hub.docker.com/python@sha256:11223344", "https://registry.hub.docker.com", "library/python", "sha256:11223344"},
		{"registry.hub.docker.com/test/python@sha256:aabbccdd", "https://registry.hub.docker.com", "test/python", "sha256:aabbccdd"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			reg, repo, ref := parseImageValue(tt.input)
			require.Equal(t, tt.expectedRegistry, reg, "registry mismatch")
			require.Equal(t, tt.expectedRepository, repo, "repository mismatch")
			require.Equal(t, tt.expectedRef, ref, "ref mismatch")
		})
	}
}

func TestParseTagOrDigest(t *testing.T) {
	tests := []struct {
		input        string
		expectedName string
		expectedRef  string
	}{
		{"alpine:latest", "alpine", "latest"},
		{"alpine", "alpine", "latest"},
		{"myregistry.com/repo/image:1.2.3", "myregistry.com/repo/image", "1.2.3"},
		{"repo/image@sha256:abc123", "repo/image", "sha256:abc123"},
		{"myregistry.com/repo/image@sha256:def456", "myregistry.com/repo/image", "sha256:def456"},
		{"image@sha256:verylongdigestwithnumbers1234567890", "image", "sha256:verylongdigestwithnumbers1234567890"},
		{"image:", "image", ""}, // edge case: empty tag
		{"image@", "image", ""}, // edge case: empty digest
		{"", "", "latest"},      // edge case: empty input
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			gotName, gotRef := parseTagOrDigest(tt.input)
			require.Equal(t, tt.expectedName, gotName, "name mismatch for input %q", tt.input)
			require.Equal(t, tt.expectedRef, gotRef, "ref mismatch for input %q", tt.input)
		})
	}
}
func TestNormalizeRegistry(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"example.com", "https://example.com/"},
		{"http://example.com", "http://example.com/"},
		{"https://example.com", "https://example.com/"},
		{"https://example.com/", "https://example.com/"},
		{"http://example.com:5000", "http://example.com:5000/"},
		{"example.com:5000", "https://example.com:5000/"},
		{"https://registry.example.com/", "https://registry.example.com/"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeRegistry(tt.input)
			require.Equal(t, tt.expected, got)
		})
	}
}
