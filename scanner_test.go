package main

import (
	"testing"
)

func TestImageParsing(t *testing.T) {
	cases := [][4]string{
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

	for _, c := range cases {
		reg, repo, tag := parseImageValue(c[0])
		if reg != c[1] || repo != c[2] || tag != c[3] {
			t.Errorf("Incorrect result: %s => got (%s, %s, %s), want (%s, %s, %s)\n",
				c[0], reg, repo, tag, c[1], c[2], c[3])
		}
	}
}
