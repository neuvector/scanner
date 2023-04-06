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
	}

	for _, c := range cases {
		reg, repo, tag := parseImageValue(c[0])
		if reg != c[1] || repo != c[2] || tag != c[3] {
			t.Errorf("Incorrect result: %s => %s, %s, %s\n", c[0], reg, repo, tag)
		}
	}
}
