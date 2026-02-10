package cvetools

import (
	"os"
	"sort"
	"testing"

	"github.com/neuvector/neuvector/share/scan"
	"github.com/stretchr/testify/require"
)

func TestParseBitNamiComponents(t *testing.T) {
	filename := "./mock/bitnami_component.json"
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	pkgs, err := parseBitNamiComponents(data, filename)
	if err != nil {
		t.Fatalf("Failed to parse bitnami components: %v", err)
	}

	expectedPkgs := []scan.AppPackage{
		{AppName: "mongodb", ModuleName: "mongodb", Version: "8.0.3", FileName: filename},
		{AppName: "mongodb-shell", ModuleName: "mongodb-shell", Version: "2.3.2", FileName: filename},
		{AppName: "render-template", ModuleName: "render-template", Version: "1.0.7", FileName: filename},
		{AppName: "wait-for-port", ModuleName: "wait-for-port", Version: "1.0.8", FileName: filename},
		{AppName: "yq", ModuleName: "yq", Version: "4.44.3", FileName: filename},
	}

	sort.Slice(pkgs, func(i, j int) bool {
		return pkgs[i].AppName < pkgs[j].AppName
	})

	sort.Slice(expectedPkgs, func(i, j int) bool {
		return pkgs[i].AppName < pkgs[j].AppName
	})

	require.Equal(t, expectedPkgs, pkgs)
}
