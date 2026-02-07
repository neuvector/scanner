package cvetools

import (
	"encoding/json"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/scan"
)

type bitnamiComponent struct {
	Arch    string `json:"arch"`
	Distro  string `json:"distro"`
	Type    string `json:"type"`
	Version string `json:"version"`
}

func isBitNami(path string) bool {
	return strings.Contains(path, ".bitnami_components.json")
}

func getBitNamiComponents(fullpath, filename string) ([]scan.AppPackage, error) {
	data, err := os.ReadFile(fullpath)
	if err != nil {
		return nil, err
	}

	pkgs, err := parseBitNamiComponents(data, filename)
	if err != nil {
		return nil, err
	}

	return pkgs, nil
}

func parseBitNamiComponents(data []byte, filename string) ([]scan.AppPackage, error) {
	var comps map[string]bitnamiComponent
	if err := json.Unmarshal(data, &comps); err != nil {
		log.WithFields(log.Fields{"file": filename, "err": err}).Error("bitnami components parse failed")
		return nil, err
	}

	if len(comps) == 0 {
		return nil, nil
	}

	pkgs := make([]scan.AppPackage, 0, len(comps))
	for name, c := range comps {
		ver := strings.TrimSpace(c.Version)
		if idx := strings.LastIndex(ver, "-"); idx != -1 {
			ver = ver[:idx]
		}
		if name == "" || ver == "" {
			continue
		}
		pkgs = append(pkgs, scan.AppPackage{
			AppName:    name,
			ModuleName: name,
			Version:    ver,
			FileName:   filename,
		})
	}

	return pkgs, nil
}
