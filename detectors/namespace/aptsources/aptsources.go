package aptsources

import (
	"bufio"
	"strings"

	"github.com/neuvector/scanner/common"
	"github.com/neuvector/scanner/detectors"
)

// AptSourcesNamespaceDetector implements NamespaceDetector and detects the Namespace from the
// /etc/apt/sources.list file.
//
// This detector is necessary to determine precise Debian version when it is
// an unstable version for instance.
type AptSourcesNamespaceDetector struct{}

func init() {
	detectors.RegisterNamespaceDetector("apt-sources", &AptSourcesNamespaceDetector{})
}

func (detector *AptSourcesNamespaceDetector) Detect(data map[string]*detectors.FeatureFile) *detectors.Namespace {
	f, hasFile := data["etc/apt/sources.list"]
	if !hasFile {
		return nil
	}

	var OS, version string

	scanner := bufio.NewScanner(strings.NewReader(string(f.Data)))
	for scanner.Scan() {
		// Format: man sources.list | https://wiki.debian.org/SourcesList)
		// deb uri distribution component1 component2 component3
		// deb-src uri distribution component1 component2 component3
		line := strings.Split(scanner.Text(), " ")
		if len(line) > 3 {
			// Only consider main component
			isMainComponent := false
			for _, component := range line[3:] {
				if component == "main" {
					isMainComponent = true
					break
				}
			}
			if !isMainComponent {
				continue
			}

			var found bool
			version, found = common.DebianReleasesMapping[line[2]]
			if found {
				OS = "debian"
				break
			}
			version, found = common.UbuntuReleasesMapping[line[2]]
			if found {
				OS = "ubuntu"
				break
			}
		}
	}

	if OS != "" && version != "" {
		return &detectors.Namespace{Name: OS + ":" + version}
	}
	return nil
}

func (detector *AptSourcesNamespaceDetector) GetRequiredFiles() []string {
	return []string{"etc/apt/sources.list"}
}
