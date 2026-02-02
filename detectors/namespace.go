package detectors

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/neuvector/scanner/common"
)

// DetectNamespace finds the OS of the layer by using every registered NamespaceDetector.
func DetectNamespace(data map[string]*FeatureFile) *Namespace {
	// check os-release first
	if ns := detectOSRelease(data); ns != nil {
		return ns
	}
	if ns := detectLSBRelease(data); ns != nil {
		return ns
	}
	if ns := detectRHRelease(data); ns != nil {
		return ns
	}
	if ns := detectAptSource(data); ns != nil {
		return ns
	}
	return nil
}

var (
	osReleaseOSRegexp          = regexp.MustCompile(`^ID=(.*)`)
	osReleaseVersionRegexp     = regexp.MustCompile(`^VERSION_ID=(.*)`)
	osReleaseCodenameRegexp    = regexp.MustCompile(`^VERSION_CODENAME=(.*)`)
	osReleaseRHELVersionRegexp = regexp.MustCompile(`^RHEL_VERSION=(.*)`)
	osReleaseIsLiberty         = regexp.MustCompile(`SLES Expanded Support`)
)

func detectOSRelease(data map[string]*FeatureFile) *Namespace {
	var OS, version, codename, rhelVer string

	for _, filePath := range []string{"etc/os-release", "usr/lib/os-release"} {
		f, hasFile := data[filePath]
		if !hasFile {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(f.Data)))
		for scanner.Scan() {
			line := scanner.Text()

			r := osReleaseOSRegexp.FindStringSubmatch(line)
			if len(r) == 2 {
				OS = strings.ReplaceAll(strings.ToLower(r[1]), "\"", "")
			}

			r = osReleaseVersionRegexp.FindStringSubmatch(line)
			if len(r) == 2 {
				version = strings.ReplaceAll(strings.ToLower(r[1]), "\"", "")
			}

			r = osReleaseCodenameRegexp.FindStringSubmatch(line)
			if len(r) == 2 {
				codename = strings.ReplaceAll(strings.ToLower(r[1]), "\"", "")
			}

			r = osReleaseRHELVersionRegexp.FindStringSubmatch(line)
			if len(r) == 2 {
				rhelVer = strings.ReplaceAll(strings.ToLower(r[1]), "\"", "")
			}

			if OS == "rhel" {
				r = osReleaseIsLiberty.FindStringSubmatch(line)
				if len(r) == 1 {
					OS = "suse-liberty"
				}
			}
		}
	}

	if OS != "" && version != "" {
		return &Namespace{Name: OS + ":" + version, RHELVer: rhelVer}
	}
	if OS != "" && codename != "" {
		if version, ok := common.DebianReleasesMapping[codename]; ok {
			return &Namespace{Name: OS + ":" + version, RHELVer: rhelVer}
		}
	}
	return nil
}

var (
	lsbReleaseOSRegexp      = regexp.MustCompile(`^DISTRIB_ID=(.*)`)
	lsbReleaseVersionRegexp = regexp.MustCompile(`^DISTRIB_RELEASE=(.*)`)
)

func detectLSBRelease(data map[string]*FeatureFile) *Namespace {
	f, hasFile := data["etc/lsb-release"]
	if !hasFile {
		return nil
	}

	var OS, version string

	scanner := bufio.NewScanner(strings.NewReader(string(f.Data)))
	for scanner.Scan() {
		line := scanner.Text()

		r := lsbReleaseOSRegexp.FindStringSubmatch(line)
		if len(r) == 2 {
			OS = strings.ReplaceAll(strings.ToLower(r[1]), "\"", "")
		}

		r = lsbReleaseVersionRegexp.FindStringSubmatch(line)
		if len(r) == 2 {
			version = strings.ReplaceAll(strings.ToLower(r[1]), "\"", "")

			// We care about the .04 for Ubuntu but not for Debian / CentOS
			if OS == "centos" || OS == "debian" {
				i := strings.Index(version, ".")
				if i >= 0 {
					version = version[:i]
				}
			}
			if strings.Contains(OS, "coreos") {
				OS = "coreos"
			}
		}
	}

	if OS != "" && version != "" {
		return &Namespace{Name: OS + ":" + version}
	}
	return nil
}

var redhatReleaseRegexp = regexp.MustCompile(`(?P<os>[^\s]*) (Linux release|release) (?P<version>[\d]+)`)

// RedhatReleaseNamespaceDetector implements NamespaceDetector and detects the OS from the
// /etc/centos-release, /etc/redhat-release and /etc/system-release files.
//
// Typically for CentOS and Red-Hat like systems
// eg. CentOS release 5.11 (Final)
// eg. CentOS release 6.6 (Final)
// eg. CentOS Linux release 7.1.1503 (Core)
func detectRHRelease(data map[string]*FeatureFile) *Namespace {
	for _, filePath := range []string{"etc/centos-release", "etc/redhat-release", "etc/system-release", "etc/fedora-release"} {
		f, hasFile := data[filePath]
		if !hasFile {
			continue
		}

		r := redhatReleaseRegexp.FindStringSubmatch(string(f.Data))
		if len(r) == 4 {
			//if strings.ToLower(r[1]) == "centos" || strings.ToLower(r[1]) == "rhel" || strings.ToLower(r[1]) == "fedora" {
			return &Namespace{Name: strings.ToLower(r[1]) + ":" + r[3]}
		}
	}

	return nil
}

func detectAptSource(data map[string]*FeatureFile) *Namespace {
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
		return &Namespace{Name: OS + ":" + version}
	}
	return nil
}
