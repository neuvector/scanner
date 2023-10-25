package detectors

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
	"github.com/neuvector/scanner/common"
)

type FeatureFile struct {
	Data   []byte
	InBase bool
}

type Namespace struct {
	Name    string
	RHELVer string
}

type ModuleVul struct {
	Name   string
	Status share.ScanVulStatus
}

type FeatureVersion struct {
	Package    string
	File       string
	Version    utils.Version
	MinVer     utils.Version
	ModuleVuls []ModuleVul
	CPEs       utils.Set
	InBase     bool
}

type AppFeatureVersion struct {
	scan.AppPackage
	ModuleVuls []ModuleVul
	InBase     bool
}

// DetectFeatures detects a list of FeatureVersion using every registered FeaturesDetector.
func DetectFeatures(namespace string, data map[string]*FeatureFile, path string) ([]FeatureVersion, error) {
	var pkgs []FeatureVersion
	var err error

	packages := []FeatureVersion{}

	pkgs, err = detectAPK(namespace, data, path)
	if err != nil {
		return packages, err
	}
	packages = append(packages, pkgs...)

	pkgs, err = detectDPKG(namespace, data, path)
	if err != nil {
		return packages, err
	}
	packages = append(packages, pkgs...)

	pkgs, err = detectRPM(namespace, data, path)
	if err != nil {
		return packages, err
	}
	packages = append(packages, pkgs...)

	pkgs, err = detectOthers(namespace, data, path)
	if err != nil {
		return packages, err
	}
	packages = append(packages, pkgs...)

	return packages, nil
}

// -- apk

const apkPackageFile = "lib/apk/db/installed"

func detectAPK(namespace string, files map[string]*FeatureFile, path string) ([]FeatureVersion, error) {
	f, hasFile := files[apkPackageFile]
	if !hasFile {
		return []FeatureVersion{}, nil
	}

	packagesMap := make(map[string]FeatureVersion)

	var pkg FeatureVersion
	var err error
	scanner := bufio.NewScanner(bytes.NewReader(f.Data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 3 {
			if line[0] == 'P' && line[1] == ':' {
				pkg.Package = strings.TrimPrefix(line, "P:")
			} else if line[0] == 'V' && line[1] == ':' {
				pkg.Version, err = utils.NewVersion(strings.TrimPrefix(line, "V:"))
				if err != nil {
					log.Warningf("could not parse package version '%c': %s. skipping", line[1], err.Error())
				}
			} else if line[0] == 'o' && line[1] == ':' {
				pkg.Package = strings.TrimPrefix(line, "o:")
			}
		}
		// Add the package to the result array if we have all the informations
		if line == "" {
			if pkg.Package != "" && pkg.Version.String() != "" {
				pkg.InBase = f.InBase
				packagesMap[pkg.Package+"#"+pkg.Version.String()] = pkg
				pkg.Package = ""
				pkg.Version = utils.Version{}
			}
		}
	}

	// Convert the map to a slice
	packages := make([]FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}

	return packages, nil
}

// -- dpkg

var (
	dpkgSrcCaptureRegexp      = regexp.MustCompile(`Source: (?P<name>[^\s]*)( \((?P<version>.*)\))?`)
	dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()
)

const (
	installedStatus = "install ok installed"
	dpkgPackageFile = "var/lib/dpkg/status"
	dpkgPackageDir  = "var/lib/dpkg/status.d/"
)

type dpkgPackage struct {
	pkgName string
	status  string
	source  string
	version string
}

func addDPKGFeature(packagesMap map[string]FeatureVersion, pkg *dpkgPackage, inBase bool, installed bool) {
	// Add the package to the result array if we have all the informations
	if (pkg.pkgName != "" || pkg.source != "") && pkg.version != "" { //
		var name string
		if pkg.pkgName != "" && pkg.source != "" {
			name = pkg.source + "/" + pkg.pkgName
		} else if pkg.source != "" {
			name = pkg.source
		} else {
			name = pkg.pkgName
		}

		ver, _ := utils.NewVersion(pkg.version)
		fv := FeatureVersion{
			Package: name,
			Version: ver,
			InBase:  inBase,
		}

		/*
			if strings.Contains(pkg.pkgName, "liblz") || strings.Contains(pkg.pkgName, "debianutils") {
				log.WithFields(log.Fields{"feature": fv, "pkg": pkg}).Error("======")
			}
		*/

		if installed || strings.Contains(pkg.status, installedStatus) {
			packagesMap[fv.Package+"#"+pkg.version] = fv
		}
	}
}

func parseDPKGFeatureFile(packagesMap map[string]FeatureVersion, f string, inBase bool, installed bool) error {
	var pkg dpkgPackage
	scanner := bufio.NewScanner(strings.NewReader(f))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Package: ") {
			// Package line
			// Defines the name of the package
			pkg.pkgName = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		} else if strings.HasPrefix(line, "Status: ") {
			pkg.status = strings.TrimSpace(strings.TrimPrefix(line, "Status: "))
		} else if strings.HasPrefix(line, "Source: ") {
			// Source line (Optionnal)
			// Gives the name of the source package
			// May also specifies a version

			srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(line, -1)[0]
			md := map[string]string{}
			for i, n := range srcCapture {
				md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}

			pkg.source = md["name"]
			if md["version"] != "" {
				ver, err := utils.NewVersion(md["version"])
				if err != nil {
					log.Warningf("could not parse package version '%c': %s. skipping", line[1], err.Error())
				}
				pkg.version = ver.String()
			}
		} else if strings.HasPrefix(line, "Version: ") && pkg.version == "" {
			// Version line
			// Defines the version of the package
			// This version is less important than a version retrieved from a Source line
			// because the Debian vulnerabilities often skips the epoch from the Version field
			// which is not present in the Source version, and because +bX revisions don't matter
			sver := strings.TrimPrefix(line, "Version: ")
			ver, err := utils.NewVersion(sver)
			if err != nil {
				log.Warningf("could not parse package version '%c': %s. skipping", line[1], err.Error())
			}
			pkg.version = ver.String()
		} else if line == "" {
			addDPKGFeature(packagesMap, &pkg, inBase, installed)
			pkg = dpkgPackage{}
		}
	}

	addDPKGFeature(packagesMap, &pkg, inBase, installed)
	return nil
}

func detectDPKG(namespace string, files map[string]*FeatureFile, path string) ([]FeatureVersion, error) {
	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[string]FeatureVersion)

	for name, file := range files {
		if name == dpkgPackageFile {
			parseDPKGFeatureFile(packagesMap, string(file.Data[:]), file.InBase, false)
		} else if strings.HasPrefix(name, dpkgPackageDir) {
			parseDPKGFeatureFile(packagesMap, string(file.Data[:]), file.InBase, true)
		}
	}

	// Convert the map to a slice
	packages := make([]FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}

	return packages, nil
}

// -- rpm

const (
	contentManifest = "root/buildinfo/content_manifests"
	dockerfile      = "root/buildinfo/Dockerfile-"
	rpmPackageFile  = "var/lib/rpm/Packages"
	// pyxisUrl        = "https://catalog.redhat.com/api/containers/v1/images/nvr"
)

var redhatRegexp = regexp.MustCompile(`com.redhat.component="([a-zA-Z0-9\-_\.]*)"`)
var archRegexp = regexp.MustCompile(`"architecture"="([a-zA-Z0-9\-_\.]*)"`)
var versionRegexp = regexp.MustCompile(`root/buildinfo/Dockerfile-([a-zA-Z0-9_]+)-([a-zA-z0-9\-_\.]*)`)

var rpms rpmsMap

func detectRPM(namespace string, files map[string]*FeatureFile, path string) ([]FeatureVersion, error) {
	var rpmFF *FeatureFile
	var max int

	for fn, ff := range files {
		// In case there are multiple rpm package files present, pick the largest
		if scan.RPMPkgFiles.Contains(fn) && len(ff.Data) > max {
			rpmFF = ff
			max = len(ff.Data)
		}
	}

	if rpmFF == nil {
		// Not RPM
		return []FeatureVersion{}, nil
	}

	if len(rpms.Data) == 0 {
		if mdata, _ := common.LoadRawFile(path, common.RHELCpeMapFile); mdata != nil {
			if err := json.Unmarshal(mdata, &rpms); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to unmarshal cpe map")
			}
		}
	}

	var cpes utils.Set
	// check the redhat CPEs
	if len(rpms.Data) > 0 {
		for filename, d := range files {
			// log.WithFields(log.Fields{"filename": filename}).Info("=============")
			if strings.HasPrefix(filename, contentManifest) && strings.HasSuffix(filename, ".json") {
				// log.WithFields(log.Fields{"file": string(d[:])}).Info("=============")
				cpes = getMappingJson(getContentSets(d.Data))
			}
		}
	}

	if cpes == nil || cpes.Cardinality() == 0 {
		if strings.HasPrefix(namespace, "rhel:7.") {
			cpes = utils.NewSet(
				"cpe:/a:redhat:rhel_software_collections:1::el7",
				"cpe:/a:redhat:rhel_software_collections:2::el7",
				"cpe:/a:redhat:rhel_software_collections:3::el7",
				"cpe:/o:redhat:enterprise_linux:7::server")
		} else if strings.HasPrefix(namespace, "rhel:8.") {
			cpes = utils.NewSet(
				"cpe:/o:redhat:rhel:8.3::baseos",
				"cpe:/a:redhat:enterprise_linux:8::appstream",
				"cpe:/o:redhat:enterprise_linux:8::baseos")
		} else if strings.HasPrefix(namespace, "rhel:9.") {
			cpes = utils.NewSet(
				"cpe:/o:redhat:enterprise_linux:9::baseos",
				"cpe:/a:redhat:enterprise_linux:9::appstream")
		}
	}

	log.WithFields(log.Fields{"namespace": namespace, "cpes": cpes}).Info()

	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[string]FeatureVersion)

	var pkgs []scan.RPMPackage
	if err := json.Unmarshal(rpmFF.Data, &pkgs); err == nil {
		for _, p := range pkgs {
			// Parse version
			var version utils.Version
			if p.Epoch == 0 {
				version, err = utils.NewVersion(fmt.Sprintf("%s-%s", p.Version, p.Release))
			} else {
				version, err = utils.NewVersion(fmt.Sprintf("%d:%s-%s", p.Epoch, p.Version, p.Release))
			}
			if err != nil {
				log.WithFields(log.Fields{"epoch": p.Epoch, "version": p.Version, "release": p.Release}).Error("Failed to parse package version")
				continue
			}

			// Add package
			pkg := FeatureVersion{
				Package: p.Name,
				Version: version,
				CPEs:    cpes,
				InBase:  rpmFF.InBase,
			}
			packagesMap[pkg.Package+"#"+pkg.Version.String()] = pkg
		}
	} else {
		// To support legacy format from old enforcer
		scanner := bufio.NewScanner(strings.NewReader(string(rpmFF.Data)))
		for scanner.Scan() {
			line := strings.Split(scanner.Text(), " ")
			if len(line) != 2 {
				// We may see warnings on some RPM versions:
				// "warning: Generating 12 missing index(es), please wait..."
				continue
			}

			// Ignore gpg-pubkey packages which are fake packages used to store GPG keys - they are not versionned properly.
			if line[0] == "gpg-pubkey" {
				continue
			}

			// Parse version
			version, err := utils.NewVersion(strings.Replace(line[1], "(none):", "", -1))
			if err != nil {
				log.Warningf("could not parse package version '%s': %s. skipping", line[1], err.Error())
				continue
			}

			// Add package
			pkg := FeatureVersion{
				Package: line[0],
				Version: version,
				CPEs:    cpes,
				InBase:  rpmFF.InBase,
			}
			packagesMap[pkg.Package+"#"+pkg.Version.String()] = pkg
		}
	}

	// Convert the map to a slice
	packages := make([]FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}

	return packages, nil
}

type Metadata struct {
	IcmVersion      int    `json:"icm_version"`
	IcmSpec         string `json:"icm_spec"`
	ImageLayerIndex int    `json:"image_layer_index"`
}

type ContainerJson struct {
	Metadata      Metadata `json:"metadata"`
	ContentSets   []string `json:"content_sets"`
	ImageContents []string `json:"image_contents"`
}

type rpmsMap struct {
	Data map[string]map[string][]string
}

func getContentSets(data []byte) []string {
	var v ContainerJson
	err := json.Unmarshal(data, &v)
	if err != nil {
		log.Errorf("could not Unmarshal the ContainerJson data: %s", err)
		return nil
	}
	return v.ContentSets
}

func getMappingJson(rpmList []string) utils.Set {
	allCpes := utils.NewSet()
	for _, rpm := range rpmList {
		if cpesMap, ok := rpms.Data[rpm]; ok {
			if cpes, ok := cpesMap["cpes"]; ok {
				for _, cpe := range cpes {
					allCpes.Add(cpe)
				}
			}
		}
	}
	return allCpes
}

/*
type rpmsNvrData struct {
	Data []rpmsData
}

type rpmsData struct {
	CpeIds []string `json:"cpe_ids"`
	ParsedData ParsedData `json:"parsed_data"`
}

type ParsedData struct {
	Labels []map[string]string `json:"labels"`
}

func pyxisGetCpes(arch, component, version string) utils.Set {
	rurl := fmt.Sprintf("%s/%s-%s", pyxisUrl, component, version)
	req, err := http.NewRequest("GET", rurl, nil)
	req.Header.Add("User-Agent", "dbgen")
	client := http.Client{}
	r, err := client.Do(req)
	if err != nil {
		log.Errorf("could not download mapping json: %s", err)
		return nil
	}
	body, _ := ioutil.ReadAll(r.Body)
	var v RpmsNvrData
	err = json.Unmarshal(body, &v)
	if err != nil {
		log.Errorf("could not Unmarshal the file: %s", err)
		return nil
	}

	allCpes := utils.NewSet()
	for _, data := range v.Data {
		for _, label := range data.ParsedData.Labels {
			if name, ok := label["name"]; ok && name == "architecture" {
				if value, ok := label["value"]; ok && value == arch {
					for _, cpe := range data.CpeIds {
						allCpes.Add(cpe)
					}
				}
			}
		}
	}

	return allCpes
}
*/

// -- others

var pipPackagesRegexp = regexp.MustCompile(`(.*) \((.*)\)`)

func detectOthers(namespace string, files map[string]*FeatureFile, path string) ([]FeatureVersion, error) {
	f, hasFile := files["others_modules"]
	if !hasFile {
		return []FeatureVersion{}, nil
	}

	packagesMap := make(map[string]FeatureVersion)

	var err error
	scanner := bufio.NewScanner(bytes.NewReader(f.Data))
	for scanner.Scan() {
		var pkg FeatureVersion
		line := scanner.Text()
		r := pipPackagesRegexp.FindStringSubmatch(line)
		if len(r) == 3 {
			pkg.Package = strings.ToLower(r[1])
			pkg.Version, err = utils.NewVersion(r[2])
			if err != nil {
				log.Warningf("could not parse package version '%s': %s. skipping", r[2], err.Error())
				continue
			}

			pkg.InBase = f.InBase
			packagesMap[pkg.Package+"#"+pkg.Version.String()] = pkg
		}
	}

	// Convert the map to a slice
	packages := make([]FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}

	return packages, nil
}
