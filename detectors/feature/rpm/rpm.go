package rpm

import (
	"bufio"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
	"github.com/neuvector/scanner/common"
	"github.com/neuvector/scanner/detectors"
)

type RpmFeaturesDetector struct{}

const (
	contentManifest = "root/buildinfo/content_manifests"
	dockerfile      = "root/buildinfo/Dockerfile-"
	rpmPackageFile  = "var/lib/rpm/Packages"
	// pyxisUrl        = "https://catalog.redhat.com/api/containers/v1/images/nvr"
)

var redhatRegexp = regexp.MustCompile(`com.redhat.component="([a-zA-Z0-9\-_\.]*)"`)
var archRegexp = regexp.MustCompile(`"architecture"="([a-zA-Z0-9\-_\.]*)"`)
var versionRegexp = regexp.MustCompile(`root/buildinfo/Dockerfile-([a-zA-Z0-9_]+)-([a-zA-z0-9\-_\.]*)`)

var rpmsMap RpmsMap

func init() {
	detectors.RegisterFeaturesDetector("rpm", &RpmFeaturesDetector{})
}

func (detector *RpmFeaturesDetector) Detect(namespace string, files map[string]*detectors.FeatureFile, path string) ([]detectors.FeatureVersion, error) {
	var rpmFF *detectors.FeatureFile
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
		return []detectors.FeatureVersion{}, nil
	}

	if len(rpmsMap.Data) == 0 {
		if mdata, _ := common.LoadRawFile(path, common.RHELCpeMapFile); mdata != nil {
			if err := json.Unmarshal(mdata, &rpmsMap); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to unmarshal cpe map")
			}
		}
	}

	var cpes utils.Set
	// check the redhat CPEs
	if len(rpmsMap.Data) > 0 {
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
	packagesMap := make(map[string]detectors.FeatureVersion)

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
			pkg := detectors.FeatureVersion{
				Feature: detectors.Feature{
					Name: p.Name,
				},
				Version: version,
				CPEs:    cpes,
				InBase:  rpmFF.InBase,
			}
			packagesMap[pkg.Feature.Name+"#"+pkg.Version.String()] = pkg
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
			pkg := detectors.FeatureVersion{
				Feature: detectors.Feature{
					Name: line[0],
				},
				Version: version,
				CPEs:    cpes,
				InBase:  rpmFF.InBase,
			}
			packagesMap[pkg.Feature.Name+"#"+pkg.Version.String()] = pkg
		}
	}

	// Convert the map to a slice
	packages := make([]detectors.FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}

	return packages, nil
}

func (detector *RpmFeaturesDetector) GetRequiredFiles() []string {
	return []string{"var/lib/rpm/Packages"}
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

type RpmsMap struct {
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

func getMappingJson(rpms []string) utils.Set {
	allCpes := utils.NewSet()
	for _, rpm := range rpms {
		if cpesMap, ok := rpmsMap.Data[rpm]; ok {
			if cpes, ok := cpesMap["cpes"]; ok {
				for _, cpe := range cpes {
					allCpes.Add(cpe)
				}
			}
		}
	}
	return allCpes
}

type RpmsNvrData struct {
	Data []RpmsData
}

type RpmsData struct {
	CpeIds     []string   `json:"cpe_ids"`
	ParsedData ParsedData `json:"parsed_data"`
}

type ParsedData struct {
	Labels []map[string]string `json:"labels"`
}

/*
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
