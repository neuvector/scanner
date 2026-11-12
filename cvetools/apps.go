package cvetools

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
	"github.com/neuvector/scanner/common"
	"github.com/neuvector/scanner/detectors"
)

const log4jModName = "org.apache.logging.log4j.log4j"

// semverPreReleaseRe detects Go-style semver pre-release suffixes such as "-rc.3" or "-beta.1".
var semverPreReleaseRe = regexp.MustCompile(`-(rc|alpha|beta|pre)[\d.]`)

func semverPreReleaseBase(ver string) (string, bool) {
	loc := semverPreReleaseRe.FindStringIndex(ver)
	if loc == nil {
		return ver, false
	}
	return ver[:loc[0]], true
}

func microPrefix(ver string) string {
	parts := strings.Split(ver, ".")
	if len(parts) < 4 {
		return ""
	}
	// "4.0.0.beta8" from being misidentified as a 4-part numeric version, return ""
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			return ""
		}
	}
	return strings.Join(parts[:len(parts)-1], ".")
}

// NVSHAS-6331: remove log4j-api because it doesn't necessarily carry the same vulnerability
// "org.apache.logging.log4j:log4j-api",
// NVSHAS-6709: disable log4j-to-slf4j too
// "org.apache.logging.log4j:log4j-to-slf4j"
var log4jComponents = utils.NewSet("org.apache.logging.log4j:log4j-core")

func (cv *ScanTools) DetectAppVul(path string, apps []detectors.AppFeatureVersion, namespace string) []vulFullReport {
	if len(apps) == 0 {
		return nil
	}
	modVuls, err := common.LoadAppVulsTb(path)
	if err != nil {
		return nil
	}

	dedup := utils.NewSet()
	vuls := make([]vulFullReport, 0)
	for i, app := range apps {
		if common.Debugs.CVEs.Cardinality() == 0 && common.Debugs.Features.Contains(app.AppName) {
			log.WithFields(log.Fields{
				"app": app.AppName, "file": app.FileName, "module": app.ModuleName, "version": app.Version,
			}).Info("DEBUG")
		}

		key := fmt.Sprintf("%s-%s-%s", app.FileName, app.ModuleName, app.Version)
		if !dedup.Contains(key) {
			dedup.Add(key)
			if mv, found := modVuls[app.ModuleName]; found {
				results := checkForVulns(app, i, apps, mv)
				vuls = append(vuls, results...)
			} else if strings.Contains(app.ModuleName, "log4j") {
				//If the entry doesn't match and module contains log4j, check the exception list for component.
				if log4jComponents.Contains(app.ModuleName) {
					//If we find the entry on the exception list check the general log4j entry as well.
					if mv, found := modVuls[log4jModName]; found {
						results := checkForVulns(app, i, apps, mv)
						vuls = append(vuls, results...)
					}
				}
			}
		}
	}
	return vuls
}

func checkForVulns(app detectors.AppFeatureVersion, appIndex int, apps []detectors.AppFeatureVersion, mv []common.AppModuleVul) []vulFullReport {
	vuls := make([]vulFullReport, 0)
	for _, v := range mv {

		if common.Debugs.Enabled {
			if common.Debugs.CVEs.Contains(v.VulName) && common.Debugs.Features.Contains(app.AppName) {
				log.WithFields(log.Fields{
					"name": v.VulName, "affected": v.AffectedVer, "fixin": v.FixedVer,
					"app": app.AppName, "file": app.FileName, "module": app.ModuleName, "version": app.Version,
				}).Info("DEBUG: check")
			}
		}

		if len(v.UnaffectedVer) > 0 {
			if unaffected := compareAppVersion(app.Version, v.UnaffectedVer); unaffected {
				continue
			}
		}
		// ruby reports patched version. The affected version is converted from patched version.
		// The conversion logic has flaws.
		if strings.HasPrefix(app.ModuleName, "ruby:") && len(v.FixedVer) > 0 {
			if fixed := compareAppVersion(app.Version, v.FixedVer); !fixed {
				fv := appVul2FullVul(app, v)
				vuls = append(vuls, fv)
				mcve := detectors.ModuleVul{Name: v.VulName, Status: share.ScanVulStatus_FixExists}
				apps[appIndex].ModuleVuls = append(apps[appIndex].ModuleVuls, mcve)

				if common.Debugs.Enabled {
					if common.Debugs.CVEs.Contains(v.VulName) {
						log.WithFields(log.Fields{
							"name": v.VulName, "app": app.AppName, "version": app.Version, "file": app.FileName, "module": app.ModuleName,
						}).Info("DEBUG: report")
					}
				}
			}
		} else {
			if affected := compareAppVersion(app.Version, v.AffectedVer); affected {
				fv := appVul2FullVul(app, v)
				vuls = append(vuls, fv)
				if len(v.FixedVer) > 0 {
					mcve := detectors.ModuleVul{Name: v.VulName, Status: share.ScanVulStatus_FixExists}
					apps[appIndex].ModuleVuls = append(apps[appIndex].ModuleVuls, mcve)
				} else {
					mcve := detectors.ModuleVul{Name: v.VulName, Status: share.ScanVulStatus_Unpatched}
					apps[appIndex].ModuleVuls = append(apps[appIndex].ModuleVuls, mcve)
				}

				if common.Debugs.Enabled {
					if common.Debugs.CVEs.Contains(v.VulName) {
						log.WithFields(log.Fields{
							"name": v.VulName, "app": app.AppName, "version": app.Version,
						}).Info("DEBUG: report")
					}
				}
			}
		}
	}
	return vuls
}

func appVul2FullVul(app detectors.AppFeatureVersion, mv common.AppModuleVul) vulFullReport {
	var fv vulFullReport
	fv.Vf.Name = mv.VulName
	fv.Vf.Namespace = app.AppName
	fv.Vf.Description = mv.Description
	fv.Vf.Link = mv.Link
	fv.Vf.Severity = mv.Severity
	fv.Vf.FixedIn = make([]common.FeaFull, 0)
	fv.Vf.FixedIn = append(fv.Vf.FixedIn, moduleVer2FixVer(app, mv))
	fv.Vf.CVSSv2.Score = mv.Score

	if strings.HasSuffix(app.FileName, scan.WPVerFileSuffix) {
		fv.Ft.Package = "WordPress"
	} else {
		fv.Ft.Package = app.ModuleName
	}
	fv.Ft.File = app.FileName
	fv.Ft.Version, _ = utils.NewVersion(app.Version)
	fv.Ft.InBase = app.InBase
	return fv
}

func moduleVer2FixVer(app detectors.AppFeatureVersion, mv common.AppModuleVul) common.FeaFull {
	ft := common.FeaFull{Name: mv.ModuleName}
	for i, v := range mv.FixedVer {
		s := strings.ReplaceAll(v.OpCode, "or", "||")
		s = strings.ReplaceAll(s, "andlt", "<")
		s = strings.ReplaceAll(s, "gt", ">")
		s = strings.ReplaceAll(s, "lt", "<")
		s = strings.ReplaceAll(s, "eq", "=")
		ft.Version += s + v.Version
		if i < (len(mv.FixedVer) - 1) {
			ft.Version += ";"
		}
	}
	return ft
}

func compareAppVersion(ver string, affectedVer []common.AppModuleVersion) bool {
	// NVSHAS-4684, version in database does have revision
	/*
		//skip the revision, no revision in database
		if a := strings.Index(ver, "-"); a > 0 {
			ver = ver[:a]
		}
	*/
	var bv utils.Version
	av, err := utils.NewVersion(ver)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "version": ver}).Error("Failed to parse app version")
		return false
	}
	var hit0, hit1 bool
	var lastOp string
	for id, mv := range affectedVer {
		var prefix string
		if mv.Version == "All" {
			return true
		} else {
			// get the prefix out, only for jar
			if a := strings.Index(mv.Version, ","); a > 0 {
				prefix = mv.Version[a+1:]
				mv.Version = mv.Version[:a]
			}
			bv, err = utils.NewVersion(mv.Version)
			if err != nil {
				log.WithFields(log.Fields{"error": err, "version": mv.Version}).Error("Failed to parse affected version")
				continue
			}
		}

		if prefix != "" {
			// DB entry format: ">=4.0.3.1,4.0"
			//   version = "4.0.3.1", prefix = "4.0", opcode = "gteq"
			//
			// Problem: prefix "4.0" is too broad — it matches 4.0.4 too,
			// but 4.0.4 is a different patch line; we don't know if it's fixed.
			//
			// Fix (gt/gteq only): narrow prefix from "4.0" to "4.0.3",
			// so only 4.0.3.x versions are compared against this entry.
			//
			// lt/lteq: keep the broad prefix "4.0" so that
			// "<5.2.4.3,5.2" still catches 5.2.3.9 as vulnerable.
			if strings.Contains(mv.OpCode, "gt") {
				if mp := microPrefix(mv.Version); mp != "" {
					if !strings.HasPrefix(ver, mp+".") && ver != mp {
						continue
					}
				} else if !strings.HasPrefix(ver, prefix) {
					continue
				}
			} else if !strings.HasPrefix(ver, prefix) {
				continue
			}
		}

		ret := av.Compare(bv)

		// Semver pre-release correction: Debian revision ordering is the opposite
		// of semver for prerelease suffixes. Fix both directions:
		//   DB prerelease:        Compare("1.27.0",     "1.27.0-rc.3") = -1 → +1
		//   Installed prerelease: Compare("1.27.0-rc.3","1.27.0")     = +1 → -1
		if ret < 0 {
			if base, ok := semverPreReleaseBase(mv.Version); ok {
				if bv2, err2 := utils.NewVersion(base); err2 == nil && av.Compare(bv2) == 0 {
					ret = 1
				}
			}
		} else if ret > 0 {
			if base, ok := semverPreReleaseBase(ver); ok {
				if bv2, err2 := utils.NewVersion(base); err2 == nil && bv2.Compare(bv) == 0 {
					ret = -1
				}
			}
		}

		hit1 = hit0
		hit0 = false
		if mv.OpCode == "" && ret == 0 {
			return true
		} else if strings.Contains(mv.OpCode, "lteq") && ret <= 0 {
			hit0 = true
		} else if strings.Contains(mv.OpCode, "lt") && ret < 0 {
			hit0 = true
		} else if strings.Contains(mv.OpCode, "eq") && ret == 0 {
			hit0 = true
		} else if strings.Contains(mv.OpCode, "gteq") && ret >= 0 {
			hit0 = true
		} else if strings.Contains(mv.OpCode, "gt") && ret > 0 {
			hit0 = true
		}
		// avoid the >=2.7.1,2 and <=2.1,2 case
		if prefix != "" {
			if hit0 && !strings.Contains(mv.OpCode, "gt") && !strings.Contains(lastOp, "gt") {
				return true
			} else {
				return hit0
			}
		}
		//the case with <= || >= <=
		if strings.Contains(mv.OpCode, "or") {
			//in case of pairs: (>= && <=) or (>= && <=)
			if hit1 && !strings.Contains(lastOp, "lt") {
				return true
			} else if hit1 && id == 1 {
				// the case for: (<) || (> && <)
				return true
			} else if hit0 && id == (len(affectedVer)-1) {
				//the last one
				return true
			}
		} else { //the case >= && <=
			if hit1 && hit0 {
				return true
			} else if hit0 && len(affectedVer) == 1 {
				//the last one
				return true
			}
		}
		lastOp = mv.OpCode
	}
	return false
}
