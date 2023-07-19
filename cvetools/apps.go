package cvetools

import (
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
	"github.com/neuvector/scanner/common"
	"github.com/neuvector/scanner/detectors"
)

const log4jModName = "org.apache.logging.log4j.log4j"

// NVSHAS-6331: remove log4j-api because it doesn't necessarily carry the same vulnerability
// "org.apache.logging.log4j:log4j-api",
// NVSHAS-6709: disable log4j-to-slf4j too
// "org.apache.logging.log4j:log4j-to-slf4j"
var log4jComponents = utils.NewSet("org.apache.logging.log4j:log4j-core")

func (cv *CveTools) DetectAppVul(path string, apps []detectors.AppFeatureVersion, namespace string) []vulFullReport {
	if apps == nil || len(apps) == 0 {
		return nil
	}
	modVuls, err := common.LoadAppVulsTb(path)
	if err != nil {
		return nil
	}
	vuls := make([]vulFullReport, 0)
	for i, app := range apps {
		//If the entry exists, find vulnerabilities.
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
	return vuls
}

func checkForVulns(app detectors.AppFeatureVersion, appIndex int, apps []detectors.AppFeatureVersion, mv []common.AppModuleVul) []vulFullReport {
	vuls := make([]vulFullReport, 0)
	for _, v := range mv {
		if len(v.UnaffectedVer) > 0 {
			if unaffected := compareAppVersion(app.Version, v.UnaffectedVer); unaffected {
				continue
			}
		}
		// ruby reports patched version. The affected version is converted from patched version.
		// The conversion logic is not correct.
		if strings.HasPrefix(app.ModuleName, "ruby:") && len(v.FixedVer) > 0 {
			if fixed := compareAppVersion(app.Version, v.FixedVer); !fixed {
				fv := appVul2FullVul(app, v)
				vuls = append(vuls, fv)
				mcve := detectors.ModuleVul{Name: v.VulName, Status: share.ScanVulStatus_FixExists}
				apps[appIndex].ModuleVuls = append(apps[appIndex].ModuleVuls, mcve)
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
	ft := common.FeaFull{Name: mv.ModuleName, Namespace: app.AppName}
	for i, v := range mv.FixedVer {
		s := strings.Replace(v.OpCode, "or", "||", -1)
		s = strings.Replace(s, "gt", ">", -1)
		s = strings.Replace(s, "lt", "<", -1)
		s = strings.Replace(s, "eq", "=", -1)
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

		if prefix != "" && !strings.HasPrefix(ver, prefix) {
			continue
		}

		ret := av.Compare(bv)

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
