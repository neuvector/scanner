package cvetools

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/neuvector/neuvector/share/utils"
	"github.com/neuvector/scanner/common"
	"github.com/neuvector/scanner/detectors"
)

type versionTestCase struct {
	result  bool
	version string
	dbVer   []common.AppModuleVersion
}

func writeAppsTb(t *testing.T, entries []common.AppModuleVul) string {
	t.Helper()
	dir := t.TempDir()
	var buf bytes.Buffer
	for _, e := range entries {
		data, _ := json.Marshal(e)
		buf.Write(data)
		buf.WriteByte('\n')
	}
	_ = os.WriteFile(filepath.Join(dir, "apps.tb"), buf.Bytes(), 0644)
	return dir
}

func TestAffectedVersion(t *testing.T) {
	cases := []versionTestCase{
		{result: false, version: "1.2.3", dbVer: []common.AppModuleVersion{}},
		{result: true, version: "1.2.3", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}}},
		{result: false, version: "1.2.4", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}}},
		{result: true, version: "4.0.1", dbVer: []common.AppModuleVersion{{OpCode: "", Version: "4.0.1"}}},
		{result: true, version: "1.2.3", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "gt", Version: "1.2.0"}}},
		{result: true, version: "1.3.4", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "gt", Version: "1.2.0"}, {OpCode: "orlt", Version: "1.3.5"}}},
		{result: true, version: "1.3.4", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "gt", Version: "1.2.0"}, {OpCode: "lt", Version: "1.3.5"}}},
		{result: false, version: "1.3.4", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "lt", Version: "1.3.5"}}},
		{result: true, version: "1.3.4", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "orlt", Version: "1.3.5"}}},
		{result: true, version: "1.3.4", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "orlt", Version: "1.3.5"}, {OpCode: "gteq", Version: "1.3.4"}}},
		{result: false, version: "1.3.3", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "orlt", Version: "1.3.5"}, {OpCode: "gteq", Version: "1.3.4"}}},
		{result: true, version: "1.1.1", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}}},
		{result: false, version: "1.1.1", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4,1.2"}}},
		{result: true, version: "1.3.6", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "lt", Version: "1.3.7"}, {OpCode: "gt", Version: "1.3.5"}}},
		{result: true, version: "1.3.6", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "orlt", Version: "1.3.7"}, {OpCode: "gt", Version: "1.3.5"}}},
		{result: false, version: "2.9.1-6.el7.4", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "2.9.1-6.el7_2.2"}}},
		{result: false, version: "4.18.0-193.19.1.el8_2", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.18.0-193.19.1.el8"}}},
		{result: false, version: "4.18.0-193.19.1.el8_2", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.18.0-193.el8"}}},
		{result: true, version: "4.18.0-193.19.1.el8", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.18.0-193.19.1.el8_2"}}},
		{result: false, version: "4.18.0.el8_2", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.18.0.el8"}}},
		{result: false, version: "5.2.4.5", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "5.2.4.3,5.2"}, {OpCode: "orlt", Version: "6.0.3.1"}}},
		{result: true, version: "5.2.4.5", dbVer: []common.AppModuleVersion{{OpCode: "gteq", Version: "5.2.4.3,5.2"}, {OpCode: "orgteq", Version: "6.0.3.1"}}},
		{result: false, version: "5.0.11", dbVer: []common.AppModuleVersion{{OpCode: "gteq", Version: "5.0"}, {OpCode: "lteq", Version: "5.0.8"}, {OpCode: "orgteq", Version: "2.1"}, {OpCode: "lteq", Version: "2.1.28"}, {OpCode: "orgteq", Version: "3.1"}, {OpCode: "lteq", Version: "3.1.17"}, {OpCode: "orgteq", Version: "7.0"}, {OpCode: "lt", Version: "7.0.7"}, {OpCode: "orgteq", Version: "7.1"}, {OpCode: "lt", Version: "7.1.4"}}},
	}

	for _, c := range cases {
		v, _ := utils.NewVersion(c.version)
		if v.String() != c.version {
			t.Errorf("Error parsing version:  %v => %v", c.version, v.String())
		}
		ret := compareAppVersion(c.version, c.dbVer)
		if ret != c.result {
			t.Errorf("package %v, affected %v => %v", c.version, c.dbVer, ret)
		}
	}
}

func TestFixedVersion(t *testing.T) {
	cases := []versionTestCase{
		{result: true, version: "4.0.2", dbVer: []common.AppModuleVersion{{OpCode: "gteq", Version: "2.12.5"}, {OpCode: "lt", Version: "3.0.0"}, {OpCode: "orgteq", Version: "3.7.2"}, {OpCode: "lt", Version: "4.0.0"}, {OpCode: "orgteq", Version: "4.0.0.beta8"}}},
	}
	for _, c := range cases {
		v, _ := utils.NewVersion(c.version)
		if v.String() != c.version {
			t.Errorf("Error parsing version:  %v => %v", c.version, v.String())
		}
		ret := compareAppVersion(c.version, c.dbVer)
		if ret != c.result {
			t.Errorf("package %v, fixed %v => %v", c.version, c.dbVer, ret)
		}
	}
}

// TestDetectAppVul_NoFalsePositiveJarOkhttp verifies that jar:okhttp
// (from an OpenTelemetry JAR's MANIFEST.MF fallback) does NOT match
// CVEs for com.squareup.okhttp3:okhttp.
func TestDetectAppVul_NoFalsePositiveJarOkhttp(t *testing.T) {
	dir := writeAppsTb(t, []common.AppModuleVul{
		{
			VulName:     "CVE-2021-0341",
			AppName:     "jar",
			ModuleName:  "com.squareup.okhttp3:okhttp",
			Description: "OkHttp hostname verification bypass",
			Severity:    "High",
			AffectedVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.9.3"}},
			FixedVer:    []common.AppModuleVersion{{OpCode: "gteq", Version: "4.9.3"}},
		},
	})

	// Simulate what the scanner produces for opentelemetry-exporter-sender-okhttp-1.58.0.jar
	// which lacks pom.properties -- MANIFEST.MF fallback produces jar:okhttp
	apps := []detectors.AppFeatureVersion{
		{
			AppName:    "jar",
			ModuleName: "jar:okhttp",
			Version:    "1.58.0",
			FileName:   "app/libs/opentelemetry-exporter-sender-okhttp-1.58.0.jar",
		},
	}

	cv := &ScanTools{}
	vuls := cv.DetectAppVul(dir, apps, "")

	if len(vuls) != 0 {
		t.Errorf("expected 0 vulnerabilities for jar:okhttp (false positive), got %d", len(vuls))
		for _, v := range vuls {
			t.Errorf("  false positive: %s matched against %s", v.Vf.Name, v.Ft.File)
		}
	}
}

// TestDetectAppVul_NoFalsePositiveJarLibrary verifies that jar:library
// (from OpenTelemetry instrumentation JARs) does NOT match CVEs for
// Jenkins FindBugs Plugin.
func TestDetectAppVul_NoFalsePositiveJarLibrary(t *testing.T) {
	dir := writeAppsTb(t, []common.AppModuleVul{
		{
			VulName:     "CVE-2018-1000011",
			AppName:     "jar",
			ModuleName:  "org.jvnet.hudson.plugins:findbugs:library",
			Description: "Jenkins FindBugs Plugin XXE",
			Severity:    "High",
			AffectedVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.72"}},
		},
	})

	// OpenTelemetry instrumentation JARs produce jar:library from MANIFEST.MF
	apps := []detectors.AppFeatureVersion{
		{
			AppName:    "jar",
			ModuleName: "jar:library",
			Version:    "2.23.0-alpha",
			FileName:   "app/libs/opentelemetry-jdbc-2.23.0-alpha.jar",
		},
		{
			AppName:    "jar",
			ModuleName: "jar:library",
			Version:    "2.23.0-alpha",
			FileName:   "app/libs/opentelemetry-kafka-clients-2.6-2.23.0-alpha.jar",
		},
	}

	cv := &ScanTools{}
	vuls := cv.DetectAppVul(dir, apps, "")

	if len(vuls) != 0 {
		t.Errorf("expected 0 vulnerabilities for jar:library (false positive), got %d", len(vuls))
		for _, v := range vuls {
			t.Errorf("  false positive: %s matched against %s", v.Vf.Name, v.Ft.File)
		}
	}
}

// TestDetectAppVul_NoFalsePositiveJarMetrics verifies that jar:metrics
// (from OpenTelemetry SDK) does NOT match CVEs for Jenkins Metrics Plugin.
func TestDetectAppVul_NoFalsePositiveJarMetrics(t *testing.T) {
	dir := writeAppsTb(t, []common.AppModuleVul{
		{
			VulName:     "CVE-2022-20621",
			AppName:     "jar",
			ModuleName:  "org.jenkins-ci.plugins:metrics",
			Description: "Jenkins Metrics Plugin plain text storage",
			Severity:    "Medium",
			AffectedVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.2.0"}},
		},
	})

	apps := []detectors.AppFeatureVersion{
		{
			AppName:    "jar",
			ModuleName: "jar:metrics",
			Version:    "1.58.0",
			FileName:   "app/libs/opentelemetry-sdk-metrics-1.58.0.jar",
		},
	}

	cv := &ScanTools{}
	vuls := cv.DetectAppVul(dir, apps, "")

	if len(vuls) != 0 {
		t.Errorf("expected 0 vulnerabilities for jar:metrics (false positive), got %d", len(vuls))
	}
}

// TestDetectAppVul_NoFalsePositiveJarCommon verifies that jar:common
// does NOT match unrelated CVEs.
func TestDetectAppVul_NoFalsePositiveJarCommon(t *testing.T) {
	dir := writeAppsTb(t, []common.AppModuleVul{
		{
			VulName:     "CVE-2024-46985",
			AppName:     "jar",
			ModuleName:  "org.example:common",
			Description: "Some common library vulnerability",
			Severity:    "High",
			AffectedVer: []common.AppModuleVersion{{OpCode: "lt", Version: "2.10.1"}},
		},
	})

	apps := []detectors.AppFeatureVersion{
		{
			AppName:    "jar",
			ModuleName: "jar:common",
			Version:    "1.58.0",
			FileName:   "app/libs/opentelemetry-common-1.58.0.jar",
		},
	}

	cv := &ScanTools{}
	vuls := cv.DetectAppVul(dir, apps, "")

	if len(vuls) != 0 {
		t.Errorf("expected 0 vulnerabilities for jar:common (false positive), got %d", len(vuls))
	}
}

// TestDetectAppVul_LegitimateExactMatch verifies that exact groupId:artifactId
// matches (from JARs with pom.properties) still work correctly.
func TestDetectAppVul_LegitimateExactMatch(t *testing.T) {
	dir := writeAppsTb(t, []common.AppModuleVul{
		{
			VulName:     "CVE-2021-0341",
			AppName:     "jar",
			ModuleName:  "com.squareup.okhttp3:okhttp",
			Description: "OkHttp hostname verification bypass",
			Severity:    "High",
			AffectedVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.9.3"}},
			FixedVer:    []common.AppModuleVersion{{OpCode: "gteq", Version: "4.9.3"}},
		},
	})

	// JAR with pom.properties produces exact groupId:artifactId
	apps := []detectors.AppFeatureVersion{
		{
			AppName:    "jar",
			ModuleName: "com.squareup.okhttp3:okhttp",
			Version:    "4.9.1", // vulnerable version
			FileName:   "app/libs/okhttp-4.9.1.jar",
		},
	}

	cv := &ScanTools{}
	vuls := cv.DetectAppVul(dir, apps, "")

	if len(vuls) != 1 {
		t.Fatalf("expected 1 vulnerability for exact match, got %d", len(vuls))
	}
	if vuls[0].Vf.Name != "CVE-2021-0341" {
		t.Errorf("expected CVE-2021-0341, got %s", vuls[0].Vf.Name)
	}
}

// TestDetectAppVul_LegitimateDotSeparatedMatch verifies that dot-separated
// module names (backward compat) still match correctly.
func TestDetectAppVul_LegitimateDotSeparatedMatch(t *testing.T) {
	dir := writeAppsTb(t, []common.AppModuleVul{
		{
			VulName:     "CVE-2021-0341",
			AppName:     "jar",
			ModuleName:  "com.squareup.okhttp3:okhttp",
			Description: "OkHttp hostname verification bypass",
			Severity:    "High",
			AffectedVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.9.3"}},
			FixedVer:    []common.AppModuleVersion{{OpCode: "gteq", Version: "4.9.3"}},
		},
	})

	// Some older scanners produce dot-separated module names
	apps := []detectors.AppFeatureVersion{
		{
			AppName:    "jar",
			ModuleName: "com.squareup.okhttp3.okhttp",
			Version:    "4.9.1",
			FileName:   "app/libs/okhttp-4.9.1.jar",
		},
	}

	cv := &ScanTools{}
	vuls := cv.DetectAppVul(dir, apps, "")

	if len(vuls) != 1 {
		t.Fatalf("expected 1 vulnerability for dot-separated match, got %d", len(vuls))
	}
	if vuls[0].Vf.Name != "CVE-2021-0341" {
		t.Errorf("expected CVE-2021-0341, got %s", vuls[0].Vf.Name)
	}
}

// TestDetectAppVul_FixedVersionNotReported verifies that a JAR at a fixed
// version is NOT reported as vulnerable.
func TestDetectAppVul_FixedVersionNotReported(t *testing.T) {
	dir := writeAppsTb(t, []common.AppModuleVul{
		{
			VulName:     "CVE-2021-0341",
			AppName:     "jar",
			ModuleName:  "com.squareup.okhttp3:okhttp",
			Description: "OkHttp hostname verification bypass",
			Severity:    "High",
			AffectedVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.9.3"}},
		},
	})

	apps := []detectors.AppFeatureVersion{
		{
			AppName:    "jar",
			ModuleName: "com.squareup.okhttp3:okhttp",
			Version:    "5.3.1", // well past fixed version
			FileName:   "app/libs/okhttp-jvm-5.3.1.jar",
		},
	}

	cv := &ScanTools{}
	vuls := cv.DetectAppVul(dir, apps, "")

	if len(vuls) != 0 {
		t.Errorf("expected 0 vulnerabilities for fixed version 5.3.1, got %d", len(vuls))
	}
}
