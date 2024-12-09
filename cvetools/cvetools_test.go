package cvetools

import (
	"testing"

	"github.com/neuvector/neuvector/share/utils"
	"github.com/neuvector/scanner/common"
	"github.com/neuvector/scanner/detectors"
)

func TestSelectDB(t *testing.T) {
	type result struct {
		ns string
		db int
	}

	tests := map[string]result{
		"alpine:3.4.6":       {"alpine:3.4", common.DBAlpine},
		"rhel:8.3":           {"centos:8", common.DBCentos},
		"mariner:1.0":        {"mariner:1.0", common.DBMariner},
		"opensuse-leap:15.2": {"sles:l15.2", common.DBSuse},
		"ol:7.8.2":           {"oracle:7", common.DBOracle},
		"ubuntu:7.1":         {"ubuntu:7.1", common.DBUbuntu},
		"debian:3.1":         {"debian:3.1", common.DBDebian},
		"server:5.4":         {"centos:5", common.DBCentos},
		"centos:5.4":         {"centos:5", common.DBCentos},
		"amzn:1.8":           {"amzn:1", common.DBAmazon},
		"sles:2.7":           {"sles:2.7", common.DBSuse},
		"opensuse-leap:2.7":  {"sles:l2.7", common.DBSuse},
	}

	for os, r := range tests {
		nss := detectors.Namespace{Name: os}
		ns, db := os2DB(&nss)
		if ns != r.ns || db != r.db {
			t.Errorf("Incorrect result:  %s != %s or %d != %d", ns, r.ns, db, r.db)
		}
	}
}

func TestRHCos(t *testing.T) {
	osRel := `
NAME="Red Hat Enterprise Linux CoreOS"
ID="rhcos"
ID_LIKE="rhel fedora"
VERSION="411.86.202212072103-0"
VERSION_ID="4.11"
PLATFORM_ID="platform:el8"
PRETTY_NAME="Red Hat Enterprise Linux CoreOS 411.86.202212072103-0 (Ootpa)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:redhat:enterprise_linux:8::coreos"
HOME_URL="https://www.redhat.com/"
DOCUMENTATION_URL="https://docs.openshift.com/container-platform/4.11/"
BUG_REPORT_URL="https://bugzilla.redhat.com/"
REDHAT_BUGZILLA_PRODUCT="OpenShift Container Platform"
REDHAT_BUGZILLA_PRODUCT_VERSION="4.11"
REDHAT_SUPPORT_PRODUCT="OpenShift Container Platform"
REDHAT_SUPPORT_PRODUCT_VERSION="4.11"
OPENSHIFT_VERSION="4.11"
RHEL_VERSION="8.6"
OSTREE_VERSION="411.86.202212072103-0"
`

	ff := detectors.FeatureFile{Data: []byte(osRel)}
	files := map[string]*detectors.FeatureFile{
		"etc/os-release": &ff,
	}

	nss := detectors.DetectNamespace(files)
	if nss.Name != "rhcos:4.11" || nss.RHELVer != "8.6" {
		t.Errorf("Incorrect os: %+v\n", nss)
	}

	ns, db := os2DB(nss)
	if ns != "centos:8" || db != common.DBCentos {
		t.Errorf("Incorrect os: ns=%s db=%v\n", ns, db)
	}
}

// TestEpochComparison ensures that a namespace in skipEpochNamespaces properly calls alternate version comparison logic and returns the expected result.
func TestEpochComparison(t *testing.T) {
	expected1 := 1
	expected2 := 0
	nsWithoutEpoch := "amzn:2023"
	nsWithEpoch := "rhel:8"
	verString := "0:1.5"
	shortVulMap := map[string][]common.VulShort{
		"rhel:8:test": {{
			Name:      "CVE-1",
			Namespace: "rhel:8",
			Fixin: []common.FeaShort{
				{
					Name:    "test",
					Version: "1:1.0",
					MinVer:  "",
				},
			},
			CPEs: []string{},
		},
		},
		"amzn:2023:test": {{
			Name:      "CVE-1",
			Namespace: "amzn:2023",
			Fixin: []common.FeaShort{
				{
					Name:    "test",
					Version: "1:1.0",
					MinVer:  "",
				},
			},
			CPEs: []string{},
		},
		},
	}
	version, err := utils.NewVersion(verString)
	if err != nil {
		t.Errorf("error creating version: %+v\n", err)
	}
	feature := detectors.FeatureVersion{
		Package:    "test",
		File:       "",
		Version:    version,
		MinVer:     utils.Version{},
		ModuleVuls: []detectors.ModuleVul{},
		CPEs:       nil,
		InBase:     false,
	}

	//Check for epoch behavior, this uses the original Compare()
	vuls, modvul := searchAffectedFeature(shortVulMap, nsWithEpoch, feature)
	//should return 1 vuln because epoch comparison is used 0:1.5 < 1:1.0
	if len(vuls) != expected1 || len(modvul) != expected1 {
		t.Errorf("error with epoch comparison, expected results: %+v, returned %v\n", expected1, len(modvul))
	}

	//Check for without epoch behavior, this uses CompareWithoutEpoch() due to the namespace being included in cvesearch.skipEpochNamespaces.
	vuls, modvul = searchAffectedFeature(shortVulMap, nsWithoutEpoch, feature)
	//should return 0 vuln because epoch comparison is NOT used 1.5 > 1.0
	if len(vuls) != expected2 || len(modvul) != expected2 {
		t.Errorf("error without epoch comparison, expected results: %+v, returned %v\n", expected2, len(modvul))
	}
}
