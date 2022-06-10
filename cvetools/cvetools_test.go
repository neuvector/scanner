package cvetools

import (
	"fmt"
	"testing"

	"github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/scanner/common"
)

const testTmpPath = "/tmp/scanner_test/"

func checkVul(vuls []vulFullReport, name string) bool {
	for _, vul := range vuls {
		if vul.Vf.Name == name {
			return true
		}
	}
	return false
}

func makePlatformReq(k8s, oc string) []scan.AppPackage {
	pkgs := make([]scan.AppPackage, 0)
	if oc != "" {
		pkgs = append(pkgs, scan.AppPackage{
			AppName:    "openshift",
			ModuleName: "openshift.kubernetes",
			Version:    oc,
			FileName:   "kubernetes",
		})
		pkgs = append(pkgs, scan.AppPackage{
			AppName:    "openshift",
			ModuleName: "openshift",
			Version:    oc,
			FileName:   "openshift",
		})
	} else if k8s != "" {
		pkgs = append(pkgs, scan.AppPackage{
			AppName:    "kubernetes",
			ModuleName: "kubernetes",
			Version:    k8s,
			FileName:   "kubernetes",
		})
	}
	return pkgs
}

func testRHSACulling(t *testing.T) {
	fullVulns := make(map[string]common.VulFull)
	fixedIn1 := common.FeaFull{
		Name:      "ldap",
		Namespace: "centos7",
	}
	fixedIn2 := common.FeaFull{
		Name:      "ldap",
		Namespace: "centos8",
	}
	fixedIn3 := common.FeaFull{
		Name:      "openldap",
		Namespace: "centos7",
	}
	full1 := common.VulFull{
		Name:      "CVE-2021-2222",
		Namespace: "centos7",
		FixedIn:   []common.FeaFull{fixedIn1, fixedIn3},
		CPEs:      []string{},
		CVEs:      []string{},
	}
	full2 := common.VulFull{
		Name:      "RHSA-33",
		Namespace: "centos7",
		FixedIn:   []common.FeaFull{fixedIn1},
		CPEs:      []string{},
		CVEs:      []string{"CVE-2021-2222"},
	}
	full3 := common.VulFull{
		Name:      "RHSA-34",
		Namespace: "centos8",
		FixedIn:   []common.FeaFull{fixedIn2, fixedIn3},
		CPEs:      []string{},
		CVEs:      []string{"CVE-2021-2223", "CVE-2021-2225"},
	}

	full4 := common.VulFull{
		Name:      "CVE-2021-2223",
		Namespace: "centos8",
		FixedIn:   []common.FeaFull{fixedIn2},
		CPEs:      []string{},
		CVEs:      []string{},
	}
	full5 := common.VulFull{
		Name:      "CVE-2021-2224",
		Namespace: "centos8",
		FixedIn:   []common.FeaFull{fixedIn1, fixedIn2, fixedIn3},
		CPEs:      []string{},
		CVEs:      []string{},
	}
	full6 := common.VulFull{
		Name:      "CVE-2021-2225",
		Namespace: "centos8",
		FixedIn:   []common.FeaFull{fixedIn2, fixedIn3},
		CPEs:      []string{},
		CVEs:      []string{},
	}
	key1 := fmt.Sprintf("%v:%v", full1.Namespace, full1.Name)
	fullVulns[key1] = full1
	key2 := fmt.Sprintf("%v:%v", full2.Namespace, full2.Name)
	fullVulns[key2] = full2
	key3 := fmt.Sprintf("%v:%v", full3.Namespace, full3.Name)
	fullVulns[key3] = full3
	key4 := fmt.Sprintf("%v:%v", full4.Namespace, full4.Name)
	fullVulns[key4] = full4
	key5 := fmt.Sprintf("%v:%v", full5.Namespace, full5.Name)
	fullVulns[key5] = full5
	key6 := fmt.Sprintf("%v:%v", full6.Namespace, full6.Name)
	fullVulns[key6] = full6

	shortVulns := make([]common.VulShort, 0)
	fulls, _ := cullAllVulns(fullVulns, shortVulns)
	if len(fulls) != 4 {
		t.Fail()
		t.Logf("FAIL - Length of vulnerabilities expected: 4, Found: %v\n", len(fulls))
	}
	if len(fulls[key1].FixedIn) != 1 {
		t.Fail()
		t.Logf("FAIL - Length of features expected for key1: 1, Found: %v\n", len(fulls[key1].FixedIn))
	}
	if len(fulls[key5].FixedIn) != 3 {
		t.Fail()
		t.Logf("FAIL - Length of features expected for key5: 3, Found: %v\n", len(fulls[key5].FixedIn))
	}
	if len(fulls[key2].FixedIn) != 1 {
		t.Fail()
		t.Logf("FAIL - Length of RHSA features expected for key2: 1, Found: %v\n", len(fulls[key2].FixedIn))
	}
	if len(fulls[key3].FixedIn) != 2 {
		t.Fail()
		t.Logf("FAIL - Length of RHSA features expected for key3: 2, Found: %v\n", len(fulls[key3].FixedIn))
	}
	if _, ok := fulls[key4]; ok {
		t.Fail()
		t.Logf("FAIL - Entry Not Culled: %v\n", fulls[key4])
	}
	if _, ok := fulls[key6]; ok {
		t.Fail()
		t.Logf("FAIL - Entry Not Culled: %v\n", fulls[key6])
	}
}
