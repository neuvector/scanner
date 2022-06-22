package cvetools

import (
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

func TestSelectDB(t *testing.T) {
	type result struct {
		ns string
		db int
	}

	tests := map[string]result{
		"alpine:3.4.6":       result{"alpine:3.4", common.DBAlpine},
		"rhel:8.3":           result{"centos:8.3", common.DBCentos},
		"mariner:1.0":        result{"mariner:1.0", common.DBMariner},
		"opensuse-leap:15.2": result{"sles:l15.2", common.DBSuse},
	}

	for ns, r := range tests {
		var db int
		ns, db = selectDB(ns)
		if ns != r.ns || db != r.db {
			t.Errorf("Incorrect result:  %s != %s or %d != %d", ns, r.ns, db, r.db)
		}
	}
}
