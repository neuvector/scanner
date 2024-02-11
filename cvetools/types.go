package cvetools

import (
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
	"github.com/neuvector/scanner/common"
	"github.com/neuvector/scanner/detectors"
)

type updateData struct {
	Redhat  bool
	Debian  bool
	Ubuntu  bool
	Alpine  bool
	Amazon  bool
	Oracle  bool
	Suse    bool
	Mariner bool
}

type ScanTools struct {
	common.CveDB
	RtSock    string
	SupportOs utils.Set
	sys       *system.SystemTools
}

type vulShortReport struct {
	Vs common.VulShort
	Ft detectors.FeatureVersion
}

type vulFullReport struct {
	Vf common.VulFull
	Ft detectors.FeatureVersion
}
