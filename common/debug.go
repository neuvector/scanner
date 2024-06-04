package common

import (
	"strings"

	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

type DebugFilter struct {
	Enabled  bool
	CVEs     utils.Set
	Features utils.Set
}

var Debugs DebugFilter

func InitDebugFilters(s string) {
	Debugs.CVEs = utils.NewSet()
	Debugs.Features = utils.NewSet()

	if s != "" {
		Debugs.Enabled = true

		tokens := strings.Split(s, ",")
		for _, token := range tokens {
			kvs := strings.Split(token, "=")
			if len(kvs) >= 2 {
				switch kvs[0] {
				case "v":
					vuls := strings.Split(kvs[1], ",")
					for _, v := range vuls {
						Debugs.CVEs.Add(v)
					}
					log.WithFields(log.Fields{"vuls": Debugs.CVEs}).Debug("vulnerability filter")
				case "f":
					fs := strings.Split(kvs[1], ",")
					for _, f := range fs {
						Debugs.Features.Add(f)
					}
					log.WithFields(log.Fields{"features": Debugs.Features}).Debug("feature filter")
				}
			}
		}
	}
}
