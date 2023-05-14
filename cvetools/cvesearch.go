package cvetools

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/httptrace"
	"github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/scan/secrets"
	"github.com/neuvector/neuvector/share/utils"
	"github.com/neuvector/scanner/common"
	"github.com/neuvector/scanner/detectors"
	_ "github.com/neuvector/scanner/detectors/feature/apk"
	_ "github.com/neuvector/scanner/detectors/feature/dpkg"
	_ "github.com/neuvector/scanner/detectors/feature/others"
	_ "github.com/neuvector/scanner/detectors/feature/rpm"
	_ "github.com/neuvector/scanner/detectors/namespace/aptsources"
	_ "github.com/neuvector/scanner/detectors/namespace/lsbrelease"
	_ "github.com/neuvector/scanner/detectors/namespace/osrelease"
	_ "github.com/neuvector/scanner/detectors/namespace/redhatrelease"
)

const (
	maxFileSize     = 300 * 1024 * 1024
	contentManifest = "root/buildinfo/content_manifests"
)

var redhat_db []common.VulShort = nil
var debian_db []common.VulShort = nil
var ubuntu_db []common.VulShort = nil
var alpine_db []common.VulShort = nil
var amazon_db []common.VulShort = nil
var oracle_db []common.VulShort = nil
var mariner_db []common.VulShort = nil
var suse_db []common.VulShort = nil

var redhat_fdb map[string]common.VulFull
var debian_fdb map[string]common.VulFull
var ubuntu_fdb map[string]common.VulFull
var alpine_fdb map[string]common.VulFull
var amazon_fdb map[string]common.VulFull
var oracle_fdb map[string]common.VulFull
var mariner_fdb map[string]common.VulFull
var suse_fdb map[string]common.VulFull

///////
const tbPath = "/tmp/neuvector/db/"

type featureVulnWindow struct {
	featureName      string
	featureNamespace string
	minOp            string
	min              string
	maxOp            string
	max              string
}

///////
var cveTools *CveTools
var overrideMap map[string][]featureVulnWindow = map[string][]featureVulnWindow{
	"CVE-2019-13509": {
		{
			featureName:      "docker-ce",
			featureNamespace: "centos:7",
			minOp:            "gteq",
			min:              "#MINV#",
			maxOp:            "lt",
			max:              "18.09.8",
		}},
	"CVE-2021-21284": {
		{
			featureName:      "docker-ce",
			featureNamespace: "centos:7",
			minOp:            "gteq",
			min:              "#MINV#",
			maxOp:            "lt",
			max:              "20.10.3",
		}},
	"CVE-2021-21285": {
		{
			featureName:      "docker-ce",
			featureNamespace: "centos:7",
			minOp:            "gteq",
			min:              "#MINV#",
			maxOp:            "lt",
			max:              "20.10.3",
		}},
}

var aliasMap map[string]string = map[string]string{
	"docker-ce": "docker"}

// NewCveTools establishs the initialization of cve tool
func NewCveTools(rtSock string, scanTool *scan.ScanUtil) *CveTools {
	return &CveTools{ // available inside package
		TbPath:   tbPath,
		RtSock:   rtSock,
		ScanTool: scanTool,
	}
}

/*
func diffFeatures(lastFeat, features []detectors.FeatureVersion) []detectors.FeatureVersion {
	dfeats := make([]detectors.FeatureVersion, 0)
	fmap := make(map[string]*detectors.FeatureVersion)
	for i, ft := range lastFeat {
		fmap[ft.Feature.Name] = &lastFeat[i]
	}
	for _, ft := range features {
		if lf, ok := fmap[ft.Feature.Name]; !ok || lf.Version != ft.Version {
			dfeats = append(dfeats, ft)
		}
	}
	return dfeats
}
*/

type layerScanFiles struct {
	pkgs map[string]*detectors.FeatureFile
	apps []detectors.AppFeatureVersion
}

func (cv *CveTools) ScanImageData(data *share.ScanData) (*share.ScanResult, error) {
	result := &share.ScanResult{
		Provider:        share.ScanProvider_Neuvector,
		Version:         cv.CveDBVersion,
		CVEDBCreateTime: cv.CveDBCreateTime,
	}

	pkgs, err := utils.SelectivelyExtractArchive(bytes.NewReader(data.Buffer), func(filename string) bool {
		return true
	}, maxFileSize)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("read file error")
		return result, err
	}

	files := make(map[string]*detectors.FeatureFile)
	for name, data := range pkgs {
		files[name] = &detectors.FeatureFile{Data: data}
	}
	appPkgs := scan.NewScanApps(true).DerivePkg(pkgs)

	// convert AppPackage to AppFeatureVersion
	afvs := make([]detectors.AppFeatureVersion, len(appPkgs))
	for i, a := range appPkgs {
		afvs[i] = detectors.AppFeatureVersion{AppPackage: a, ModuleVuls: make([]detectors.ModuleVul, 0)}
	}

	namespace, serr, vuls, features, apps := cv.doScan(&layerScanFiles{pkgs: files, apps: afvs}, nil)
	result.Error = serr
	result.Vuls = vuls

	if namespace != nil {
		result.Namespace = namespace.Name
		result.Modules = feature2Module(namespace.Name, features, apps)
	}

	return result, nil
}

// ScanAppPackage helps scanning application packages
func (cv *CveTools) ScanAppPackage(req *share.ScanAppRequest, namespace string) (*share.ScanResult, error) {
	var apps []detectors.AppFeatureVersion

	for _, ap := range req.Packages {
		afv := detectors.AppFeatureVersion{
			AppPackage: scan.AppPackage{
				AppName:    ap.AppName,
				ModuleName: ap.ModuleName,
				Version:    ap.Version,
				FileName:   ap.FileName,
			},
		}
		apps = append(apps, afv)
	}

	appvuls := cv.DetectAppVul(cv.TbPath, apps, namespace)
	vulList := getVulItemList(appvuls, common.DBAppName)

	result := &share.ScanResult{
		Provider:        share.ScanProvider_Neuvector,
		Version:         cv.CveDBVersion,
		CVEDBCreateTime: cv.CveDBCreateTime,
		Error:           share.ScanErrorCode_ScanErrNone,
		Vuls:            vulList,
		Modules:         feature2Module(namespace, nil, apps),
	}
	return result, nil
}

// ScanImage helps the Image scanning
func (cv *CveTools) ScanImage(ctx context.Context, req *share.ScanImageRequest, imgPath string) (*share.ScanResult, error) {
	var err error
	result := &share.ScanResult{
		Provider:        share.ScanProvider_Neuvector,
		Version:         cv.CveDBVersion,
		CVEDBCreateTime: cv.CveDBCreateTime,
		Error:           share.ScanErrorCode_ScanErrNone,
		Registry:        req.Registry,
		Repository:      req.Repository,
		Tag:             req.Tag,
		Layers:          make([]*share.ScanLayerResult, 0),
	}

	var baseReg, baseRepo, baseTag string
	if req.BaseImage != "" {
		reg, repo, tag, err := scan.ParseImageName(req.BaseImage)
		if err != nil {
			log.WithFields(log.Fields{
				"base": req.BaseImage, "error": err,
			}).Error("Failed to parse base image")

			result.Error = share.ScanErrorCode_ScanErrArgument
			return result, nil
		}

		baseReg = reg
		baseRepo = repo
		baseTag = tag
	}

	var info *scan.ImageInfo
	var layerFiles map[string]*scan.LayerFiles
	var baseLayers utils.Set = utils.NewSet()
	var secret *share.ScanSecretResult = &share.ScanSecretResult{
		Error: share.ScanErrorCode_ScanErrNone,
		Logs:  make([]*share.ScanSecretLog, 0),
	}
	// var layeredSecret []*share.ScanSecretResult
	var setidPerm []*share.ScanSetIdPermLog
	var layers []string

	// for layered storages
	if imgPath == "" { // not-defined yet
		imgPath = CreateImagePath("")
		defer os.RemoveAll(imgPath)
	}

	if req.Registry != "" {
		var errCode share.ScanErrorCode

		if baseRepo != "" {
			if baseReg == "" {
				log.WithFields(log.Fields{
					"base": req.BaseImage,
				}).Error("Base image must be remote if the image to be scanned is remote")
				result.Error = share.ScanErrorCode_ScanErrNotSupport
				return result, nil
			}

			rc := scan.NewRegClient(baseReg, req.Username, req.Password, req.Proxy, new(httptrace.NopTracer))
			info, errCode = rc.GetImageInfo(ctx, baseRepo, baseTag)
			if errCode != share.ScanErrorCode_ScanErrNone {
				result.Error = errCode
				return result, nil
			}

			for _, l := range info.Layers {
				baseLayers.Add(l)
			}

			log.WithFields(log.Fields{"baseImage": req.BaseImage, "base": baseLayers, "layers": len(info.Layers)}).Debug()
		}

		rc := scan.NewRegClient(req.Registry, req.Username, req.Password, req.Proxy, new(httptrace.NopTracer))

		info, errCode = rc.GetImageInfo(ctx, req.Repository, req.Tag)
		if errCode != share.ScanErrorCode_ScanErrNone {
			result.Error = errCode
			return result, nil
		}

		// There is a download timeout inside this function
		layerFiles, errCode = rc.DownloadRemoteImage(ctx, req.Repository, imgPath, info.Layers, info.Sizes)
		if errCode != share.ScanErrorCode_ScanErrNone {
			result.Error = errCode
			return result, nil
		}

		signatureData, errCode := rc.GetSignatureDataForImage(ctx, req.Repository, info.Digest)
		if errCode != share.ScanErrorCode_ScanErrNone {
			result.Error = errCode
			return result, fmt.Errorf("error code when getting signature data for image: %s", errCode.String())
		}

		result.Verifiers, err = verifyImageSignatures(info.Digest, req.RootsOfTrust, signatureData)
		if err != nil {
			return result, fmt.Errorf("error verifying signatures for image: %s", err.Error())
		}

		layers = info.Layers
		for _, lf := range layerFiles {
			result.Size += lf.Size
		}
		result.ImageID = info.ID
		result.Digest = info.Digest
		log.WithFields(log.Fields{"layers": len(info.Layers), "id": info.ID, "digest": info.Digest, "size": result.Size}).Debug("scan remote image")
	} else {
		var errCode share.ScanErrorCode

		if baseRepo != "" {
			if baseReg != "" {
				log.WithFields(log.Fields{
					"base": req.BaseImage,
				}).Error("Base image must be local if the image to be scanned is local")
				result.Error = share.ScanErrorCode_ScanErrNotSupport
				return result, nil
			}

			meta, errCode := cv.ScanTool.GetLocalImageMeta(ctx, baseRepo, baseTag, cv.RtSock)
			if errCode != share.ScanErrorCode_ScanErrNone {
				result.Error = errCode
				return result, nil
			}

			for _, l := range meta.Layers {
				baseLayers.Add(l)
			}

			log.WithFields(log.Fields{"baseImage": req.BaseImage, "base": baseLayers, "layers": len(meta.Layers)}).Debug()
		}

		info, layerFiles, layers, errCode = cv.ScanTool.LoadLocalImage(ctx, req.Repository, req.Tag, cv.RtSock, imgPath)
		if errCode != share.ScanErrorCode_ScanErrNone {
			result.Error = errCode
			return result, nil
		}

		for _, lf := range layerFiles {
			result.Size += lf.Size
		}
		result.ImageID = info.ID
		result.Digest = info.Digest
		log.WithFields(log.Fields{"layers": len(info.Layers), "id": info.ID, "digest": info.Digest, "size": result.Size}).Debug("scan local image")

		// The following 2 commands actually inpect the same image
		// 	echo -e "GET /images/nvlab/iperf/json HTTP/1.0\r\n" | nc -U /var/run/docker.sock
		// 	echo -e "GET /images/docker.io/nvlab/iperf/json HTTP/1.0\r\n" | nc -U /var/run/docker.sock
	}

	// For those package manager files, they can exist in multiple layers, the upper layer has the superset (if no deletion).
	// Scan the file in the upper layer is enough for image scan, but if we want to identify if the package is installed in
	// the base layer, we will mark all packages as "not in base". This is why we need scan layers again if BaseImage variable
	// is not empty.
	var scanLayers bool
	if req.ScanLayers || req.BaseImage != "" {
		// verify the info matching
		if len(info.Layers) != len(info.Cmds) {
			log.WithFields(log.Fields{"layer": len(info.Layers), "cmds": len(info.Cmds)}).Error("layer and cmds not match")
			scanLayers = false
		} else {
			// initialize layered structures
			result.Layers = make([]*share.ScanLayerResult, len(info.Layers))
			scanLayers = true
		}
	}

	// Build a map for whole image
	fileMap := make(map[string]string) // [path]:[file from untar layers]
	for i := len(layers) - 1; i >= 0; i-- {
		layerPath := filepath.Join(imgPath, layers[i])
		if _, err := collectImageFileMap(layerPath, fileMap); err != nil {
			log.WithFields(log.Fields{"error": err, "layer": layerPath}).Error("virtual image map")
			break
		}
	}

	// parallel scanning: cve and secrets
	done := make(chan bool, 1)
	if req.ScanSecrets {
		go func() {
			log.Info("Scanning secrets ....")
			config := secrets.Config{
				MiniWeight: 0.1, // Some other texts will dilute the weight, so it is better to stay at a smaller weight
			}

			// Include env variables into the search
			buffers := &bytes.Buffer{}
			for _, s := range info.Envs {
				buffers.WriteString(s)
				buffers.WriteByte('\n')
			}
			envVars, _ := ioutil.ReadAll(buffers)
			logs, perms, err := secrets.FindSecretsByFilePathMap(fileMap, envVars, config)
			secret = buildSecretResult(logs, err)
			setidPerm = buildSetIdPermLogs(perms)
			log.Info("Done secrets ....")
			done <- true
		}()
	} else {
		done <- false // bypass
	}

	// Merge file data, layer order in schema V1, the first is the latest layer
	gotFirstCpe := false
	mergedFiles := make(map[string]*detectors.FeatureFile)
	mergedApps := make(map[string][]detectors.AppFeatureVersion)
	for _, l := range info.Layers {
		isBase := baseLayers.Contains(l)
		if lf, ok := layerFiles[l]; ok {
			var hasRpmPackages bool
			for filename, _ := range lf.Pkgs {
				if scan.RPMPkgFiles.Contains(filename) {
					hasRpmPackages = true
					break
				}
			}

			for filename, data := range lf.Pkgs {
				if _, ok := mergedFiles[filename]; !ok {
					// for redhat CPE
					if strings.HasPrefix(filename, contentManifest) && strings.HasSuffix(filename, ".json") {
						if hasRpmPackages && !gotFirstCpe {
							mergedFiles[filename] = &detectors.FeatureFile{Data: data, InBase: isBase}
							gotFirstCpe = true
						}
					} else {
						mergedFiles[filename] = &detectors.FeatureFile{Data: data, InBase: isBase}
					}
				}
			}
			for filename, apps := range lf.Apps {
				fpath := filepath.Join("/", filename) // add "/" at its front
				if pos := strings.Index(fpath, ":"); pos > 0 {
					// jar: a package inside a package
					fpath = fpath[:pos]
				}

				if _, ok := fileMap[fpath]; !ok {
					// log.WithFields(log.Fields{"filename": fpath, "apps": apps}).Info("Ignore")
					continue
				}

				if _, ok := mergedApps[filename]; !ok {
					// convert AppPackage to AppFeatureVersion
					afvs := make([]detectors.AppFeatureVersion, len(apps))
					for i, a := range apps {
						afvs[i] = detectors.AppFeatureVersion{
							AppPackage: a,
							ModuleVuls: make([]detectors.ModuleVul, 0),
							InBase:     isBase,
						}
					}

					mergedApps[filename] = afvs
				}
			}
		}
	}

	appFVs := make([]detectors.AppFeatureVersion, 0)
	for _, afvs := range mergedApps {
		appFVs = append(appFVs, afvs...)
	}

	namespace, serr, vuls, features, apps := cv.doScan(&layerScanFiles{pkgs: mergedFiles, apps: appFVs}, nil)
	if namespace != nil {
		result.Namespace = namespace.Name
		result.Modules = feature2Module(namespace.Name, features, apps)
	}
	result.Error = serr
	result.Vuls = vuls
	result.Author = info.Author
	result.Envs = info.Envs
	result.Labels = info.Labels
	result.Cmds = info.Cmds

	// scan layer
	if serr == share.ScanErrorCode_ScanErrNone && scanLayers {
		for i := len(info.Layers) - 1; i >= 0; i-- {
			layer := info.Layers[i]
			if layer == "" {
				// This could be empty layers of local images
				l := &share.ScanLayerResult{
					Digest: layer,
					Vuls:   make([]*share.ScanVulnerability, 0),
					Cmds:   info.Cmds[i],
					Size:   0,
				}
				result.Layers[i] = l
			} else if lf, ok := layerFiles[layer]; ok {
				if lf.Size > 0 {
					var vuls []*share.ScanVulnerability

					isBase := baseLayers.Contains(layer)

					log.WithFields(log.Fields{"layer": layer, "cmd": info.Cmds[i], "base": isBase, "size": lf.Size}).Debug("scan layer")

					files := make(map[string]*detectors.FeatureFile)
					appFVs = make([]detectors.AppFeatureVersion, 0)
					for filename, data := range lf.Pkgs {
						files[filename] = &detectors.FeatureFile{Data: data, InBase: isBase}
					}
					for _, apps := range lf.Apps {
						// convert AppPackage to AppFeatureVersion
						afvs := make([]detectors.AppFeatureVersion, len(apps))
						for i, a := range apps {
							afvs[i] = detectors.AppFeatureVersion{AppPackage: a, ModuleVuls: make([]detectors.ModuleVul, 0), InBase: isBase}
						}
						appFVs = append(appFVs, afvs...)
					}
					_, _, vuls, _, _ = cv.doScan(&layerScanFiles{pkgs: files, apps: appFVs}, namespace)
					l := &share.ScanLayerResult{
						Digest: layer,
						Vuls:   vuls,
						Cmds:   info.Cmds[i],
						Size:   lf.Size,
					}
					result.Layers[i] = l
					log.WithFields(log.Fields{"vuls": len(vuls), "layer": layer}).Debug("scan layer done")
				} else {
					l := &share.ScanLayerResult{
						Digest: layer,
						Vuls:   make([]*share.ScanVulnerability, 0),
						Cmds:   info.Cmds[i],
						Size:   lf.Size,
					}
					result.Layers[i] = l
				}
			} else {
				log.WithFields(log.Fields{"layer": layer}).Error("layer not found")
			}
		}
	}

	log.Info("Done cve ....")
	// parallely scanning: done and collecting data
	<-done
	close(done)
	log.WithFields(log.Fields{"id": info.ID, "secrets": len(secret.Logs), "vuls": len(vuls)}).Info("scan image done")

	// Correct CVE in-base flag
	if req.BaseImage != "" {
		vulMap := make(map[string]*share.ScanVulnerability)
		for _, v := range result.Vuls {
			vulMap[v.Name] = v
		}

		for i := len(result.Layers) - 1; i >= 0; i-- {
			layer := result.Layers[i]
			if !baseLayers.Contains(layer.Digest) {
				break
			}

			for _, lv := range layer.Vuls {
				if v, ok := vulMap[lv.Name]; ok {
					v.InBase = true
				}
			}
		}
	}

	// Clean up layer result if it is not requested.
	if !req.ScanLayers {
		result.Layers = nil
	}

	result.Secrets = secret
	result.SetIdPerms = setidPerm
	if req.ScanLayers {
		if scanLayers {
			//	if req.ScanSecrets {
			//		for i := len(info.Layers) - 1; i >= 0; i-- {
			//			result.Layers[i].Secrets = layeredSecret[i]
			//		}
			//	}
		} else {
			// layer scan is disabled because of its mis-matched info
			result.Error = share.ScanErrorCode_ScanErrRegistryAPI
		}
	}

	// bs, _ := json.Marshal(result)
	// fmt.Println(string(bs[:]))

	return result, nil
}

// ScanAwsLambda helps the AWS Lambda scanning
func (cv *CveTools) ScanAwsLambda(req *share.ScanAwsLambdaRequest, imgPath string) (*share.ScanResult, error) {
	result := &share.ScanResult{
		Provider:        share.ScanProvider_Neuvector,
		Version:         cv.CveDBVersion,
		CVEDBCreateTime: cv.CveDBCreateTime,
	}

	uid := uuid.New().String()
	filename := fmt.Sprintf("/tmp/%s-%s-%s.zip", req.Region, req.FuncName, uid)
	err := downloadFromUrl(req.FuncLink, filename)
	if err != nil {
		log.WithFields(log.Fields{"Lambda": req.FuncName}).Error("Lambada Func download fail")
		result.Error = share.ScanErrorCode_ScanErrAwsDownloadErr
		return result, nil
	}

	// for scan Secrets by request
	// parallel scanning: cve and secrets
	done := make(chan bool, 1)
	if req.ScanSecrets {
		// for scan Secrets
		if imgPath == "" { // not-defined yet
			imgPath = CreateImagePath("")
			defer os.RemoveAll(imgPath)
		}

		if err := utils.Unzip(filename, imgPath); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("no unzipped packages")
		}

		go func() {
			log.Info("Scanning secrets ....")
			config := secrets.Config{
				MaxFileSize: 16 * 1024, //
				MiniWeight:  0.1,       // Some other texts will dilute the weight, so it is better to stay at a smaller weight
			}

			var envVars []byte
			logs, perms, err := secrets.FindSecretsByRootpath(imgPath, envVars, config)
			result.Secrets = buildSecretResult(logs, err)
			result.SetIdPerms = buildSetIdPermLogs(perms)
			log.Info("Done secrets ....")
			done <- true
		}()
	} else {
		done <- false // bypass
	}

	appPkg, err := scan.GetAwsFuncPackages(filename)
	if err != nil {
		log.WithFields(log.Fields{"Lambda": req.FuncName}).Error("Lambada Func pkg find fail")
		result.Error = share.ScanErrorCode_ScanErrFileSystem
		return result, nil
	}

	reqs := &share.ScanAppRequest{
		Packages: appPkg,
	}

	res, err := cv.ScanAppPackage(reqs, "")
	<-done

	// merge results here
	if res == nil {
		return result, err
	}
	res.Secrets = result.Secrets
	return res, err
}

var releaseRegexp = regexp.MustCompile(`^([a-z-]+):([0-9.]+)`)

func (cv *CveTools) doScan(layerFiles *layerScanFiles, imageNs *detectors.Namespace) (*detectors.Namespace, share.ScanErrorCode, []*share.ScanVulnerability, []detectors.FeatureVersion, []detectors.AppFeatureVersion) {
	features, namespace, apps, serr := cv.getFeatures(layerFiles, imageNs)

	var ns detectors.Namespace
	if namespace != nil {
		ns = *namespace
	}
	if serr != share.ScanErrorCode_ScanErrNone {
		return namespace, serr, nil, nil, nil
	}

	errCode, vuls := cv.startScan(features, ns.Name, apps)
	return namespace, errCode, vuls, features, apps
}

func os2DB(nsName string) (string, int) {
	db := common.DBMax
	r := releaseRegexp.FindStringSubmatch(nsName)
	if len(r) == 3 {
		switch r[1] {
		case "ubuntu":
			db = common.DBUbuntu
		case "debian":
			db = common.DBDebian
		case "rhel", "server", "centos":
			if dot := strings.Index(r[2], "."); dot != -1 {
				nsName = "centos:" + r[2][:dot]
			} else {
				nsName = "centos:" + r[2]
			}
			db = common.DBCentos
			log.Info("namespace map to: ", nsName)
		case "fedora":
			// Map to ubuntu upstream: NVSHAS-6723
			nsName = "ubuntu:upstream"
			db = common.DBUbuntu
		case "rhcos":
			// unsupported
		case "alpine":
			nsName = removeSubVersion(nsName)
			db = common.DBAlpine
		case "amzn":
			// amazon linux only has two versions: 1, 2
			if v := strings.TrimPrefix(nsName, "amzn:"); v != "2" {
				nsName = "amzn:1"
			}
			db = common.DBAmazon
		case "ol":
			majorVersion := majorVersion(r[2])
			nsName = "oracle:" + majorVersion
			db = common.DBOracle
		case "mariner":
			nsName = r[1] + ":" + r[2]
			db = common.DBMariner
		case "sles":
			db = common.DBSuse
		case "opensuse-leap":
			nsName = "sles:l" + r[2]
			db = common.DBSuse
		}
	}
	return nsName, db
}

func (cv *CveTools) startScan(features []detectors.FeatureVersion, nsName string, appPkg []detectors.AppFeatureVersion) (share.ScanErrorCode, []*share.ScanVulnerability) {
	var db int
	var vss []common.VulShort
	var vfs map[string]common.VulFull
	var err error

	nsName, db = os2DB(nsName)
	if db == common.DBMax {
		log.WithFields(log.Fields{"os": nsName}).Info("Unsupported OS")
		return share.ScanErrorCode_ScanErrNone, make([]*share.ScanVulnerability, 0)
	}

	cv.UpdateMux.Lock()
	defer cv.UpdateMux.Unlock()

	if common.DBS.Buffers[db].Short == nil {
		common.DBS.Buffers[db].Short, err = common.LoadVulnerabilityIndex(cv.TbPath, common.DBS.Buffers[db].Name)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Load Database error:", common.DBS.Buffers[db].Name)
			return share.ScanErrorCode_ScanErrDatabase, nil
		}
		common.DBS.Buffers[db].Full, err = common.LoadFullVulnerabilities(cv.TbPath, common.DBS.Buffers[db].Name)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Load full Database error:", common.DBS.Buffers[db].Name)
			return share.ScanErrorCode_ScanErrDatabase, nil
		}
	}

	vss = common.DBS.Buffers[db].Short
	vfs = common.DBS.Buffers[db].Full

	log.WithFields(log.Fields{"db": common.DBS.Buffers[db].Name, "namespace": nsName, "short": len(vss), "full": len(vfs)}).Info("Load Database")

	var vulList []*share.ScanVulnerability
	var vuls []vulFullReport

	if vss != nil {
		// build feature -> vul version map for search use
		mv := makeFeatureMap(vss, nsName)
		log.WithFields(log.Fields{"count": len(mv)}).Info("Packages in database to be examed")

		// get the vulnerbilitys from the hash map, associate them with the modules in features.
		avsr := getAffectedVul(mv, features, nsName)
		updateModuleCVEStatus(nsName, features, vfs)

		// get the full vulneribility description from full database
		vuls = getFullAffectedVul(avsr, vfs)
		vulList = append(vulList, getVulItemList(vuls, common.DBS.Buffers[db].Name)...)
	}

	if len(appPkg) != 0 {
		appvuls := cv.DetectAppVul(cv.TbPath, appPkg, nsName)
		vulList = append(vulList, getVulItemList(appvuls, common.DBAppName)...)
	}

	return share.ScanErrorCode_ScanErrNone, vulList
}

func updateModuleCVEStatus(nsName string, features []detectors.FeatureVersion, vfs map[string]common.VulFull) {
	for _, ft := range features {
		for i, cve := range ft.ModuleVuls {
			name := cve.Name
			kname := fmt.Sprintf("%s:%s", nsName, name)
			if vf, ok := vfs[kname]; ok {
				if cve.Status == share.ScanVulStatus_Unpatched &&
					(strings.Contains(vf.Description, "will not fix")) {
					ft.ModuleVuls[i].Status = share.ScanVulStatus_WillNotFix
				}
			}
		}
	}
}

func getFullAffectedVul(avs []vulShortReport, vfs map[string]common.VulFull) []vulFullReport {
	vuls := make([]vulFullReport, 0)

	for _, short := range avs {
		name := short.Vs.Name
		// This is CVE name, do we need get prefix here?
		// if a := strings.Index(name, "/"); a > 0 {
		// 	name = name[:a]
		// }
		kname := fmt.Sprintf("%s:%s", short.Vs.Namespace, name)
		vf, ok := vfs[kname]
		if ok {
			for _, fts := range short.Vs.Fixin {
				vf.FixedIn = append(vf.FixedIn, common.FeaFull{
					Name: fts.Name, Namespace: vf.Namespace, Version: fts.Version, MinVer: fts.MinVer, AddedBy: "",
				})
			}
			vfr := vulFullReport{Vf: vf, Ft: short.Ft}
			vuls = append(vuls, vfr)
		}
	}
	return vuls
}

func getAffectedVul(mv map[string][]common.VulShort, features []detectors.FeatureVersion, namespace string) []vulShortReport {
	avs := make([]vulShortReport, 0)

	for i, ft := range features {
		vs, mc := searchAffectedFeature(mv, namespace, ft)
		for _, v := range vs {
			vsr := vulShortReport{Vs: v, Ft: ft}
			avs = append(avs, vsr)
		}
		features[i].ModuleVuls = mc
	}
	return avs
}

func (cv *CveTools) getFeatures(layerFiles *layerScanFiles, imageNs *detectors.Namespace) ([]detectors.FeatureVersion, *detectors.Namespace, []detectors.AppFeatureVersion, share.ScanErrorCode) {
	var namespace *detectors.Namespace

	// Detect namespace.
	layerNs := detectors.DetectNamespace(layerFiles.pkgs)
	// use image namespace if no namespace find in current layer
	if imageNs != nil {
		namespace = imageNs
	} else {
		namespace = layerNs
	}

	var nsName string
	if namespace != nil {
		nsName = namespace.Name
	}

	features, err := detectors.DetectFeatures(nsName, layerFiles.pkgs, cv.TbPath)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("get features error")
		return features, namespace, layerFiles.apps, share.ScanErrorCode_ScanErrPackage
	}

	// get the nginx package from os dpkg or rpm and append it to application package
	for i, ft := range features {
		if ft.Feature.Name == "nginx" {
			nginx := scan.AppPackage{AppName: "nginx", ModuleName: "nginx", Version: ft.Version.String(), FileName: "nginx"}
			app := detectors.AppFeatureVersion{AppPackage: nginx, ModuleVuls: make([]detectors.ModuleVul, 0), InBase: ft.InBase}
			layerFiles.apps = append(layerFiles.apps, app)
		} else if ft.Feature.Name == "openssl" && namespace == nil {
			// add the openssl to the app to compare
			ver := ft.Version.String()
			ssl := scan.AppPackage{AppName: "openssl", ModuleName: "openssl", Version: ver, FileName: "openssl"}
			app := detectors.AppFeatureVersion{AppPackage: ssl, ModuleVuls: make([]detectors.ModuleVul, 0), InBase: ft.InBase}
			layerFiles.apps = append(layerFiles.apps, app)
			features[i].Feature.Name = "opensslxx"
		} else if ft.Feature.Name == "busybox" && namespace == nil {
			namespace = &detectors.Namespace{Name: "busybox" + ":" + ft.Version.String()}
			log.WithFields(log.Fields{"busybox": *namespace}).Debug("BusyBox")

			ver := ft.Version.String()
			bbox := scan.AppPackage{AppName: "busybox", ModuleName: "busybox", Version: ver, FileName: "busybox"}
			app := detectors.AppFeatureVersion{AppPackage: bbox, ModuleVuls: make([]detectors.ModuleVul, 0), InBase: ft.InBase}
			layerFiles.apps = append(layerFiles.apps, app)
		}
	}

	log.WithFields(log.Fields{"apps": len(layerFiles.apps), "features": len(features), "namespace": namespace}).Debug()
	return features, namespace, layerFiles.apps, share.ScanErrorCode_ScanErrNone
}

func isInVulnWindow(window featureVulnWindow, ft detectors.FeatureVersion, minVer utils.Version, maxVer utils.Version) bool {
	switch window.minOp {
	case "gt":
		if ft.Version.Compare(minVer) < 1 {
			return false
		}
	case "gteq":
		if ft.Version.Compare(minVer) < 0 {
			return false
		}
	}
	switch window.maxOp {
	case "lt":
		if ft.Version.Compare(maxVer) > -1 {
			return false
		}
	case "lteq":
		if ft.Version.Compare(maxVer) > 0 {
			return false
		}
	}
	return true
}

// For a given feature ft, return vul list and module list
func searchAffectedFeature(mv map[string][]common.VulShort, namespace string, ft detectors.FeatureVersion) ([]common.VulShort, []detectors.ModuleVul) {
	// feature name can take format util-linux/libsmartcols1, the source is util-linux and should be used to search cve.
	name := ft.Feature.Name
	if a := strings.Index(name, "/"); a > 0 {
		name = name[:a]
	}
	if val, ok := aliasMap[name]; ok {
		name = val
	}
	featName := fmt.Sprintf("%s:%s", namespace, name)
	vs, _ := mv[featName]

	matchMap := make(map[string]share.ScanVulStatus)
	moduleVuls := make([]detectors.ModuleVul, 0)
	affectVs := make([]common.VulShort, 0)

	for _, v := range vs {
		// check redhat cpe. Modules in ubi image has no cpe, so always accept them.
		if v.CPEs != nil && ft.CPEs != nil && ft.CPEs.Cardinality() > 0 {
			match := false
			for _, cpe := range v.CPEs {
				if ft.CPEs.Contains(cpe) {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		afStatus := share.ScanVulStatus_Unaffected
		//if cve in calibrateMap
		if val, ok := overrideMap[v.Name]; ok {
			//Remove fixin entries since this CVE will be overwritten.
			// v.Fixin = nil
			for _, window := range val {
				//Check that the vulnerability matches correct window for the vulnerability.
				if strings.EqualFold(window.featureName, ft.Feature.Name) && strings.EqualFold(window.featureNamespace, namespace) {
					minVer, err := utils.NewVersion(window.min)
					if err != nil {
						log.WithFields(log.Fields{"error": err, "version": window.min}).Error()
						continue
					}
					maxVer, err := utils.NewVersion(window.max)
					if err != nil {
						log.WithFields(log.Fields{"error": err, "version": window.max}).Error()
						continue
					}
					if maxVer == utils.MaxVersion {
						afStatus = share.ScanVulStatus_Unpatched
					} else if maxVer == utils.MinVersion {
						afStatus = share.ScanVulStatus_Unaffected
					} else {
						afStatus = share.ScanVulStatus_FixExists
					}
					//check if module is within version window.
					if !isInVulnWindow(window, ft, minVer, maxVer) {
						continue
					}
					//is within the window
					affectVs = append(affectVs, v)
					if afStatus == share.ScanVulStatus_FixExists ||
						afStatus == share.ScanVulStatus_Unpatched ||
						afStatus == share.ScanVulStatus_WillNotFix {
						mcve := detectors.ModuleVul{Name: v.Name, Status: afStatus}

						if st, ok := matchMap[v.Name]; !ok {
							moduleVuls = append(moduleVuls, mcve)
							matchMap[v.Name] = mcve.Status
						} else if st != mcve.Status {
							log.WithFields(log.Fields{"v": v, "featName": featName}).Error()
						}
					}
				}
			}
			continue
		}

		for _, fix := range v.Fixin {
			if namespace == "ubuntu:upstream" && (strings.Contains(fix.Version, ":") || fix.Version == "#MINV#" || fix.Version == "#MAXV#") {
				continue
			}

			if fix.Name != name {
				continue
			}

			ftVer := ft.Version
			fixVer := fix.Version

			if name == "openssl" {
				if fmt.Sprintf("%s-r0", ftVer.String()) == fixVer {
					// for openssl: 1.1.1g is same as 1.1.1g-r0
					continue
				} else if ft.Version.String()[0] != fixVer[0] {
					continue
				}
			}

			// the naming of centos and redhat is different. centos skip the el7_5's minor version 5.
			if strings.Contains(ft.Version.String(), "centos") {
				if a := strings.Index(fix.Version, ".el"); a > 0 {
					fixVer = fix.Version[:a+4]
				} else {
					fixVer = fix.Version
				}
			}
			ver, err := utils.NewVersion(fixVer)
			if err != nil {
				log.WithFields(log.Fields{"error": err, "version": fixVer}).Error()
				continue
			}
			if ver == utils.MaxVersion {
				afStatus = share.ScanVulStatus_Unpatched
			} else if ver == utils.MinVersion {
				afStatus = share.ScanVulStatus_Unaffected
			} else {
				afStatus = share.ScanVulStatus_FixExists
			}
			if ftVer.Compare(ver) >= 0 {
				afStatus = share.ScanVulStatus_Unaffected
				continue
			}

			if fix.MinVer != "" {
				minVer, err := utils.NewVersion(fix.MinVer)
				if err != nil {
					log.WithFields(log.Fields{"error": err, "min-version": fix.MinVer}).Error()
					continue
				}

				if ftVer.Compare(minVer) < 0 {
					continue
				}
			}

			v.Fixin = append(v.Fixin, common.FeaShort{
				Name: fix.Name, Version: fix.Version, MinVer: fix.MinVer,
			})
			affectVs = append(affectVs, v)
			break
		}

		if afStatus == share.ScanVulStatus_FixExists ||
			afStatus == share.ScanVulStatus_Unpatched ||
			afStatus == share.ScanVulStatus_WillNotFix {
			mcve := detectors.ModuleVul{Name: v.Name, Status: afStatus}

			if st, ok := matchMap[v.Name]; !ok {
				moduleVuls = append(moduleVuls, mcve)
				matchMap[v.Name] = mcve.Status
			} else if st != mcve.Status {
				log.WithFields(log.Fields{"v": v, "featName": featName}).Error()
			}
		}
	}
	return affectVs, moduleVuls
}

func makeFeatureMap(vss []common.VulShort, namespace string) map[string][]common.VulShort {
	mv := make(map[string][]common.VulShort)

	for _, v := range vss {
		// remove v in fixin version, and only keep the match namespace
		vns := strings.Replace(v.Namespace, ":v", ":", 1)
		if vns != namespace {
			continue
		}

		for _, ft := range v.Fixin {
			// if strings.Contains(ft.Name, "openssl-libs") {
			// 	log.WithFields(log.Fields{"ft": ft, "vns": vns, "name": v.Name}).Debug(" ------------")
			// }
			// Only choose the relevant module
			short := common.VulShort{
				Name:      v.Name,
				Namespace: v.Namespace,
				Fixin: []common.FeaShort{
					// make a copy instead of reference
					common.FeaShort{Name: ft.Name, Version: ft.Version, MinVer: ft.MinVer},
				},
				CPEs: v.CPEs,
			}
			s := fmt.Sprintf("%s:%s", vns, ft.Name)
			vs, _ := mv[s]
			vs = append(vs, short)
			mv[s] = vs
		}
	}
	return mv
}

type vulnerabilityInfo struct {
	vulnerability common.VulFull
	featVer       detectors.FeatureVersion
	fixedIn       common.FeaFull
	severity      common.Priority
}
type SortBy func(v1, v2 vulnerabilityInfo) bool

func (by SortBy) Sort(vulnerabilities []vulnerabilityInfo) {
	ps := &sorter{
		vulnerabilities: vulnerabilities,
		by:              by,
	}
	sort.Sort(ps)
}

type sorter struct {
	vulnerabilities []vulnerabilityInfo
	by              func(v1, v2 vulnerabilityInfo) bool
}

func (s *sorter) Len() int {
	return len(s.vulnerabilities)
}

func (s *sorter) Swap(i, j int) {
	s.vulnerabilities[i], s.vulnerabilities[j] = s.vulnerabilities[j], s.vulnerabilities[i]
}

func (s *sorter) Less(i, j int) bool {
	return s.by(s.vulnerabilities[i], s.vulnerabilities[j])
}

func getVulItemList(vuls []vulFullReport, dbPrefix string) []*share.ScanVulnerability {
	vulnerabilities := make([]vulnerabilityInfo, 0)
	vulList := make([]*share.ScanVulnerability, 0)
	if len(vuls) == 0 {
		return vulList
	}

	for _, vul := range vuls {
		name := vul.Ft.Feature.Name
		if a := strings.Index(name, "/"); a > 0 {
			// feature name can take format util-linux/libsmartcols1, user the source name but keep the feature full name, NVSHAS-4042
			// vul.ft.Feature.Name = name[a+1:]
			name = name[:a]
		}
		severity := common.Priority(vul.Vf.Severity)

		var fixedin common.FeaFull
		if len(vul.Vf.FixedIn) == 1 {
			fixedin = vul.Vf.FixedIn[0]
		} else if len(vul.Vf.FixedIn) > 1 {
			for _, fi := range vul.Vf.FixedIn {
				if name == fi.Name {
					fixedin = fi
					break
				}
			}
		} else {
			log.Info("No vulnerability found")
		}

		vulInfo := vulnerabilityInfo{vulnerability: vul.Vf, featVer: vul.Ft, fixedIn: fixedin, severity: severity}
		vulnerabilities = append(vulnerabilities, vulInfo)
	}

	// Sort vulnerabilitiy by severity.
	priority := func(v1, v2 vulnerabilityInfo) bool {
		if v1.severity.Compare(v2.severity) == 0 {
			return v1.featVer.Feature.Name <= v2.featVer.Feature.Name
		} else {
			return v1.severity.Compare(v2.severity) > 0
		}
	}

	SortBy(priority).Sort(vulnerabilities)

	unique := utils.NewSet()
	for _, vuln := range vulnerabilities {
		v := vuln.vulnerability
		featver := vuln.featVer
		fixedin := vuln.fixedIn
		severity := vuln.severity

		var fixedInVer string
		if fixedin.Version == "#MAXV#" {
			fixedInVer = ""
		} else if fixedin.Version == "#MINV#" {
			continue
		} else {
			fixedInVer = fixedin.Version
		}
		packVer := featver.Version.String()

		// TODO: Quick fix to remove duplication. It should be done earlier
		key := fmt.Sprintf("%s-%s-%s", v.Name, featver.Feature.Name, packVer)
		if unique.Contains(key) {
			continue
		}
		unique.Add(key)

		if severity == common.Critical {
			severity = common.High
		}
		var cpes []string
		if featver.CPEs != nil && featver.CPEs.Cardinality() > 0 {
			cpes = make([]string, featver.CPEs.Cardinality())
			i := 0
			for iter := range featver.CPEs.Iter() {
				cpes[i] = iter.(string)
				i++
			}
		}

		// Reduce grpc message size
		item := &share.ScanVulnerability{
			// Description:      v.Description,
			// Link:             v.Link,
			// Vectors:          v.CVSSv2.Vectors,
			// VectorsV3:        v.CVSSv3.Vectors,
			Score:            float32(v.CVSSv2.Score),
			ScoreV3:          float32(v.CVSSv3.Score),
			Name:             v.Name,
			Severity:         fmt.Sprintf("%s", severity),
			PackageName:      featver.Feature.Name,
			PackageVersion:   packVer,
			FixedVersion:     strings.Replace(fixedInVer, "||", " OR ", -1),
			PublishedDate:    fmt.Sprintf("%d", v.IssuedDate.Unix()),
			LastModifiedDate: fmt.Sprintf("%d", v.LastModDate.Unix()),
			CPEs:             cpes,
			FeedRating:       v.FeedRating,
			InBase:           featver.InBase,
			DBKey:            fmt.Sprintf("%s:%s", dbPrefix, v.Name),
		}
		if len(v.CVEs) > 0 {
			item.CVEs = v.CVEs
		} else if strings.HasPrefix(v.Name, "CVE-") {
			item.CVEs = []string{v.Name}
		}
		vulList = append(vulList, item)
	}
	// log.Info("scan report:", len(vulList))
	return vulList
}

func removeSubVersion(name string) string {
	// remove the second ".", only take like 3.7
	if a := strings.Index(name, "."); a > 0 {
		if b := strings.Index(name[a+1:], "."); b > 0 {
			name = name[:a+b+1]
		}
	}
	return name
}

//majorVersion returns only the most significant version, ex: 7.8.112 -> 7
func majorVersion(name string) string {
	substrings := strings.Split(name, ".")
	return substrings[0]
}

func feature2Module(namespace string, features []detectors.FeatureVersion, apps []detectors.AppFeatureVersion) []*share.ScanModule {
	modules := make([]*share.ScanModule, len(features)+len(apps))

	i := 0
	for _, f := range features {
		modules[i] = &share.ScanModule{Name: f.Feature.Name, Version: f.Version.String(), Source: namespace}

		for _, mv := range f.ModuleVuls {
			cve := &share.ScanModuleVul{Name: mv.Name, Status: mv.Status}
			modules[i].Vuls = append(modules[i].Vuls, cve)
		}
		if f.CPEs != nil && f.CPEs.Cardinality() > 0 {
			modules[i].CPEs = make([]string, f.CPEs.Cardinality())
			j := 0
			for cpe := range f.CPEs.Iter() {
				modules[i].CPEs[j] = cpe.(string)
				j++
			}
		}

		i++
	}
	for _, app := range apps {
		modules[i] = &share.ScanModule{Name: app.ModuleName, Version: app.Version, Source: app.AppName}
		for _, mv := range app.ModuleVuls {
			cve := &share.ScanModuleVul{Name: mv.Name, Status: mv.Status}
			modules[i].Vuls = append(modules[i].Vuls, cve)
		}
		i++
	}

	return modules
}

func buildSecretResult(logs []share.CLUSSecretLog, err error) *share.ScanSecretResult {
	res := &share.ScanSecretResult{
		Error: share.ScanErrorCode_ScanErrNone,
		Logs:  make([]*share.ScanSecretLog, len(logs)),
	}

	if err == nil {
		//	log.WithFields(log.Fields{"logCnt": len(logs)}).Debug()
	} else {
		errStr := err.Error()
		if strings.Contains(errStr, "Timeout") {
			res.Error = share.ScanErrorCode_ScanErrTimeout
		} else {
			res.Error = share.ScanErrorCode_ScanErrFileSystem // error while walking diretory
		}
		log.WithFields(log.Fields{"err": err}).Error()
	}

	for i, l := range logs {
		// log.WithFields(log.Fields{"desc": l.RuleDesc, "path": l.File}).Debug()
		var subject string
		// cloak the secret a little bit by masking out some digits
		secretLength := len(l.Text)
		if secretLength > 32 {
			subject = l.Text[:30]
		} else if secretLength > 6 { // should be longer than 6
			subject = l.Text[:secretLength-3]
		}
		subject += "..."

		res.Logs[i] = &share.ScanSecretLog{
			Type:       l.Type,
			Text:       subject, // description
			File:       l.File,
			RuleDesc:   l.RuleDesc,
			Suggestion: l.Suggestion,
		}
	}
	return res
}

func buildSetIdPermLogs(perms []share.CLUSSetIdPermLog) []*share.ScanSetIdPermLog {
	permLogs := make([]*share.ScanSetIdPermLog, len(perms))
	for i, p := range perms {
		// log.WithFields(log.Fields{"setid": p, "i": i}).Debug()
		permLogs[i] = &share.ScanSetIdPermLog{
			Type:     p.Types,
			File:     p.File,
			Evidence: p.Evidence,
		}
	}
	return permLogs
}
