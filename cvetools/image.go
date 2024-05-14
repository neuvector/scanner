package cvetools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	goDigest "github.com/opencontainers/go-digest"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/container/dockerclient"
	"github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/scan/registry"
	"github.com/neuvector/neuvector/share/scan/secrets"
	"github.com/neuvector/neuvector/share/utils"
)

const (
	//max package file size
	manifestJson = "manifest.json"
	layerJson    = "/json"
	dockerfile   = "root/buildinfo/Dockerfile-"
	ociIndexJson = "index.json"
	ociLayout    = "oci-layout"
)

type imageManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type downloadLayerResult struct {
	layer   string
	Size    int64
	TarSize int64
	err     error
}

func parseSocketFromRepo(repo string) (string, string) {
	if strings.HasPrefix(repo, "tcp://") {
		n := strings.Index(strings.TrimPrefix(repo, "tcp://"), "/")
		if n > 0 {
			return repo[:n+6], repo[n+6+1:]
		}
	}

	return "", repo
}

func (s *ScanTools) GetLocalImageMeta(ctx context.Context, repository, tag string) (*container.ImageMeta, share.ScanErrorCode) {
	sock, repo := parseSocketFromRepo(repository)
	if sock == "" {
		sock = s.RtSock
	}

	rt, err := container.ConnectDocker(sock, s.sys)
	if err != nil {
		log.WithFields(log.Fields{"repo": repository, "tag": tag, "error": err}).Error("Connect docker server fail")
		return nil, share.ScanErrorCode_ScanErrContainerAPI
	}

	meta, err := rt.GetImage(fmt.Sprintf("%s:%s", repo, tag))
	if err != nil {
		log.WithFields(log.Fields{"repo": repository, "tag": tag, "error": err}).Error("Failed to get local image")
		if err == dockerclient.ErrImageNotFound {
			return nil, share.ScanErrorCode_ScanErrImageNotFound
		}
		return nil, share.ScanErrorCode_ScanErrContainerAPI
	}

	return meta, share.ScanErrorCode_ScanErrNone
}

func (s *ScanTools) LoadLocalImage(ctx context.Context, repository, tag, imgPath string, cacher *ImageLayerCacher) (
	map[string]*LayerRecord, *scan.ImageInfo, []string, share.ScanErrorCode) {

	sock, repo := parseSocketFromRepo(repository)
	if sock == "" {
		sock = s.RtSock
	}

	rt, err := container.ConnectDocker(sock, s.sys)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Connect docker server fail")
		return nil, nil, nil, share.ScanErrorCode_ScanErrContainerAPI
	}

	imageName := fmt.Sprintf("%s:%s", repo, tag)

	meta, err := rt.GetImage(imageName)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to get local image")
		if err == dockerclient.ErrImageNotFound {
			return nil, nil, nil, share.ScanErrorCode_ScanErrImageNotFound
		}
		return nil, nil, nil, share.ScanErrorCode_ScanErrContainerAPI
	}

	histories, err := rt.GetImageHistory(imageName)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to get local image history")
		if err == dockerclient.ErrImageNotFound {
			return nil, nil, nil, share.ScanErrorCode_ScanErrImageNotFound
		}
		return nil, nil, nil, share.ScanErrorCode_ScanErrContainerAPI
	}

	file, err := rt.GetImageFile(meta.ID)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to get image")
		if err == dockerclient.ErrImageNotFound {
			return nil, nil, nil, share.ScanErrorCode_ScanErrImageNotFound
		} else if err == container.ErrMethodNotSupported {
			return nil, nil, nil, share.ScanErrorCode_ScanErrDriverAPINotSupport
		}
		return nil, nil, nil, share.ScanErrorCode_ScanErrContainerAPI
	}

	// create an image file and image layered folders
	repoFolder := filepath.Join(imgPath, "repo")
	os.MkdirAll(repoFolder, 0755)
	defer os.RemoveAll(repoFolder)

	// save the image
	imageFile := filepath.Join(repoFolder, "image.tar")
	out, err := os.OpenFile(imageFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err == nil {
		_, err = io.Copy(out, file)
		out.Close()
	}
	file.Close()
	if err != nil {
		log.Errorf("could not write to image: %s", err)
		return nil, nil, nil, share.ScanErrorCode_ScanErrFileSystem
	}

	// obtain layer information, then extract the layers into tar files
	layers, blobs, err := getImageLayers(repoFolder, imageFile)
	if err != nil {
		log.Errorf("could not extract image layers: %s", err)
		return nil, nil, nil, share.ScanErrorCode_ScanErrPackage
	}

	//log.WithFields(log.Fields{"layers": layers, "blobs": blobs}).Debug()

	var downloads []string // download layer requests
	cacheLayers := make(map[string]*LayerRecord)
	keepers := utils.NewSet()
	for _, layer := range layers {
		if layer == "" {
			continue
		}

		// log.WithFields(log.Fields{"i": i, "layer": layer, "size": sizes[layer]}).Debug()
		if cacher == nil {
			downloads = append(downloads, layer)
			continue
		}

		lr := LayerRecord{}
		keepers.Add(cacher.RecordName(layer, &lr)) // reference for write record
		if _, err := cacher.ReadRecordCache(layer, &lr); err == nil {
			log.WithFields(log.Fields{"layer": layer}).Info("cache")
			cacheLayers[layer] = &lr
		} else {
			downloads = append(downloads, layer)
		}
	}

	log.WithFields(log.Fields{"imageName": imageName, "downloads": downloads}).Debug()

	layerModules, errCode := getImageLayerIterate(ctx, downloads, nil, false, imgPath,
		func(ctx context.Context, layer string) (interface{}, int64, error) {
			blob, _ := blobs[layer]
			file, err := os.Open(filepath.Join(repoFolder, blob))
			if err != nil {
				return nil, -1, err
			}
			stat, err := file.Stat()
			if err != nil {
				return nil, -1, err
			}
			var bytes int64
			bytes = stat.Size()
			return file, bytes, nil
		})

	if cacher != nil {
		secrets, setIDs, fmap, removed := collectLayerRawRecord(imgPath, downloads)
		// save downloaded records
		for layer, mod := range layerModules {
			slogs, _ := secrets[layer]
			plogs, _ := setIDs[layer]
			flogs, _ := fmap[layer]
			rlogs, _ := removed[layer]
			layerRec := LayerRecord{
				Modules: mod,
				Secrets: &SecretPermLogs{
					SecretLogs: slogs,
					SetidPerm:  plogs,
				},
				Files:   flogs,
				Removed: rlogs,
			}

			if err := cacher.WriteRecordCache(layer, &layerRec, keepers); err != nil {
				log.WithFields(log.Fields{"error": err, "layer": layer}).Error()
			}
			// merging cacher's records
			cacheLayers[layer] = &layerRec
		}
	} else {
		for layer, mod := range layerModules {
			cacheLayers[layer] = &LayerRecord{Modules: mod}
		}
	}

	// GetImage(sha256:xxxx) and getImageLayers (yyyy) return different sets of layer ID, make them consistent.
	// In the "inspect image" CLI command, users can only read the "sha256:xxxx" list.
	// however, "yyyy" is the real data storage and referrable.
	// SWAP tarID into layerID
	tars := layers
	for i, tarID := range tars { // tar
		// log.WithFields(log.Fields{"i": i, "tarID": tarID}).Debug()
		shaID := meta.Layers[i] // sha
		if lr, ok := cacheLayers[tarID]; ok {
			cacheLayers[shaID] = lr
			delete(cacheLayers, tarID)
		}
	}

	// Use cmds from "docker history" API, add 0-sized layer back in.
	tarLayers := make([]string, len(histories))
	layers = make([]string, len(histories))
	cmds := make([]string, len(histories))
	lenML := len(meta.Layers)
	ml := 0
	for i, h := range histories {
		cmds[i] = scan.NormalizeImageCmd(h.Cmd)
		if ml < lenML {
			matched := (h.Size > 0)
			if !matched {
				if mod, ok := layerModules[tars[ml]]; ok {
					matched = (mod.Size == 0) // symblic blobs, not exactly at its position but it is near enough
				}
			}

			if matched {
				layers[i] = meta.Layers[ml]
				tarLayers[i] = tars[ml]
				ml++
				continue
			}
		}

		// empty layer
		layers[i] = ""
		tarLayers[i] = ""
	}

	repoInfo := &scan.ImageInfo{
		ID:       meta.ID,
		Digest:   meta.Digest,
		Layers:   layers,
		Cmds:     cmds,
		Envs:     meta.Env,
		Labels:   meta.Labels,
		RepoTags: meta.RepoTags,
	}

	return cacheLayers, repoInfo, tarLayers, errCode
}

type layerMetadata struct {
	ID              string    `json:"id"`
	Parent          string    `json:"parent"`
	Created         time.Time `json:"created"`
	Container       string    `json:"container"`
	ContainerConfig struct {
		Hostname   string            `json:"Hostname"`
		Domainname string            `json:"Domainname"`
		User       string            `json:"User"`
		Env        []string          `json:"Env"`
		Cmd        []string          `json:"Cmd"`
		Labels     map[string]string `json:"Labels"`
	} `json:"container_config"`
	Config struct {
		Hostname    string            `json:"Hostname"`
		Domainname  string            `json:"Domainname"`
		User        string            `json:"User"`
		Env         []string          `json:"Env"`
		Cmd         []string          `json:"Cmd"`
		ArgsEscaped bool              `json:"ArgsEscaped"`
		Image       string            `json:"Image"`
		WorkingDir  string            `json:"WorkingDir"`
		Labels      map[string]string `json:"Labels"`
	} `json:"config"`
	Architecture string `json:"architecture"`
	Os           string `json:"os"`
}

func getImageLayers(tmpDir string, imageTar string) ([]string, map[string]string, error) {
	var image []imageManifest

	reader, err := os.Open(imageTar)
	if err != nil {
		return nil, nil, err
	}
	defer reader.Close()

	//get the manifest from the image tar
	files, err := utils.SelectivelyExtractArchive(bufio.NewReader(reader), func(filename string) bool {
		if filename == manifestJson || strings.HasSuffix(filename, layerJson) || filename == ociLayout {
			return true
		} else {
			return false
		}
	}, maxFileSize)

	// https://github.com/opencontainers/image-spec/blob/main/image-layout.md
	// Optional: Following the index.json to find a manifest
	_, bOciLayout := files[ociLayout]
	log.WithFields(log.Fields{"bOciLayout": bOciLayout}).Debug()

	if dat, ok := files[manifestJson]; !ok {
		return nil, nil, fmt.Errorf("Can not locate the manifest.json in image")
	} else {
		if err = json.Unmarshal(dat, &image); err != nil {
			return nil, nil, err
		}
		if len(image) == 0 {
			return nil, nil, fmt.Errorf("Can not extract layer from the image")
		}
	}

	//extract all the layers to tar files
	reader.Seek(0, 0)
	fileMap, err := utils.SelectivelyExtractToFile(bufio.NewReader(reader), func(filename string) bool {
		for _, l := range image[0].Layers {
			if filename == l {
				return true
			}
		}
		return false
	}, tmpDir)

	if err != nil {
		return nil, nil, err
	}

	layerCount := len(image[0].Layers)
	layers := make([]string, layerCount)
	blobs := make(map[string]string)
	for i, ftar := range image[0].Layers {
		if fpath, ok := fileMap[ftar]; !ok {
			return layers, blobs, fmt.Errorf("could not find the image layer: " + ftar)
		} else {
			fpath = filepath.Base(fpath)
			layer := strings.TrimSuffix(fpath, "_layer.tar") // remove unwanted suffix
			if bOciLayout {
				ls := strings.Split(layer, "_")
				layer = ls[len(ls)-1]
			}
			layers[layerCount-i-1] = layer
			blobs[layer] = fpath
		}
	}
	return layers, blobs, nil
}

type LayerFiles struct {
	Size int64
	Pkgs map[string][]byte
	Apps map[string][]scan.AppPackage
}

func getApkPackages(fullpath string) ([]byte, error) {
	inputFile, err := os.Open(fullpath)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "P:") ||
			strings.HasPrefix(line, "V:") ||
			strings.HasPrefix(line, "o:") ||
			line == "" {
			buf.WriteString(line)
			buf.WriteString("\n")
		}
	}
	return buf.Bytes(), nil
}

func getImageLayerIterate(
	ctx context.Context, layers []string, sizes map[string]int64, schemaV1 bool, imgPath string,
	layerReader func(ctx context.Context, layer string) (interface{}, int64, error),
) (map[string]*LayerFiles, share.ScanErrorCode) { // layer -> filename -> file content
	lfs := make(map[string]*LayerFiles)

	// download layered images into image folder
	layerInfo, err := downloadLayers(ctx, layers, sizes, imgPath, layerReader)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Open image layer fail")
		return nil, share.ScanErrorCode_ScanErrFileSystem
	}

	//for registry, download all the layers.
	//for read all the layers.
	for _, layer := range layers {
		log.WithFields(log.Fields{"layer": layer}).Debug()

		var size int64
		layerPath := filepath.Join(imgPath, layer)
		if info, ok := layerInfo[layer]; ok {
			size = info.Size
		}

		pathMap, err := selectiveFilesFromPath(layerPath, maxFileSize, func(path, fullpath string) bool {
			if scan.OSPkgFiles.Contains(path) || scan.IsAppsPkgFile(path, fullpath) {
				return true
			}
			if strings.HasPrefix(path, scan.DpkgStatusDir) {
				return true
			}
			if strings.HasPrefix(path, contentManifest) && strings.HasSuffix(path, ".json") {
				return true
			}
			if strings.HasPrefix(path, dockerfile) {
				return true
			}
			if scan.IsRlangPackage(path) {
				return true
			}
			return false
		})

		if err != nil {
			return nil, share.ScanErrorCode_ScanErrPackage
		}

		// for file content
		curLayerFiles := make(map[string][]byte)
		curLayerApps := scan.NewScanApps(true)
		for filename, fullpath := range pathMap {
			var data []byte
			if scan.RPMPkgFiles.Contains(filename) {
				data, err = scan.GetRpmPackages(fullpath, "")
				if err != nil {
					continue
				}
			} else if filename == scan.DpkgStatus || strings.HasPrefix(filename, scan.DpkgStatusDir) {
				// get the dpkg status file
				data, err = scan.GetDpkgStatus(fullpath, "")
				if err != nil {
					continue
				}
			} else if filename == "lib/apk/db/installed" {
				data, err = getApkPackages(fullpath)
				if err != nil {
					continue
				}
			} else if scan.IsAppsPkgFile(filename, fullpath) {
				curLayerApps.ExtractAppPkg(filename, fullpath)
				continue
			} else {
				// Files have been selectively picked above.
				data, err = ioutil.ReadFile(fullpath)
			}

			curLayerFiles[filename] = data
		}

		lfs[layer] = &LayerFiles{Size: size, Pkgs: curLayerFiles, Apps: curLayerApps.Data()}
	}

	return lfs, share.ScanErrorCode_ScanErrNone
}

////////
type layerSize struct {
	layer string
	size  int64
}

func sortLayersBySize(layerMap map[string]int64) []layerSize {
	if len(layerMap) == 0 {
		return nil
	}

	layers := make([]layerSize, 0, len(layerMap))
	for k, v := range layerMap {
		l := layerSize{layer: k, size: v}
		layers = append(layers, l)
	}

	sort.SliceStable(layers, func(i, j int) bool {
		return layers[i].size > layers[j].size
	})

	// log.WithFields(log.Fields{"layers": layers}).Debug()
	return layers
}

// Download layers in parallels
// Reducing memory by limiting its concurrent downloading tar size near to 400MB,
//    which size information is provided from the Image Manifest Version 2, Schema 2.
// The download layers are sorted by descending layer's tar sizes
// (1) if the tar size is greater than 500MB, it will be downloaded alone
// (2) if concurrent download (accumulate) is greater than 400MB, the next download item will wait until there are sufficient resources
// (3) the maximum accumulate is less 800MB (for example, 399.99MB + 399.98MB).
// Note: docker uses the "maxConcurrentDownloads" (3)
//       containerd uses the download altogether
//
const downloadThrottlingVolume = 400 * 1024 * 1024 // the average could be around this level, decompressed size could be 4x more

func downloadLayers(ctx context.Context, layers []string, sizes map[string]int64, imgPath string,
	layerReader func(ctx context.Context, layer string) (interface{}, int64, error)) (map[string]*downloadLayerResult, error) {

	bHasSizeInfo := (len(sizes) > 0) // sizes data is from schema v2
	results := make(map[string]*downloadLayerResult)

	// remove duplicate layers
	layerMap := make(map[string]int64)
	for _, layer := range layers {
		if _, ok := layerMap[layer]; !ok && layer != "" {
			layerMap[layer] = 0 // no decision
			if bHasSizeInfo {
				if size, ok := sizes[layer]; ok {
					layerMap[layer] = size
				}
			}
		}
	}

	layerBySizes := sortLayersBySize(layerMap)

	////
	var accumlates int64
	complete := make(chan error)
	done := make(chan *downloadLayerResult)
	go func() { // monitor
		var err error
		for i := 0; i < len(layerMap); i++ {
			res := <-done
			results[res.layer] = res
			accumlates -= res.TarSize
			log.WithFields(log.Fields{"res": res}).Info()
			if res.err != nil {
				err = res.err // reporting just one error
			}
		}
		complete <- err
	}()

	for _, layerSize := range layerBySizes {
		ml := layerSize.layer
		sl := layerSize.size // from manifest
		accumlates += sl
		// log.WithFields(log.Fields{"layerSize": layerSize}).Debug()
		go func() { // workers
			var err error
			var size int64
			var rd interface{}
			var retry int

			layerPath := filepath.Join(imgPath, ml)
			if bHasSizeInfo && sl == 0 {
				//log.WithFields(log.Fields{"layer": ml}).Debug("skip")
				os.MkdirAll(layerPath, 0755) // empty folder
				done <- &downloadLayerResult{layer: ml, err: nil, Size: 0, TarSize: 0}
				return
			}

			for retry < 3 {
				retry++
				rd, size, err = layerReader(ctx, ml)
				if err == nil {
					// unpack image data
					if _, err = os.Stat(layerPath); os.IsNotExist(err) { // ignored if it was untarred before
						err = os.MkdirAll(layerPath, 0755)
						if err != nil {
							log.WithFields(log.Fields{"error": err, "path": layerPath}).Error("Failed to make dir")
							// local file error, no retry
							break
						}

						size, err = utils.ExtractAllArchive(layerPath, rd.(io.ReadCloser), -1)
						if err != nil {
							log.WithFields(log.Fields{"error": err, "path": layerPath}).Error("Failed to unzip image")
							os.RemoveAll(layerPath)
							continue
						}
					}
					break
				}
			}
			done <- &downloadLayerResult{layer: ml, err: err, Size: size, TarSize: sl}
		}()

		for accumlates > downloadThrottlingVolume { // pause and wait for released resources
			// log.WithFields(log.Fields{"accumlates": accumlates}).Debug("Wait")
			time.Sleep(time.Second * 1)
		}
	}

	err := <-complete
	close(done)
	close(complete)
	return results, err
}

// selectiveFilesFromPath the specified files and folders
// store them in a map indexed by file paths
func selectiveFilesFromPath(rootPath string, maxFileSize int64, selected func(string, string) bool) (map[string]string, error) {
	rootLen := len(filepath.Clean(rootPath))
	data := make(map[string]string)

	// log.WithFields(log.Fields{"rootPath": rootPath}).Debug()
	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.WithFields(log.Fields{"path": rootPath, "error": err.Error()}).Error()
			return err
		}

		if !info.IsDir() {
			if info.Mode().IsRegular() && (maxFileSize > 0 && info.Size() < maxFileSize) {
				inpath := path[(rootLen + 1):] // remove the root "/"
				if selected(inpath, path) {
					data[inpath] = path
				}
			}
		}
		return nil
	})

	return data, err
}

const dataTimeout = 10 * time.Minute
const retryTimes = 3

func layerURL(pathTemplate string, url string, args ...interface{}) string {
	pathSuffix := fmt.Sprintf(pathTemplate, args...)
	return fmt.Sprintf("%s%s", url, pathSuffix)
}

func collectLayerRawRecord(imgPath string, downloads []string) (map[string][]share.CLUSSecretLog, map[string][]share.CLUSSetIdPermLog, map[string][]string, map[string][]string) {
	secretLogs := make(map[string][]share.CLUSSecretLog)
	setidPermLogs := make(map[string][]share.CLUSSetIdPermLog)
	fmap := make(map[string][]string)
	removed := make(map[string][]string)

	config := secrets.Config{
		MiniWeight: 0.1, // Some other texts will dilute the weight, so it is better to stay at a smaller weight
	}

	for _, id := range downloads {
		fpath := filepath.Join(imgPath, id)
		if sLogs, pLogs, err := secrets.FindSecretsByRootpath(fpath, nil, config); err == nil {
			secretLogs[id] = sLogs
			setidPermLogs[id] = pLogs
		} else {
			log.WithFields(log.Fields{"fpath": fpath, "error": err}).Error("secrets")
		}

		lmap := make(map[string]string)
		if _, rFiles, err := collectImageFileMap(fpath, lmap); err == nil {
			files := make([]string, 0)
			for f, _ := range lmap {
				files = append(files, f)
			}
			fmap[id] = files
			removed[id] = rFiles
		} else {
			log.WithFields(log.Fields{"fpath": fpath, "error": err}).Error("fmap")
		}
	}
	return secretLogs, setidPermLogs, fmap, removed
}

func DownloadRemoteImage(ctx context.Context, rc *scan.RegClient, name, imgPath string, layers []string, sizes map[string]int64, cacher *ImageLayerCacher) (map[string]*LayerRecord, share.ScanErrorCode) {
	var downloads []string // download layer requests
	var total_downloaded int64

	log.WithFields(log.Fields{"name": name}).Debug()
	cacheLayers := make(map[string]*LayerRecord)
	keepers := utils.NewSet()
	for i := len(layers) - 1; i >= 0; i-- { // v2
		layer := layers[i]
		if layer == "" {
			continue
		}

		// log.WithFields(log.Fields{"i": i, "layer": layer, "size": sizes[layer]}).Debug()
		if cacher == nil {
			downloads = append(downloads, layer)
			continue
		}

		lr := LayerRecord{}
		keepers.Add(cacher.RecordName(layer, &lr)) // reference for write recor
		if _, err := cacher.ReadRecordCache(layer, &lr); err == nil {
			log.WithFields(log.Fields{"layer": layer}).Info("cache")
			cacheLayers[layer] = &lr
		} else {
			downloads = append(downloads, layer)
		}
	}

	log.WithFields(log.Fields{"downloads": downloads}).Debug()
	// scheme is always set to v1 because layers of v2 image have been reversed in GetImageInfo.
	layerModules, err := getImageLayerIterate(ctx, downloads, sizes, true, imgPath, func(ctx context.Context, layer string) (interface{}, int64, error) {
		return downloadRemoteLayer(ctx, rc, name, goDigest.Digest(layer))
	})

	if cacher != nil {
		secrets, setIDs, fmap, removed := collectLayerRawRecord(imgPath, downloads)
		// save downloaded records
		for layer, mod := range layerModules {
			slogs, _ := secrets[layer]
			plogs, _ := setIDs[layer]
			flogs, _ := fmap[layer]
			rlogs, _ := removed[layer]
			layerRec := LayerRecord{
				Modules: mod,
				Secrets: &SecretPermLogs{
					SecretLogs: slogs,
					SetidPerm:  plogs,
				},
				Files:   flogs,
				Removed: rlogs,
			}

			if err := cacher.WriteRecordCache(layer, &layerRec, keepers); err != nil {
				log.WithFields(log.Fields{"error": err, "layer": layer}).Error()
			}
			// merging cacher's records
			cacheLayers[layer] = &layerRec
			total_downloaded += mod.Size
		}
	} else {
		for layer, mod := range layerModules {
			cacheLayers[layer] = &LayerRecord{Modules: mod}
			total_downloaded += mod.Size
		}
	}
	log.WithFields(log.Fields{"total_downloaded": total_downloaded}).Info()
	return cacheLayers, err
}

func downloadRemoteLayer(ctx context.Context, rc *scan.RegClient, repository string, digest digest.Digest) (io.ReadCloser, int64, error) {
	url := layerURL("/v2/%s/blobs/%s", rc.URL, repository, digest)
	log.WithFields(log.Fields{"digest": digest}).Debug()

	rc.Client.SetTimeout(dataTimeout)

	var resp *http.Response
	var req *http.Request
	var err error
	retry := 0
	for retry < retryTimes {
		req, err = http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, -1, err
		}
		reqWithContext := req.WithContext(ctx)

		resp, err = rc.Client.Do(reqWithContext)
		if err == nil {
			return resp.Body, resp.ContentLength, nil
		}

		log.WithFields(log.Fields{"error": err}).Error()
		if ctx.Err() == context.Canceled {
			return nil, -1, ctx.Err()
		}

		retry++
	}

	return nil, -1, err
}

// SignatureData represents signature image data retrieved from the registry to be
// used in verification.
type SignatureData struct {
	// The raw manifest JSON retrieved from the registry
	Manifest string `json:"Manifest"`

	// A collection of signature payloads referenced by the manifest to be verified.
	Payloads map[string]string `json:"Payloads"`
}

// GetSignatureDataForImage fetches the signature image's maniest and layers for the
// given repository and digest. The layers are small JSON blobs that represent the payload created and signed
// by Sigstore's Cosign to be used in verification later.
//
// More information about the cosign's signature specification can be found here:
// https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md
func getSignatureDataForImage(ctx context.Context, rc *scan.RegClient, repo, digest string) (s SignatureData, errCode share.ScanErrorCode) {
	signatureTag := scan.GetCosignSignatureTagFromDigest(digest)
	info, errCode := rc.GetImageInfo(ctx, repo, signatureTag, registry.ManifestRequest_CosignSignature)
	if errCode != share.ScanErrorCode_ScanErrNone {
		return SignatureData{}, errCode
	}
	s.Payloads = make(map[string]string)
	for _, layer := range info.Layers {
		rdr, _, err := rc.DownloadLayer(context.Background(), repo, goDigest.Digest(layer))
		if err != nil {
			return SignatureData{}, share.ScanErrorCode_ScanErrRegistryAPI
		}
		layerBytes, err := ioutil.ReadAll(rdr)
		if err != nil {
			return SignatureData{}, share.ScanErrorCode_ScanErrRegistryAPI
		}
		s.Payloads[layer] = string(layerBytes)
	}
	s.Manifest = string(info.RawManifest)
	return s, share.ScanErrorCode_ScanErrNone
}
