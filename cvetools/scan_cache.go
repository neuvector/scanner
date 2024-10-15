package cvetools

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

type SecretPermLogs struct {
	SecretLogs []share.CLUSSecretLog    `json:"secrets,omitempty"`
	SetidPerm  []share.CLUSSetIdPermLog `json:"set_ids,omitempty"`
}

type LayerRecord struct {
	Modules *LayerFiles     `json:"modules,omitempty"`
	Secrets *SecretPermLogs `json:"secret_logs,omitempty"`
	Files   []string        `json:"files,omitempty"`
	Removed []string        `json:"removed_file,omitempty"`
}

type cacheData struct {
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	RefCnt  uint32    `json:"ref_cnt"`
	RefLast time.Time `json:"ref_last"`
}

type CacherData struct {
	CacheRecordMap map[string]*cacheData `json:"cache_records,omitempty"`
	MissCnt        int64                 `json:"cache_misses,omitempty"`
	HitCnt         int64                 `json:"cache_hits,omitempty"`
	CurRecordSize  int64                 `json:"current_record_size"`
}

type CacheVersion struct {
	Version     int    `json:"version"`
	Description string `json:"description"`
}

type ImageLayerCacher struct {
	flock         int
	cachePath     string
	indexFile     string
	lockFile      string
	maxRecordSize int64 // scanned record: modules
}

// TODO
const curVersion = 0
const versionDescription = "initial implementation"

const pickVictimCnt = 256
const versionFile = "version"
const subRecordFolder = "ref"

// //////
func InitImageLayerCacher(cacheFile, lockFile, cachePath string, maxRecordSize int64) (*ImageLayerCacher, error) {
	log.WithFields(log.Fields{"maxRecordSize": maxRecordSize}).Info()
	if maxRecordSize == 0 {
		return nil, nil
	}
	log.WithFields(log.Fields{"cacheFile": cacheFile, "lockFile": lockFile, "cachePath": cachePath}).Debug()

	if err := os.MkdirAll(cachePath, 0755); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		return nil, err
	}

	if err := os.MkdirAll(filepath.Join(cachePath, subRecordFolder), 0755); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		return nil, err
	}
	cacher := &ImageLayerCacher{
		flock:         -1,
		lockFile:      lockFile,
		indexFile:     cacheFile,
		cachePath:     cachePath,
		maxRecordSize: maxRecordSize * 1024 * 1024,
	}

	cacher.InvaldateCache()
	return cacher, nil
}

func (lc *ImageLayerCacher) LeaveLayerCacher() {
	log.Debug()
	lc.reset_lock()
}

func (lc *ImageLayerCacher) writeVersionFile() {
	log.Debug()
	ver := CacheVersion{
		Version:     curVersion,
		Description: versionDescription,
	}

	log.WithFields(log.Fields{"ver": ver}).Info()
	data, _ := json.Marshal(&ver)
	if err := os.WriteFile(filepath.Join(lc.cachePath, versionFile), data, 0644); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
	}
}

func (lc *ImageLayerCacher) InvaldateCache() bool {
	lc.lock()
	defer lc.unlock()
	defer lc.reset_lock()

	bReset := false
	if file, err := os.ReadFile(filepath.Join(lc.cachePath, versionFile)); err == nil {
		var ver CacheVersion

		if err := json.Unmarshal([]byte(file), &ver); err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			bReset = true
		} else {
			if ver.Version != curVersion {
				log.WithFields(log.Fields{"old ver": ver}).Info("Invalidate old caches")
				bReset = true
			}
		}
	} else {
		log.Info("Missing version file: invalidate old caches")
		bReset = true
	}

	if bReset {
		os.Remove(lc.indexFile)
		os.RemoveAll(filepath.Join(lc.cachePath, subRecordFolder))
		if err := os.MkdirAll(filepath.Join(lc.cachePath, subRecordFolder), 0755); err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
		}
		lc.writeVersionFile()
		return true
	}

	return false
}

func (lc *ImageLayerCacher) lock() {
	if lc.flock == -1 { // the file lock because it is thread-depedent
		if fd, err := syscall.Open(lc.lockFile, syscall.O_CREAT|syscall.O_RDONLY, 0600); err == nil {
			lc.flock = fd
		} else {
			log.WithFields(log.Fields{"error": err}).Error("Lock failed")
			return
		}
	}

	if err := syscall.Flock(lc.flock, syscall.LOCK_EX); err != nil {
		if err.Error() != "bad file descriptor" { // PVC cases
			log.WithFields(log.Fields{"error": err, "flock": lc.flock}).Error("Wait")
		}
	}
	// log.WithFields(log.Fields{"fn": utils.GetCaller(3, nil)}).Debug()
	// time.Sleep(time.Second*10)
}

func (lc *ImageLayerCacher) unlock() {
	// log.WithFields(log.Fields{"fn": utils.GetCaller(3, nil)}).Debug()
	if err := syscall.Flock(lc.flock, syscall.LOCK_UN); err != nil {
		if err.Error() != "bad file descriptor" { // PVC cases
			log.WithFields(log.Fields{"error": err, "flock": lc.flock}).Error()
		}
	}
}

func (lc *ImageLayerCacher) reset_lock() {
	syscall.Close(lc.flock)
	lc.flock = -1 // reset the file lock because it is thread-depedent
}

func (lc *ImageLayerCacher) readCacheFile() *CacherData {
	var cache CacherData
	file, _ := os.ReadFile(lc.indexFile)
	if err := json.Unmarshal([]byte(file), &cache); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
	}
	if cache.CacheRecordMap == nil {
		cache.CacheRecordMap = make(map[string]*cacheData)
	}

	// log.WithFields(log.Fields{"cache": cache}).Debug()
	return &cache // return empty data even if does not exist
}

func (lc *ImageLayerCacher) writeCacheFile(cache *CacherData) {
	data, _ := json.Marshal(cache)
	// log.WithFields(log.Fields{"data": string(data)}).Debug()
	if err := os.WriteFile(lc.indexFile, data, 0644); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
	}
}

// /////////////// Record caches ////////////////
func (lc *ImageLayerCacher) RecordName(id string, record interface{}) string {
	switch record.(type) {
	case *LayerRecord: // scan package
		return id + "_" + "layer_file"
	}
	return ""
}

func (lc *ImageLayerCacher) ReadRecordCache(id string, record interface{}) (string, error) {
	name := lc.RecordName(id, record)
	if name == "" {
		return "", errors.New("Invalid type")
	}

	// log.WithFields(log.Fields{"name": name}).Debug()
	lc.lock()
	defer lc.unlock()

	cacher := lc.readCacheFile()
	defer lc.writeCacheFile(cacher) // update reference count

	cc, ok := cacher.CacheRecordMap[name]
	if !ok {
		cacher.MissCnt++
		return "", errors.New("Not found: " + name)
	}
	cacher.HitCnt++

	// double check
	if _, err := os.Stat(cc.Path); err != nil {
		cacher.CurRecordSize -= cc.Size
		delete(cacher.CacheRecordMap, id)
		return "", err
	}

	value, _ := os.ReadFile(cc.Path)
	uzb := utils.GunzipBytes(value)
	if err := json.Unmarshal([]byte(uzb), record); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		return "", err
	}
	cc.RefCnt++
	cc.RefLast = time.Now()
	// log.WithFields(log.Fields{"cc": cc}).Debug()
	return cc.Path, nil
}

func (lc *ImageLayerCacher) WriteRecordCache(id string, record interface{}, keeper utils.Set) error {
	name := lc.RecordName(id, record)
	if name == "" {
		return errors.New("Invalid type")
	}

	// log.WithFields(log.Fields{"name": name}).Debug()

	lc.lock()
	defer lc.unlock()

	cacher := lc.readCacheFile()
	if _, ok := cacher.CacheRecordMap[name]; !ok {
		dest := filepath.Join(lc.cachePath, subRecordFolder, name)
		data, _ := json.Marshal(record)
		zb := utils.GzipBytes(data)
		if err := os.WriteFile(dest, zb, 0644); err != nil {
			log.WithFields(log.Fields{"error": err, "dest": dest}).Error()
		}
		size := int64(len(zb))
		cacher.CurRecordSize += size
		cacher.CacheRecordMap[name] = &cacheData{Path: dest, Size: size, RefLast: time.Now()}
		// log.WithFields(log.Fields{"dest": dest, "size": size}).Debug()

		// prune the cacher size
		lc.pruneRecordCache(name, cacher, keeper)
	}
	lc.writeCacheFile(cacher)
	return nil
}

func (lc *ImageLayerCacher) pruneRecordCache(name string, cacher *CacherData, keepers utils.Set) {
	// log.WithFields(log.Fields{"curRecSize": cacher.CurRecordSize, "max": lc.maxRecordSize, "keepers": keepers}).Debug()
	if cacher.CurRecordSize < lc.maxRecordSize {
		return
	}

	// exclude current cached layers, pick 8-16 victims
	var keys []string
	for key, _ := range cacher.CacheRecordMap {
		if keepers.Contains(key) {
			continue
		}
		keys = append(keys, key)
	}

	if len(keys) > pickVictimCnt {
		sort.SliceStable(keys, func(i, j int) bool {
			return cacher.CacheRecordMap[keys[i]].RefLast.Before(cacher.CacheRecordMap[keys[j]].RefLast)
			// return cacher.CacheRecordMap[keys[i]].RefCnt < cacher.CacheRecordMap[keys[j]].RefCnt
		})
	}

	var removedSize int64
	for i, key := range keys {
		if i >= pickVictimCnt {
			break
		}

		if cc, ok := cacher.CacheRecordMap[key]; ok {
			log.WithFields(log.Fields{"path": cc.Path, "size": cc.Size, "last": cc.RefLast, "cnt": cc.RefCnt}).Debug("remove")
			removedSize += cc.Size
			os.RemoveAll(cc.Path)
			delete(cacher.CacheRecordMap, key)
		}
	}
	cacher.CurRecordSize -= removedSize
	log.WithFields(log.Fields{"removed": removedSize}).Debug("done")
}

func (lc *ImageLayerCacher) GetStat() *share.ScanCacheStatRes {
	log.Debug()
	lc.lock()
	defer lc.unlock()
	cacher := lc.readCacheFile()
	return &share.ScanCacheStatRes{
		RecordCnt:  uint64(len(cacher.CacheRecordMap)),
		RecordSize: uint64(cacher.CurRecordSize),
		MissCnt:    uint64(cacher.MissCnt),
		HitCnt:     uint64(cacher.HitCnt),
	}
}

func (lc *ImageLayerCacher) GetIndexFile() []byte {
	log.Debug()
	lc.lock()
	defer lc.unlock()

	cacher := lc.readCacheFile()
	cache_data := scan.CacherData{
		MissCnt:       uint64(cacher.MissCnt),
		HitCnt:        uint64(cacher.HitCnt),
		CurRecordSize: uint64(cacher.CurRecordSize),
		CacheRecords:  make([]scan.CacheRecord, 0),
	}

	for id, rec := range cacher.CacheRecordMap {
		r := scan.CacheRecord{
			Layer:   id,
			Size:    uint64(rec.Size),
			RefCnt:  uint32(rec.RefCnt),
			RefLast: rec.RefLast,
		}
		cache_data.CacheRecords = append(cache_data.CacheRecords, r)
	}

	data, _ := json.Marshal(cache_data)
	return utils.GzipBytes(data) // zipped
}
