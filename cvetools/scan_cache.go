package cvetools

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

type SecretPermLogs struct {
	SecretLogs  []share.CLUSSecretLog		`json:"secrets,omitempty"`
	SetidPerm 	[]share.CLUSSetIdPermLog	`json:"set_ids,omitempty"`
}

type LayerRecord struct {
	Modules *LayerFiles 		`json:"modules,omitempty"`
	Secrets	*SecretPermLogs		`json:"secret_logs,omitempty"`
	Files   []string			`json:"files,omitempty"`
	Removed []string			`json:"removed_file,omitempty"`
}

type cacheData struct {
	Path	string		`json:"path"`
	Size	int64		`json:"size"`
	RefCnt	uint32		`json:"ref_cnt"`
	RefLast	time.Time	`json:"ref_last"`
}

type CacherData struct {
	CacheRecordMap 	map[string]*cacheData	`json:"cache_records,omitempty"`
	CurRecordSize   int64					`json:"current_record_size"`
}

type ImageLayerCacher struct {
	flock			int
	cachePath 		string
	dataFile		string
    lockFile		string
	maxRecordSize	int64	// scanned record: modules
}

const pickVictimCnt = 8
const subRecordFolder = "ref"

////////
func InitImageLayerCacher(cacheFile, lockFile, cachePath string, maxRecordSize int64) (*ImageLayerCacher, error) {
	log.WithFields(log.Fields{"maxRecordSize": maxRecordSize}).Info()
	if maxRecordSize == 0 {
		return nil, nil
	}
	log.WithFields(log.Fields{"cacheFile": cacheFile, "lockFile": lockFile, "cachePath": cachePath}).Debug()

	os.MkdirAll(cachePath, 0755)
	os.MkdirAll(filepath.Join(cachePath, subRecordFolder), 0755)
	return &ImageLayerCacher{
		flock:			-1,
		lockFile:       lockFile,
		dataFile:  		cacheFile,
		cachePath: 		cachePath,
		maxRecordSize: 	maxRecordSize*1024*1024,
	}, nil
}

func (lc *ImageLayerCacher) LeaveLayerCacher() {
	log.Debug()
	syscall.Close(lc.flock)
}

func (lc *ImageLayerCacher) lock() {
	if lc.flock == -1 { // need to keep it within the same goroutine (pid)
		if fd, err := syscall.Open(lc.lockFile, syscall.O_CREAT|syscall.O_RDONLY, 0600); err == nil {
			lc.flock = fd
		} else {
			log.WithFields(log.Fields{"error": err}).Error("Lock failed")
			return
		}
	}

	if err := syscall.Flock(lc.flock, syscall.LOCK_EX); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Wait")
	}
	// log.WithFields(log.Fields{"fn": utils.GetCaller(3, nil)}).Debug()
	// time.Sleep(time.Second*10)
}

func (lc *ImageLayerCacher) unlock() {
	// log.WithFields(log.Fields{"fn": utils.GetCaller(3, nil)}).Debug()
	syscall.Flock(lc.flock, syscall.LOCK_UN)
}

func (lc *ImageLayerCacher) readCacheFile() *CacherData {
	var cache CacherData
	file, _ := ioutil.ReadFile(lc.dataFile)
	json.Unmarshal([]byte(file), &cache)
	if cache.CacheRecordMap == nil {
		cache.CacheRecordMap = make(map[string]*cacheData)
	}

	// log.WithFields(log.Fields{"cache": cache}).Debug()
	return &cache // return empty data even if does not exist
}

func (lc *ImageLayerCacher) writeCacheFile(cache *CacherData) {
	data, _ := json.Marshal(cache)
	// log.WithFields(log.Fields{"data": string(data)}).Debug()
	ioutil.WriteFile(lc.dataFile, data, 0644)
}

///////////////// Record caches ////////////////
func (lc *ImageLayerCacher) RecordName(id string, record interface{}) string {
	switch record.(type) {
		case *LayerRecord:  // scan package
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
	cc, ok := cacher.CacheRecordMap[name]
	if !ok {
		return "", errors.New("Not found: " + name)
	}

	defer lc.writeCacheFile(cacher) // update reference count

	// double check
	if _, err := os.Stat(cc.Path); err != nil {
		cacher.CurRecordSize -= cc.Size
		delete(cacher.CacheRecordMap, id)
		return "", err
	}

	value, _ := ioutil.ReadFile(cc.Path)
	uzb := utils.GunzipBytes(value)
	json.Unmarshal([]byte(uzb), record)
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
		if err := ioutil.WriteFile(dest, zb, 0644); err != nil {
			log.WithFields(log.Fields{"error": err, "dest": dest}).Error()
		}
		size := int64(len(zb))
		cacher.CurRecordSize += size
		cacher.CacheRecordMap[name] = &cacheData { Path: dest, Size: size, RefLast: time.Now(),}
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

func (lc *ImageLayerCacher) IsExistInCache(files []string) (string, bool) {
	lc.lock()
	defer lc.unlock()

	cacher := lc.readCacheFile()
	for _, name := range files {
		if _, ok := cacher.CacheRecordMap[name]; !ok {
			return name, false	// return first missing item
		}
	}
	return "", true
}
