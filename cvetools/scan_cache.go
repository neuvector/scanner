package cvetools

import (
	"encoding/json"
	"errors"
	"io"
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
	SecretLogs  []*share.ScanSecretLog		`json:"secrets,omitempty"`
	SetidPerm 	[]*share.ScanSetIdPermLog	`json:"set_ids,omitempty"`
}

type ContainerFileMap struct {
	FileMap		map[string]string	`json:"file_map,omitempty"`
}

type cacheData struct {
	Path	string		`json:"path"`
	Size	int64		`json:"size"`
	RefCnt	uint32		`json:"ref_cnt"`
	RefLast	time.Time	`json:"ref_last"`
}

type CacherData struct {
	CacheLayerMap 	map[string]*cacheData	`json:"cache_data,omitempty"`
	CacheRecordMap 	map[string]*cacheData	`json:"cache_records,omitempty"`
	CurLayerSize   	int64					`json:"current_layer_size"`
	CurRecordSize   int64					`json:"current_record_size"`
}

type ImageLayerCacher struct {
	flock			int
	cachePath 		string
	dataFile		string
    lockFile		string
	maxLayerSize   	int64	// raw data
	maxRecordSize	int64	// scanned data: modules
}

const pickVictimCnt = 8
const subLayerFolder = "data"
const subRecordFolder = "ref"

////////
func InitImageLayerCacher(cacheFile, lockFile, cachePath string, maxLayerSize, maxRecordSize int64) (*ImageLayerCacher, error) {
	log.WithFields(log.Fields{"maxLayerSize": maxLayerSize, "maxRecordSize": maxRecordSize}).Info()
	if maxLayerSize == 0 && maxRecordSize == 0 {
		return nil, nil
	}
	log.WithFields(log.Fields{"cacheFile": cacheFile, "lockFile": lockFile, "cachePath": cachePath}).Debug()

	os.MkdirAll(cachePath, 0755)
	os.MkdirAll(filepath.Join(cachePath, subLayerFolder), 0755)
	os.MkdirAll(filepath.Join(cachePath, subRecordFolder), 0755)

	maxLayerSize = maxLayerSize*1024*1024
	maxRecordSize = maxRecordSize*1024*1024
	return &ImageLayerCacher{
		flock:			-1,
		lockFile:       lockFile,
		dataFile:  		cacheFile,
		cachePath: 		cachePath,
		maxLayerSize: 	maxLayerSize,
		maxRecordSize: 	maxRecordSize,
	}, nil
}

func (lc *ImageLayerCacher) LeaveLayerCacher() {
	log.Debug()
	syscall.Close(lc.flock)
}

func (lc *ImageLayerCacher) IsLayerDataDisable() bool {
	return (lc.maxLayerSize < 1)
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
	if cache.CacheLayerMap == nil {
		cache.CacheLayerMap = make(map[string]*cacheData)
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
	ioutil.WriteFile(lc.dataFile, data, 0644)
}

///////////////// Record caches ////////////////
func (lc *ImageLayerCacher) RecordName(id string, record interface{}) string {
	switch record.(type) {
		case *LayerFiles:  // scan package
			return id + "_" + "layer_file"
		case *SecretPermLogs:
			return id + "_" + "secrets"
		case *ContainerFileMap:
			return id + "_" + "fmap"
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
		cacher.CurLayerSize -= cc.Size
		delete(cacher.CacheLayerMap, id)
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
			// log.WithFields(log.Fields{"path": cc.Path, "size": cc.Size, "last": cc.RefLast, "cnt": cc.RefCnt}).Debug("remove")
			removedSize += cc.Size
			os.RemoveAll(cc.Path)
			delete(cacher.CacheRecordMap, key)
		}
    }
	cacher.CurRecordSize -= removedSize
	log.WithFields(log.Fields{"cacher": cacher, "removed": removedSize}).Debug("done")
}

///////////////// Layer data caches ////////////////
func (lc *ImageLayerCacher) ReadLayerDataCache(layerID string) (io.ReadCloser, int64, error) {
	lc.lock()
	defer lc.unlock()

	cacher := lc.readCacheFile()
	cc, ok := cacher.CacheLayerMap[layerID]
	if !ok {
		return nil, 0, errors.New("not found")
	}

	defer lc.writeCacheFile(cacher) // update reference count

	// double check
	if _, err := os.Stat(cc.Path); err != nil {
		cacher.CurLayerSize -= cc.Size
		delete(cacher.CacheLayerMap, layerID)
		return nil, 0, errors.New("not exist")
	}
	rd, _ := os.Open(cc.Path)
	cc.RefCnt++
	cc.RefLast = time.Now()
	log.WithFields(log.Fields{"cc": cc}).Debug()
	return rd, cc.Size, nil
}

func (lc *ImageLayerCacher) WriteLayerDataCache(layerID string, rd io.ReadCloser, size int64, keeper utils.Set) (io.ReadCloser, error) {
	// log.WithFields(log.Fields{"layerID": layerID}).Debug()
	lc.lock()
	defer lc.unlock()

	cacher := lc.readCacheFile()
	if _, ok := cacher.CacheLayerMap[layerID]; !ok {
		dest := filepath.Join(lc.cachePath, subLayerFolder, layerID)
		outFile, err := os.Create(dest)
		if err != nil {
			log.WithFields(log.Fields{"dest": dest, "error": err}).Error()
			return rd, err
		}
		defer outFile.Close()
		if _, err = io.Copy(outFile, rd); err != nil {
			log.WithFields(log.Fields{"dest": dest, "error": err, "size": size}).Error()
			return rd, err
		}
		rd, _ = os.Open(dest)   // rebuild the io reader
		cacher.CurLayerSize += size
		cacher.CacheLayerMap[layerID] = &cacheData { Path: dest, Size: size, RefLast: time.Now(),}
		// log.WithFields(log.Fields{"dest": dest, "size": size}).Debug("data: wr")

		// prune the cacher size
		lc.pruneLayerDataCache(cacher, keeper)
	}
	lc.writeCacheFile(cacher)
	return rd, nil
}

func (lc *ImageLayerCacher) pruneLayerDataCache(cacher *CacherData, keeper utils.Set) {
	// log.WithFields(log.Fields{"curSize": cacher.CurLayerSize}).Debug()
	if cacher.CurLayerSize < lc.maxLayerSize {
		return
	}

	// exclude current cached layers, pick 8-16 victims
	var keys []string
	for layerID, _ := range cacher.CacheLayerMap {
		if keeper.Contains(layerID) {
			continue
		}
		keys = append(keys, layerID)
	}

	if len(keys) > pickVictimCnt {
		sort.SliceStable(keys, func(i, j int) bool {
			return cacher.CacheRecordMap[keys[i]].RefLast.Before(cacher.CacheRecordMap[keys[j]].RefLast)
			// return cacher.CacheLayerMap[keys[i]].RefCnt < cacher.CacheLayerMap[keys[j]].RefCnt
		})
	}

	var removedSize int64
	for i, layerID := range keys {
		if i >= pickVictimCnt {
			break
		}

		if cc, ok := cacher.CacheLayerMap[layerID]; ok {
			// log.WithFields(log.Fields{"path": cc.Path, "size": cc.Size, "last": cc.RefLast, "cnt": cc.RefCnt}).Debug("remove")
			removedSize += cc.Size
			os.RemoveAll(cc.Path)
			delete(cacher.CacheLayerMap, layerID)
		}
    }
	cacher.CurLayerSize -= removedSize
	log.WithFields(log.Fields{"cacher": cacher, "removed": removedSize}).Debug("done")
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
