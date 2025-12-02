package common

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

const CveDBExpandPath = "/tmp/neuvector/db/"

type CveDB struct {
	ExpandPath      string
	CveDBVersion    string
	CveDBCreateTime string
}

func NewCveDB() *CveDB {
	return &CveDB{
		ExpandPath: CveDBExpandPath,
	}
}

const maxExtractSize = 0 // No extract limit
const maxVersionHeader = 100 * 1024
const maxBufferSize = 1024 * 1024

const (
	DBUbuntu = iota
	DBDebian
	DBCentos
	DBAlpine
	DBAmazon
	DBOracle
	DBMariner
	DBSuse
	DBPhoton
	DBRocky
	DBMax
)

const DBAppName = "apps"

type dbBuffer struct {
	Name  string
	Full  map[string]VulFull
	Short []VulShort
}

type dbSpace struct {
	Buffers [DBMax]dbBuffer
}

var DBS dbSpace = dbSpace{
	Buffers: [DBMax]dbBuffer{
		DBUbuntu:  {Name: "ubuntu"},
		DBDebian:  {Name: "debian"},
		DBCentos:  {Name: "centos"},
		DBAlpine:  {Name: "alpine"},
		DBAmazon:  {Name: "amazon"},
		DBOracle:  {Name: "oracle"},
		DBMariner: {Name: "mariner"},
		DBPhoton:  {Name: "photon"},
		DBSuse:    {Name: "suse"},
		DBRocky:   {Name: "rocky"},
	},
}

func GetCVEDBEncryptKey() []byte {
	return cveDBEncryptKey
}

type OutputPackage struct {
	Package      string `json:"Package"`
	FixedVersion string `json:"FixedVersion"`
}

type OutputCVEEntry struct {
	OSApp            string           `json:"OSApp"`
	OSAppVer         string           `json:"OSAppVersion"`
	PublishedDate    string           `json:"PublishedDate"`
	LastModifiedDate string           `json:"LastModifiedDate"`
	Packages         []*OutputPackage `json:"Packages"`
}

type OutputCVEVul struct {
	Name      string            `json:"Name"`
	Severity  string            `json:"Severity"`
	Score     float32           `json:"Score"`
	Vectors   string            `json:"Vectors"`
	ScoreV3   float32           `json:"ScoreV3"`
	VectorsV3 string            `json:"VectorsV3"`
	Entries   []*OutputCVEEntry `json:"Entries"`
}

func ns2String(ns string) (string, string) {
	if strings.HasPrefix(ns, "alpine:") {
		return "Alpine Linux", ns[7:]
	} else if strings.HasPrefix(ns, "amzn:") {
		return "Amazon Linux", ns[5:]
	} else if strings.HasPrefix(ns, "centos:") {
		return "Red Hat Linux", ns[7:]
	} else if strings.HasPrefix(ns, "debian:") {
		return "Debian", ns[7:]
	} else if strings.HasPrefix(ns, "mariner:") {
		return "CBL-Mariner", ns[8:]
	} else if strings.HasPrefix(ns, "oracle:") {
		return "Oracle Linux", ns[7:]
	} else if strings.HasPrefix(ns, "sles:l") {
		return "openSUSE Leap", ns[6:]
	} else if strings.HasPrefix(ns, "sles:tw") {
		return "openSUSE Tumbleweed", ns[6:]
	} else if strings.HasPrefix(ns, "sles:") {
		return "SUSE Linux", ns[5:]
	} else if strings.HasPrefix(ns, "ubuntu:") {
		return "Ubuntu", ns[7:]
	} else if strings.HasPrefix(ns, "photon:") {
		return "Photon", ns[7:]
	}

	return "", ""
}

func ReadCveDbMeta(path string, output bool) (map[string]*share.ScanVulnerability, []*OutputCVEVul, error) {
	var osCVEs map[string]*OutputCVEVul
	var appCVEs map[string]*OutputCVEVul
	var outCVEs map[string]*OutputCVEVul
	var out []*OutputCVEVul
	var err error

	if output {
		outCVEs = make(map[string]*OutputCVEVul)
	}

	fullDb := make(map[string]*share.ScanVulnerability, 0)
	for i := 0; i < DBMax; i++ {
		if osCVEs, err = readCveDbMeta(path, DBS.Buffers[i].Name, fullDb, output); err != nil {
			return nil, nil, err
		}
		if output {
			for cve, v := range osCVEs {
				if exist, ok := outCVEs[cve]; ok {
					exist.Entries = append(exist.Entries, v.Entries...)
				} else {
					outCVEs[cve] = v
				}
			}
		}
	}

	if appCVEs, err = readAppDbMeta(path, fullDb, output); err != nil {
		return nil, nil, err
	}

	if output {
		for cve, v := range appCVEs {
			if exist, ok := outCVEs[cve]; ok {
				exist.Entries = append(exist.Entries, v.Entries...)
			} else {
				outCVEs[cve] = v
			}
		}

		// convert map to array
		i := 0
		out = make([]*OutputCVEVul, len(outCVEs))
		for _, v := range outCVEs {
			out[i] = v
			i++
		}

		sort.Slice(out, func(s, t int) bool {
			return out[s].Name < out[t].Name
		})
	}

	return fullDb, out, nil
}

func readCveDbMeta(path, osname string, fullDb map[string]*share.ScanVulnerability, output bool) (map[string]*OutputCVEVul, error) {
	var outCVEs map[string]*OutputCVEVul

	filename := fmt.Sprintf("%s%s_full.tb", path, osname)
	fvul, err := os.Open(filename)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "os": osname}).Error("Can't open file")
		return nil, err
	}
	defer fvul.Close()

	data, err := io.ReadAll(fvul)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Read file error")
		return nil, err
	}

	if output {
		outCVEs = make(map[string]*OutputCVEVul, 0)
	}

	buf := make([]byte, maxBufferSize)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(buf, maxBufferSize)
	for scanner.Scan() {
		var v VulFull
		s := scanner.Text()
		err := json.Unmarshal([]byte(s), &v)
		var cveName string
		// get ubuntu upstream out from ubuntu. make it an independent branch
		if v.Namespace == "ubuntu:upstream" {
			cveName = fmt.Sprintf("upstream:%s", v.Name)
		} else {
			cveName = fmt.Sprintf("%s:%s", osname, v.Name)
		}
		if err == nil {
			if _, ok := fullDb[cveName]; !ok {
				sv := &share.ScanVulnerability{
					Description:      v.Description,
					Link:             v.Link,
					Severity:         v.Severity,
					Score:            float32(v.CVSSv2.Score),
					Vectors:          v.CVSSv2.Vectors,
					ScoreV3:          float32(v.CVSSv3.Score),
					VectorsV3:        v.CVSSv3.Vectors,
					PublishedDate:    v.IssuedDate.Format(time.RFC3339),
					LastModifiedDate: v.LastModDate.Format(time.RFC3339),
					FeedRating:       v.FeedRating,
				}
				fullDb[cveName] = sv
			}

			if output {
				os, ver := ns2String(v.Namespace)
				if os != "" {
					var ov *OutputCVEVul
					var ok bool

					if ov, ok = outCVEs[v.Name]; !ok {
						ov = &OutputCVEVul{
							Name:      v.Name,
							Severity:  v.Severity,
							Score:     float32(v.CVSSv2.Score),
							Vectors:   v.CVSSv2.Vectors,
							ScoreV3:   float32(v.CVSSv3.Score),
							VectorsV3: v.CVSSv3.Vectors,
							Entries:   make([]*OutputCVEEntry, 0),
						}
						outCVEs[v.Name] = ov
					}

					e := &OutputCVEEntry{
						OSApp:            os,
						OSAppVer:         ver,
						PublishedDate:    v.IssuedDate.Format("2006-01-02"),
						LastModifiedDate: v.LastModDate.Format("2006-01-02"),
						Packages:         make([]*OutputPackage, 0),
					}
					for _, fi := range v.FixedIn {
						e.Packages = append(e.Packages, &OutputPackage{Package: fi.Name, FixedVersion: fi.Version})
					}
					sort.Slice(e.Packages, func(s, t int) bool {
						return e.Packages[s].Package < e.Packages[t].Package
					})

					ov.Entries = append(ov.Entries, e)
				}
			}
		}
	}

	log.WithFields(log.Fields{"vuls": len(fullDb), "osname": osname, "path": path}).Debug("")
	return outCVEs, nil
}

func readAppDbMeta(path string, fullDb map[string]*share.ScanVulnerability, output bool) (map[string]*OutputCVEVul, error) {
	var outCVEs map[string]*OutputCVEVul

	filename := fmt.Sprintf("%s/apps.tb", path)
	fvul, err := os.Open(filename)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("open file error")
		return nil, err
	}
	defer fvul.Close()

	data, err := io.ReadAll(fvul)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Read file error")
		return nil, err
	}

	if output {
		outCVEs = make(map[string]*OutputCVEVul)
	}

	buf := make([]byte, maxBufferSize)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(buf, maxBufferSize)
	for scanner.Scan() {
		var v AppModuleVul
		s := scanner.Text()
		err := json.Unmarshal([]byte(s), &v)
		if err == nil {
			cveName := fmt.Sprintf("%s:%s", DBAppName, v.VulName)
			if _, ok := fullDb[cveName]; !ok {
				sv := &share.ScanVulnerability{
					Description:      v.Description,
					Link:             v.Link,
					Severity:         v.Severity,
					Score:            float32(v.Score),
					Vectors:          v.Vectors,
					ScoreV3:          float32(v.ScoreV3),
					VectorsV3:        v.VectorsV3,
					PublishedDate:    v.IssuedDate.Format(time.RFC3339),
					LastModifiedDate: v.LastModDate.Format(time.RFC3339),
					FeedRating:       v.Severity,
				}
				fullDb[cveName] = sv

				if output {
					var ov *OutputCVEVul
					var ok bool

					if ov, ok = outCVEs[v.VulName]; !ok {
						ov = &OutputCVEVul{
							Name:      v.VulName,
							Severity:  v.Severity,
							Score:     float32(v.Score),
							Vectors:   v.Vectors,
							ScoreV3:   float32(v.ScoreV3),
							VectorsV3: v.VectorsV3,
							Entries:   make([]*OutputCVEEntry, 0),
						}
						outCVEs[v.VulName] = ov
					}

					e := &OutputCVEEntry{
						OSApp:            v.AppName,
						OSAppVer:         "",
						PublishedDate:    v.IssuedDate.Format("2006-01-02"),
						LastModifiedDate: v.LastModDate.Format("2006-01-02"),
						Packages:         make([]*OutputPackage, 0),
					}

					e.Packages = append(e.Packages, &OutputPackage{Package: v.ModuleName})
					for _, fv := range v.FixedVer {
						op := strings.Replace(fv.OpCode, "or", "||", -1)
						op = strings.Replace(op, "gt", ">", -1)
						op = strings.Replace(op, "lt", "<", -1)
						op = strings.Replace(op, "eq", "=", -1)
						e.Packages[0].FixedVersion = fmt.Sprintf("%s%s;%s", op, fv.Version, e.Packages[0].FixedVersion)
					}
					ov.Entries = append(ov.Entries, e)
				}
			}
		} else {
			log.WithFields(log.Fields{"error": err}).Error("Unmarshal vulnerability error")
		}
	}
	return outCVEs, nil
}

func LoadVulnerabilityIndex(path, osname string) ([]VulShort, error) {
	filename := fmt.Sprintf("%s/%s_index.tb", path, osname)
	fvul, err := os.Open(filename)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Open file error")
		return nil, err
	}
	defer fvul.Close()

	data, err := io.ReadAll(fvul)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Read file error")
		return nil, err
	}

	vul := make([]VulShort, 0)

	buf := make([]byte, maxBufferSize)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(buf, maxBufferSize)
	for scanner.Scan() {
		var v VulShort
		s := scanner.Text()
		err := json.Unmarshal([]byte(s), &v)
		if err == nil {
			vul = append(vul, v)
		} else {
			log.Error("Unmarshal vulnerability err")
		}
	}
	return vul, nil
}

func LoadFullVulnerabilities(path, osname string) (map[string]VulFull, error) {
	filename := fmt.Sprintf("%s%s_full.tb", path, osname)

	fvul, err := os.Open(filename)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Can't open file")
		return nil, err
	}
	defer fvul.Close()

	data, err := io.ReadAll(fvul)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Read file error")
		return nil, err
	}

	fullDb := make(map[string]VulFull, 0)

	buf := make([]byte, maxBufferSize)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(buf, maxBufferSize)
	for scanner.Scan() {
		var v VulFull
		s := scanner.Text()
		err := json.Unmarshal([]byte(s), &v)
		cveName := fmt.Sprintf("%s:%s", v.Namespace, v.Name)
		if err == nil {
			fullDb[cveName] = v
		}
	}
	return fullDb, nil
}

func uniqueVulDb(vuls []AppModuleVul) []AppModuleVul {
	var unique []AppModuleVul
	dedup := utils.NewSet()
	for _, v := range vuls {
		if !dedup.Contains(v.VulName) {
			dedup.Add(v.VulName)
			unique = append(unique, v)
		}
	}
	return unique
}

func LoadAppVulsTb(path string) (map[string][]AppModuleVul, error) {
	filename := fmt.Sprintf("%s/apps.tb", path)
	fvul, err := os.Open(filename)
	if err != nil {
		log.WithFields(log.Fields{"filename": filename, "error": err}).Error("open file error")
		return nil, err
	}
	defer fvul.Close()

	data, err := io.ReadAll(fvul)
	if err != nil {
		log.WithFields(log.Fields{"filename": filename, "error": err}).Error("Read file error")
		return nil, err
	}

	vul := make(map[string][]AppModuleVul, 0)

	buf := make([]byte, maxBufferSize)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(buf, maxBufferSize)
	for scanner.Scan() {
		var v AppModuleVul
		s := scanner.Text()
		err := json.Unmarshal([]byte(s), &v)
		if err == nil {
			vf, ok := vul[v.ModuleName]
			if !ok {
				vf = make([]AppModuleVul, 0)
			}
			vf = append(vf, v)
			vul[v.ModuleName] = vf
		} else {
			log.Error("Unmarshal vulnerability err")
		}
	}

	// for org.apache.logging.log4j:log4j-core, we will also search
	// org.apache.logging.log4j.log4j-core: for backward compatibility
	// log4j-core: for jar file without pom.xml. Prefix jar: to avoid collision
	var mns []string
	for mn := range vul {
		if colon := strings.LastIndex(mn, ":"); colon > 0 {
			mns = append(mns, mn)
		}
	}

	for _, mn := range mns {
		colon := strings.LastIndex(mn, ":")
		m := strings.ReplaceAll(mn, ":", ".")
		vf := vul[mn]

		if _, ok := vul[m]; ok {
			vul[m] = uniqueVulDb(append(vul[m], vf...))
		} else {
			vul[m] = vf
		}
		if m = mn[colon+1:]; len(m) > 0 {
			key := fmt.Sprintf("jar:%s", m)
			if _, ok := vul[key]; ok {
				vul[key] = uniqueVulDb(append(vul[key], vf...))
			} else {
				vul[key] = vf
			}
		}
	}
	return vul, nil
}

func LoadRawFile(path, name string) ([]byte, error) {
	filename := fmt.Sprintf("%s/%s", path, name)
	fp, err := os.Open(filename)
	if err != nil {
		log.WithFields(log.Fields{"filename": filename, "error": err}).Error("open file error")
		return nil, err
	}
	defer fp.Close()

	data, err := io.ReadAll(fp)
	if err != nil {
		log.WithFields(log.Fields{"filename": filename, "error": err}).Error("Read file error")
		return nil, err
	}

	return data, nil
}

// Reduce the flackiness of the continuse scanner process by cleaning up the db after a certain period of time.
func CleanUpDB(path string) error {
	cleanUpDBRetry := 10
	if os.Getenv("CLEAN_UP_DB_RETRY") != "" {
		cleanUpRetry, err := strconv.Atoi(os.Getenv("CLEAN_UP_DB_RETRY"))
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to parse CLEAN_UP_DB_RETRY")
		} else {
			cleanUpDBRetry = cleanUpRetry
		}
	}

	var err error
	for i := 0; i < cleanUpDBRetry; i++ {
		if err = os.RemoveAll(path); err != nil {
			log.WithFields(log.Fields{"error": err, "dir": path}).Error("Failed to remove directory")
		} else {
			break
		}
		time.Sleep(time.Second * 1)
	}
	return err
}

func LoadCveDb(path, desPath string, encryptKey []byte) (string, string, error) {
	var latestVer string

	if err := CleanUpDB(desPath); err != nil {
		log.WithFields(log.Fields{"error": err, "dir": desPath}).Error("Failed to remove directory before loading new database")
		return "", "", err
	}

	if _, err := os.Stat(desPath); os.IsNotExist(err) {
		if err = os.MkdirAll(desPath, 0760); err != nil {
			log.WithFields(log.Fields{"error": err, "dir": desPath}).Error("Failed to make directory")
			return "", "", err
		}
	}

	// Read new db version
	newVer, update, err := GetDbVersion(path)
	if err == nil {
		log.WithFields(log.Fields{"version": newVer, "update": update}).Debug("New DB found")
	} else {
		log.Error(err)
	}

	// Read expanded db version
	oldVer, _, oldErr := CheckExpandedDb(desPath, true)
	if oldErr != nil && err != nil {
		// no new database, no expanded database
		log.WithFields(log.Fields{"error": err}).Error("No CVE database found")
		return "", "", err
	} else if oldErr != nil && err == nil {
		log.WithFields(log.Fields{"version": newVer}).Info("Expand new DB")

		// has new database, no expanded database, untar the new database
		err = unzipDb(path, desPath, encryptKey)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Unzip CVE database")
			return "", "", err
		}

		newVer, update, err = CheckExpandedDb(desPath, true)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("CVE database format error")
			return "", "", errors.New("Invalid database format")
		}
		latestVer = fmt.Sprintf("%.3f", newVer)
	} else if oldErr == nil && err == nil && newVer > oldVer {
		log.WithFields(log.Fields{"version": newVer}).Info("Expand new DB")

		// new database is newer then the expanded database, untar the new database
		tmpDir, err := os.MkdirTemp(os.TempDir(), "cvedb")
		if err != nil {
			log.Errorf("could not create temporary folder for RPM detection: %s", err)
			return "", "", err
		}

		err = unzipDb(path, tmpDir+"/", encryptKey)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Unzip CVE database")
			os.RemoveAll(tmpDir)
			return "", "", err
		}

		newVer, update, err = CheckExpandedDb(tmpDir+"/", true)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("CVE database format error")
			os.Remove(path + share.DefaultCVEDBName)
			os.RemoveAll(tmpDir)
		} else {
			removeDb(desPath)
			err = moveDb(tmpDir+"/", desPath)
			os.RemoveAll(tmpDir)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("mv CVE database error")
				return "", "", err
			}
		}
		latestVer = fmt.Sprintf("%.3f", newVer)
	} else {
		latestVer = fmt.Sprintf("%.3f", oldVer)
	}

	return latestVer, update, nil
}

func GetDbVersion(path string) (float64, string, error) {
	f, err := os.Open(path + share.DefaultCVEDBName)
	if err != nil {
		return 0, "", fmt.Errorf("Read db file fail: %v", err)
	}
	defer f.Close()

	bhead := make([]byte, 4)
	nlen, err := f.Read(bhead)
	if err != nil || nlen != 4 {
		return 0, "", fmt.Errorf("Read db file error: %v", err)
	}
	var headLen int32
	err = binary.Read(bytes.NewReader(bhead), binary.BigEndian, &headLen)
	if err != nil {
		return 0, "", fmt.Errorf("Read header len error: %v", err)
	}

	if headLen > maxVersionHeader {
		return 0, "", fmt.Errorf("Version Header too big: %v", headLen)
	}

	bhead = make([]byte, headLen)
	nlen, err = f.Read(bhead)
	if err != nil || nlen != int(headLen) {
		return 0, "", fmt.Errorf("Read db file version error:%v", err)
	}

	var keyVer KeyVersion

	err = json.Unmarshal(bhead, &keyVer)
	if err != nil {
		return 0, "", fmt.Errorf("Unmarshal keys error:%v", err)
	}
	verFl, err := strconv.ParseFloat(keyVer.Version, 64)
	if err != nil {
		return 0, "", fmt.Errorf("Invalid version value:%v", err)
	}

	return verFl, keyVer.UpdateTime, nil
}

func unzipDb(path, desPath string, encryptKey []byte) error {
	f, err := os.Open(path + share.DefaultCVEDBName)
	if err != nil {
		log.Info("Open zip db file fail")
		return err
	}
	defer f.Close()

	if _, err := f.Seek(0, 0); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
	}

	// read keys len
	bhead := make([]byte, 4)
	nlen, err := f.Read(bhead)
	if err != nil || nlen != 4 {
		log.WithFields(log.Fields{"error": err}).Error("Read db file error")
		return err
	}
	var headLen int32
	err = binary.Read(bytes.NewReader(bhead), binary.BigEndian, &headLen)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Write header len error")
		return err
	}
	if headLen > maxVersionHeader {
		log.Info("Version Header too big:", headLen)
		return err
	}

	// Read head and write keys file
	bhead = make([]byte, headLen)
	nlen, err = f.Read(bhead)
	if err != nil || nlen != int(headLen) {
		log.WithFields(log.Fields{"error": err}).Error("Read db file error")
		return err
	}
	err = os.WriteFile(desPath+"keys", bhead, 0400)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Write keys file error")
		return err
	}

	// Read the rest of DB
	cipherData, err := io.ReadAll(f)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Read db file tar part error")
		return err
	}

	// Use local decrypt function
	plainData, err := decrypt(cipherData, encryptKey)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Decrypt tar file error")
		return err
	}

	tarFile := bytes.NewReader(plainData)
	err = utils.ExtractAllArchiveToFiles(desPath, tarFile, maxExtractSize, nil)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Extract db file error")
		return err
	}

	return nil
}

func checkDbHash(filename, hash string) bool {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.WithFields(log.Fields{"file": filename, "error": err}).Info("Read file error")
		return false
	}

	sha := sha256.Sum256(data)
	ss := fmt.Sprintf("%x", sha)
	if hash == ss {
		return true
	} else {
		log.WithFields(log.Fields{"file": filename}).Error("Hash not match")
		return false
	}
}

const RHELCpeMapFile = "rhel-cpe.map"

var fileList = []string{
	"keys",
	"ubuntu_index.tb",
	"ubuntu_full.tb",
	"debian_index.tb",
	"debian_full.tb",
	"centos_index.tb",
	"centos_full.tb",
	"alpine_index.tb",
	"alpine_full.tb",
	"amazon_index.tb",
	"amazon_full.tb",
	"mariner_full.tb",
	"mariner_index.tb",
	"photon_full.tb",
	"photon_index.tb",
	"oracle_index.tb",
	"oracle_full.tb",
	"suse_index.tb",
	"suse_full.tb",
	"apps.tb",
	RHELCpeMapFile,
}

func removeDb(path string) {
	for _, file := range fileList {
		os.Remove(path + file)
	}
}

func moveDb(path, desPath string) error {
	for _, file := range fileList {
		buf, err := utils.Exec(desPath, "mv", path+file, desPath+file)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error(fmt.Sprintf("%s\n", buf))
			return err
		}
	}
	return nil
}

func CheckExpandedDb(path string, checkHash bool) (float64, string, error) {
	data, err := os.ReadFile(path + "keys")
	if err != nil {
		return 0, "", err
	}

	var key KeyVersion
	err = json.Unmarshal(data, &key)
	if err != nil {
		removeDb(path)
		return 0, "", err
	}

	var verFl float64
	verFl, err = strconv.ParseFloat(key.Version, 64)
	if err != nil {
		removeDb(path)
		return 0, "", err
	}

	if checkHash {
		valid := true

		for i := 1; i < len(fileList); i++ {
			if !checkDbHash(path+fileList[i], key.Shas[fileList[i]]) {
				log.WithFields(log.Fields{"file": fileList[i]}).Error("Database hash error")
				valid = false
			}
		}

		if !valid {
			removeDb(path)
			return 0, "", errors.New("database hash error")
		}
	}

	return verFl, key.UpdateTime, nil
}
