package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/httpclient"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
	"github.com/neuvector/scanner/common"
	"github.com/neuvector/scanner/cvetools"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: scannerTask [OPTIONS]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

var cveTools *cvetools.ScanTools // available inside package

// //
func checkDbReady() bool {
	var dbReady bool
	for {
		if newVer, createTime, err := common.CheckExpandedDb(cveTools.ExpandPath, false); err == nil {
			cveTools.CveDBVersion = fmt.Sprintf("%.3f", newVer)
			cveTools.CveDBCreateTime = createTime
			dbReady = true
			break
		} else {
			time.Sleep(time.Second * 4)
		}
	}
	return dbReady
}

// //////////////////////
func processRequest(tm *taskMain, scanType, infile, workingPath string) int {
	var err error
	jsonFile, err := os.Open(infile)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "file": infile}).Error("Failed to open input file")
		return -1
	}
	byteValue, _ := io.ReadAll(jsonFile)
	jsonFile.Close()

	// selector
	switch scanType {
	case "reg": // registry scan: images
		var req share.ScanImageRequest
		if err = json.Unmarshal(byteValue, &req); err == nil {
			return tm.doScanTask(req, workingPath)
		}
	case "pkg": // app package scan
		var req share.ScanAppRequest
		if err = json.Unmarshal(byteValue, &req); err == nil {
			return tm.doScanTask(req, workingPath)
		}
	case "dat": // img/pkg data scan: it is also a result from scan_running_image
		var req share.ScanData
		if err = json.Unmarshal(byteValue, &req); err == nil {
			return tm.doScanTask(req, workingPath)
		}
	case "awl": // aws lambda scan
		var req share.ScanAwsLambdaRequest
		if err = json.Unmarshal(byteValue, &req); err == nil {
			return tm.doScanTask(req, workingPath)
		}
	default:
		err = errors.New("invalid type")
	}

	log.WithFields(log.Fields{"type": scanType, "err": err}).Error("")
	return -1
}

// /////////////////////
func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&utils.LogFormatter{Module: "SCT"})

	scanType := flag.String("t", "", "scan type: reg, pkg, dat or awl (Required)")
	infile := flag.String("i", "input.json", "input json name")                       // uuid input filename
	outfile := flag.String("o", "result.json", "output json name")                    // uuid output filename
	modulefile := flag.String("m", "", "modules json name")                           // debug: modules for reg type
	rtSock := flag.String("u", "", "Container socket URL")                            // used for scan local image
	maxCacherRecordSize := flag.Int64("maxrec", 0, "maximum layer cacher size in MB") // common.MaxRecordCacherSizeMB
	tlsVerification := flag.Bool("enable-tls-verification", false, "enable tls verification")
	cacerts := flag.String("cacerts", "", "the path of cacerts file")
	verbose := flag.Bool("x", false, "more debug")

	flag.Usage = usage
	flag.Parse()

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	var pool *x509.CertPool
	if *cacerts != "" {
		certs, err := os.ReadFile(*cacerts)
		if err != nil {
			log.WithError(err).Warn("failed to load ca certs")
		}
		pool = x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(certs); !ok {
			log.Warn("failed to parse ca cert")
		}
	}

	// Default TLS config
	err := httpclient.SetDefaultTLSClientConfig(&httpclient.TLSClientSettings{
		TLSconfig: &tls.Config{
			InsecureSkipVerify: !*tlsVerification, // #nosec G402
			RootCAs:            pool,
		},
	}, "", "", "")
	if err != nil {
		log.WithError(err).Warn("failed to set default TLS config")
	}

	// acquire tool
	layerCacher, _ := cvetools.InitImageLayerCacher(common.ImageLayerCacherFile, common.ImageLayerLockFile, common.ImageLayersCachePath, *maxCacherRecordSize)
	if layerCacher != nil {
		defer layerCacher.LeaveLayerCacher()
	}

	cveTools = cvetools.NewScanTools(*rtSock, system.NewSystemTools(), layerCacher, *modulefile)
	common.InitDebugFilters("")

	// create an imgPath from the input file
	var imageWorkingPath string
	if *infile == "inputs.json" { // default
		imageWorkingPath = common.CreateImagePath("")
	} else { // normal from scanner
		uid := strings.TrimPrefix(*infile, "/tmp/")
		uid = strings.TrimSuffix(uid, "_i.json") // obtains the uuid
		imageWorkingPath = common.GetImagePath(uid)
	}
	log.WithFields(log.Fields{"imageWorkingPath": imageWorkingPath}).Debug()
	defer os.RemoveAll(imageWorkingPath) // either delete from caller (kill -9) or self-deleted

	log.Info("Running ... ")
	start := time.Now()

	done := make(chan int, 1)
	c_sig := make(chan os.Signal, 1)
	signal.Notify(c_sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c_sig
		done <- 0
	}()

	go func() {
		nRet := -1
		if checkDbReady() { // check if loaded and unzipped in the target path
			if tm, ok := InitTaskMain(*outfile); ok {
				nRet = processRequest(tm, *scanType, *infile, imageWorkingPath)
			}
		}

		if nRet < 0 {
			log.Error("Failed to init. Exit!")
			nRet = -10
		}
		done <- nRet
	}()

	rc := <-done
	log.WithFields(log.Fields{"imageWorkingPath": imageWorkingPath, "used": time.Since(start).Seconds()}).Info("Exiting ...")
	os.Exit(rc)
}
