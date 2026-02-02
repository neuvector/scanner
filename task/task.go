package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
)

// global control data
type taskMain struct {
	ctx     context.Context
	outfile string
}

// ///////////
func InitTaskMain(filename string) (*taskMain, bool) {
	tm := &taskMain{
		ctx:     context.Background(),
		outfile: filename,
	}
	return tm, true
}

// ///
func (tm *taskMain) ScanImage(req share.ScanImageRequest, imgPath string) (*share.ScanResult, error) {
	log.WithFields(log.Fields{
		"Registry": req.Registry, "image": fmt.Sprintf("%s:%s", req.Repository, req.Tag), "base": req.BaseImage,
	}).Debug()

	return cveTools.ScanImage(tm.ctx, &req, imgPath)
}

// ///
func (tm *taskMain) ScanAppPackage(req share.ScanAppRequest) (*share.ScanResult, error) {
	log.WithFields(log.Fields{"packages": len(req.Packages)}).Debug()

	return cveTools.ScanAppPackage(&req, "")
}

// ///
func (rs *taskMain) ScanImageData(data share.ScanData) (*share.ScanResult, error) {
	log.Debug()

	return cveTools.ScanImageData(&data)
}

// ///
func (rs *taskMain) ScanAwsLambda(data share.ScanAwsLambdaRequest, imgPath string) (*share.ScanResult, error) {
	log.WithFields(log.Fields{"function": data.FuncName, "region": data.Region}).Debug()

	return cveTools.ScanAwsLambda(&data, imgPath)
}

// /// worker
func (tm *taskMain) doScanTask(request interface{}, workingPath string) int {
	var err error
	var res *share.ScanResult

	switch req := request.(type) {
	case share.ScanImageRequest:
		res, err = tm.ScanImage(req, workingPath)
	case share.ScanAppRequest:
		res, err = tm.ScanAppPackage(req)
	case share.ScanData:
		res, err = tm.ScanImageData(req)
	case share.ScanAwsLambdaRequest:
		res, err = tm.ScanAwsLambda(req, workingPath)
	default:
		err = errors.New("invalid type")
	}

	if err != nil {
		return -1
	}

	// log.WithFields(log.Fields{"result": res}).Info("")
	data, _ := json.Marshal(res)
	if err := os.WriteFile(tm.outfile, data, 0644); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
	}
	return 0
}
