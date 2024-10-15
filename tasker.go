package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/scanner/common"
)

const reqTemplate = "/tmp/%s_i.json"
const resTemplate = "/tmp/%s_o.json"
const cacertTemplate = "/tmp/%s_cacert"

// ///
type Tasker struct {
	bEnable             bool
	bShowDebug          bool
	mutex               sync.Mutex
	taskPath            string
	rtSock              string // Container socket URL
	sys                 *system.SystemTools
	maxCacherRecordSize int64
}

// ///
func newTasker(taskPath, rtSock string, showDebug bool, sys *system.SystemTools, maxCacherRecordSize int64) *Tasker {
	log.WithFields(log.Fields{"showDebug": showDebug}).Debug()

	return &Tasker{
		bEnable:             true,
		taskPath:            taskPath, // sannnerTask path
		rtSock:              rtSock,   // Container socket URL
		bShowDebug:          showDebug,
		sys:                 sys,
		maxCacherRecordSize: maxCacherRecordSize, // MB
	}
}

func TryWriteFile(filepath string, data []byte) error {
	_, err := os.Stat(filepath)
	if err == nil {
		return fmt.Errorf("file exists: %s", filepath)
	}
	if !os.IsNotExist(err) {
		return err
	}
	if err = os.WriteFile(filepath, data, 0644); err != nil {
		return err
	}
	return nil
}

func (ts *Tasker) writeInputFile(data []byte, cacert []byte) (uid string, err error) {
	uid = uuid.New().String()
	input := fmt.Sprintf(reqTemplate, uid)
	cacertInput := fmt.Sprintf(cacertTemplate, uid)

	defer func() {
		// clean up
		if err != nil {
			os.Remove(input)
			os.Remove(cacertInput)
		}
	}()

	err = TryWriteFile(input, data)
	if err != nil {
		return uid, err
	}

	if len(cacert) != 0 {
		err = TryWriteFile(cacertInput, cacert)
		if err != nil {
			return uid, err
		}
	}

	return uid, nil
}

// ////
func (ts *Tasker) putInputFile(request interface{}) (string, []string, error) {
	var args []string
	var uid string
	var data []byte
	var err error

	switch req := request.(type) {
	case share.ScanImageRequest:
		data, _ = json.Marshal(req)
		args = append(args, "-t", "reg")
		args = append(args, "-u", ts.rtSock)
		args = append(args, "-maxrec", strconv.FormatInt(ts.maxCacherRecordSize, 10))
	case share.ScanAppRequest:
		data, _ = json.Marshal(req)
		args = append(args, "-t", "pkg")
	case share.ScanData:
		data, _ = json.Marshal(req)
		args = append(args, "-t", "dat")
	case share.ScanAwsLambdaRequest:
		data, _ = json.Marshal(req)
		args = append(args, "-t", "awl")
	default:
		return "", args, errors.New("invalid type")
	}

	if ts.bShowDebug {
		args = append(args, "-x")
	}

	cfg := getGlobalConfig()
	cacerts := ""

	if cfg.tlsVerification {
		args = append(args, "--enable-tls-verification")
		cacerts = cfg.caCerts
	}

	/// lock the allocation
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	for i := 0; i < 256; i++ {
		uid, err = ts.writeInputFile(data, []byte(cacerts))
		if err != nil {
			continue // retry
		}

		args = append(args, "-i", fmt.Sprintf(reqTemplate, uid))
		args = append(args, "-o", fmt.Sprintf(resTemplate, uid))
		if cacerts != "" {
			args = append(args, "--cacerts", fmt.Sprintf(cacertTemplate, uid))
		}
		return uid, args, nil
	}

	return uid, args, errors.New("failed to allocate")
}

// ///
func (ts *Tasker) getResultFile(uid string) (*share.ScanResult, error) {
	jsonFile, err := os.Open(fmt.Sprintf(resTemplate, uid))
	if err != nil {
		log.WithFields(log.Fields{"error": err, "uid": uid}).Error("Failed to open result")
		return nil, err
	}
	byteValue, _ := io.ReadAll(jsonFile)
	jsonFile.Close()

	var res share.ScanResult
	if err = json.Unmarshal(byteValue, &res); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to parse result")
		return nil, err
	}
	log.Debug("Completed")
	return &res, nil
}

// ////
func (ts *Tasker) Run(ctx context.Context, request interface{}) (*share.ScanResult, error) {
	if !ts.bEnable {
		return nil, fmt.Errorf("session ended")
	}

	log.Debug()
	uid, args, err := ts.putInputFile(request)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error()
		return nil, err
	}

	// remove files
	defer os.Remove(fmt.Sprintf(reqTemplate, uid))
	defer os.Remove(fmt.Sprintf(resTemplate, uid))
	defer os.Remove(fmt.Sprintf(cacertTemplate, uid))

	// image working folder
	workingFolder := common.CreateImagePath(uid)
	defer os.RemoveAll(workingFolder)

	log.WithFields(log.Fields{"cmd": ts.taskPath, "wpath": workingFolder, "args": args}).Debug()
	//////
	cmd := exec.Command(ts.taskPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if ts.bShowDebug {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Start(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Start")
		return nil, err
	}

	pgid := cmd.Process.Pid
	// log.WithFields(log.Fields{"pid": pgid}).Debug()
	ts.sys.AddToolProcess(pgid, 0, "Run", uid)

	ctxError := false
	bRunning := true
	go func() {
		for bRunning {
			if ctx.Err() != nil { // context.Canceled: remote cancelled
				ctxError = true
				// log.WithFields(log.Fields{"error": ctx.Err()}).Error("gRpc")
				ts.sys.RemoveToolProcess(pgid, true) // kill it
				return
			}
			time.Sleep(time.Millisecond * 250)
		}
	}()

	err = cmd.Wait()
	bRunning = false
	if ctxError {
		err = ctx.Err()
	} else {
		ts.sys.RemoveToolProcess(pgid, false)
	}

	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Done")
		return nil, err
	}
	return ts.getResultFile(uid)
}

// ///
func (ts *Tasker) Close() {
	log.Debug()

	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	ts.bEnable = false

	//
	ts.sys.ShowToolProcesses()
	ts.sys.StopToolProcesses()
}
