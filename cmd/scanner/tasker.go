package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

const (
	reqSuffix    = "_i.json"
	resSuffix    = "_o.json"
	cacertSuffix = "_cacert"
)

// ///
type Tasker struct {
	bEnable             bool
	bShowDebug          bool
	mutex               sync.Mutex
	taskPath            string
	taskDir             string // private (0700) directory holding the task request, result and cacert files
	rtSock              string // Container socket URL
	sys                 *system.SystemTools
	maxCacherRecordSize int64
}

// ///
// Task files may carry registry credentials, so they are kept in a directory only this process's user can
// access instead of the shared /tmp.
func newTasker(taskPath, rtSock string, showDebug bool, sys *system.SystemTools, maxCacherRecordSize int64) (*Tasker, error) {
	log.WithFields(log.Fields{"showDebug": showDebug}).Debug()

	taskDir, err := os.MkdirTemp("", "scanner-task-")
	if err != nil {
		return nil, fmt.Errorf("failed to create task file directory: %w", err)
	}

	return &Tasker{
		bEnable:             true,
		taskPath:            taskPath, // sannnerTask path
		taskDir:             taskDir,
		rtSock:              rtSock, // Container socket URL
		bShowDebug:          showDebug,
		sys:                 sys,
		maxCacherRecordSize: maxCacherRecordSize, // MB
	}, nil
}

func (ts *Tasker) taskFile(uid, suffix string) string {
	return filepath.Join(ts.taskDir, uid+suffix)
}

// TryWriteFile creates a new owner-only file. It fails if the path already exists, including as a symlink,
// because task files may carry registry credentials.
func TryWriteFile(path string, data []byte) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	_, err = f.Write(data)
	return err
}

func (ts *Tasker) writeInputFile(data []byte, cacert []byte) (uid string, err error) {
	uid = uuid.New().String()
	input := ts.taskFile(uid, reqSuffix)
	cacertInput := ts.taskFile(uid, cacertSuffix)

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

	if caps := getParsingCaps(); caps != nil && caps.GetJarAutoModuleName() {
		args = append(args, "--enable-jar-auto-module-name")
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

		args = append(args, "-i", ts.taskFile(uid, reqSuffix))
		args = append(args, "-o", ts.taskFile(uid, resSuffix))
		if cacerts != "" {
			args = append(args, "--cacerts", ts.taskFile(uid, cacertSuffix))
		}
		return uid, args, nil
	}

	return uid, args, errors.New("failed to allocate")
}

// ///
func (ts *Tasker) getResultFile(uid string) (*share.ScanResult, error) {
	jsonFile, err := os.Open(ts.taskFile(uid, resSuffix))
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
	defer os.Remove(ts.taskFile(uid, reqSuffix))
	defer os.Remove(ts.taskFile(uid, resSuffix))
	defer os.Remove(ts.taskFile(uid, cacertSuffix))

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

	if err := os.RemoveAll(ts.taskDir); err != nil {
		log.WithFields(log.Fields{"error": err, "dir": ts.taskDir}).Error("Failed to remove task file directory")
	}
}
