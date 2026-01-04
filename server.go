package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/httpclient"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/scanner/common"
	"github.com/neuvector/scanner/cvetools"
)

const (
	period   = 20 // Minutes to check if the scanner is in the controller and controller is alive
	retryMax = 3  // Number of retry
)

func createEnforcerScanServiceWrapper(conn *grpc.ClientConn) cluster.Service {
	return share.NewEnforcerScanServiceClient(conn)
}

func findEnforcerServiceClient(ep string) (share.EnforcerScanServiceClient, error) {
	if cluster.GetGRPCClientEndpoint(ep) == "" {
		if err := cluster.CreateGRPCClient(ep, ep, true, createEnforcerScanServiceWrapper); err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			return nil, err
		}
	}
	c, err := cluster.GetGRPCClient(ep, nil, nil)
	if err == nil {
		return c.(share.EnforcerScanServiceClient), nil
	} else {
		log.WithFields(log.Fields{"err": err}).Error("Failed to connect to grpc server")
		return nil, err
	}
}

type rpcService struct {
}

func (rs *rpcService) Ping(ctx context.Context, v *share.RPCVoid) (*share.RPCVoid, error) {
	return &share.RPCVoid{}, nil
}

func (rs *rpcService) ScanRunning(ctx context.Context, req *share.ScanRunningRequest) (sr *share.ScanResult, err error) {
	var result *share.ScanResult

	log.WithFields(log.Fields{"id": req.ID, "type": req.Type, "agent": req.AgentRPCEndPoint}).Debug("")

	client, err := findEnforcerServiceClient(req.AgentRPCEndPoint)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to connect to agent")

		result = &share.ScanResult{Version: cveDB.CveDBVersion, CVEDBCreateTime: cveDB.CveDBCreateTime, Error: share.ScanErrorCode_ScanErrNetwork}
		return result, nil
	}

	data, err := client.ScanGetFiles(ctx, req)
	if ctx.Err() != nil { // context.Canceled: remote cancelled
		// no timeout is set for (enforcer <-> scanner)
		// however, 60 sec timeout is set for (controller <-> scanner), and 5 restries from controller
		// wait for next pulling from ctl and it should return the cache results from enforcer immediately
		log.WithFields(log.Fields{"id": req.ID}).Debug("session expired")
		return &share.ScanResult{Error: share.ScanErrorCode_ScanErrCanceled}, status.Error(codes.Aborted, fmt.Sprintf("aborted: %s, %s", ctx.Err(), req.ID)) // aborted by controller
	}

	if data != nil && err == nil {
		// actual result from enforcer with only 3 conditions
		switch data.Error {
		case share.ScanErrorCode_ScanErrContainerExit: // no longer live
			result = &share.ScanResult{Version: cveDB.CveDBVersion, CVEDBCreateTime: cveDB.CveDBCreateTime, Error: data.Error}
			return result, nil
		case share.ScanErrorCode_ScanErrInProgress: // in progress
			return &share.ScanResult{Error: data.Error}, status.Error(codes.Unavailable, fmt.Sprintf("In progress: %s", req.ID)) // keep alive
		case share.ScanErrorCode_ScanErrNone: // a good result within time, proceed to scan procedure
		}
	} else if data == nil {
		// rpc request not made
		log.WithFields(log.Fields{"error": err}).Error("Fail to make rpc call")
		result = &share.ScanResult{Version: cveDB.CveDBVersion, CVEDBCreateTime: cveDB.CveDBCreateTime, Error: share.ScanErrorCode_ScanErrNetwork}
		return result, nil
	} else if err != nil || data.Error != share.ScanErrorCode_ScanErrNone {
		log.WithFields(log.Fields{"error": err}).Error("Fail to read files")
		result = &share.ScanResult{Version: cveDB.CveDBVersion, CVEDBCreateTime: cveDB.CveDBCreateTime, Error: data.Error}
		return result, nil
	}

	log.WithFields(log.Fields{"id": req.ID, "type": req.Type}).Debug("File read done")
	if scanTasker != nil {
		sr, err = scanTasker.Run(ctx, *data)
	} else {
		cveTools := cvetools.NewScanTools("", system.NewSystemTools(), nil, "")
		sr, err = cveTools.ScanImageData(data)
	}

	if err == nil && !ctrlCaps.CriticalVul {
		downgradeCriticalSeverityInResult(sr)
	}

	return sr, err
}

func (rs *rpcService) ScanImageData(ctx context.Context, data *share.ScanData) (sr *share.ScanResult, err error) {
	log.Debug("")

	if scanTasker != nil {
		sr, err = scanTasker.Run(ctx, *data)
	} else {
		cveTools := cvetools.NewScanTools("", system.NewSystemTools(), nil, "")
		sr, err = cveTools.ScanImageData(data)
	}

	if err == nil && !ctrlCaps.CriticalVul {
		downgradeCriticalSeverityInResult(sr)
	}

	return sr, err
}

func (rs *rpcService) ScanImage(ctx context.Context, req *share.ScanImageRequest) (sr *share.ScanResult, err error) {
	ref := req.Tag
	sep := ":"
	if strings.HasPrefix(ref, "sha256:") {
		sep = "@"
	}

	log.WithFields(log.Fields{
		"Registry": req.Registry, "image": fmt.Sprintf("%s%s%s", req.Repository, sep, ref),
	}).Debug()

	if scanTasker != nil {
		sr, err = scanTasker.Run(ctx, *req)
	} else {
		cveTools := cvetools.NewScanTools("", system.NewSystemTools(), nil, "")
		sr, err = cveTools.ScanImage(ctx, req, "")
	}

	if err == nil && !ctrlCaps.CriticalVul {
		downgradeCriticalSeverityInResult(sr)
	}

	return sr, err
}

func (rs *rpcService) ScanAppPackage(ctx context.Context, req *share.ScanAppRequest) (sr *share.ScanResult, err error) {
	log.WithFields(log.Fields{"Packages": req.Packages}).Debug("")
	if scanTasker != nil {
		sr, err = scanTasker.Run(ctx, *req)
	} else {
		cveTools := cvetools.NewScanTools("", system.NewSystemTools(), nil, "")
		sr, err = cveTools.ScanAppPackage(req, "")
	}

	if err == nil && !ctrlCaps.CriticalVul {
		downgradeCriticalSeverityInResult(sr)
	}

	return sr, err
}

func (rs *rpcService) ScanAwsLambda(ctx context.Context, req *share.ScanAwsLambdaRequest) (sr *share.ScanResult, err error) {
	log.WithFields(log.Fields{"LambdaFunc": req.FuncName}).Debug("")
	if scanTasker != nil {
		sr, err = scanTasker.Run(ctx, *req)
	} else {
		cveTools := cvetools.NewScanTools("", system.NewSystemTools(), nil, "")
		sr, err = cveTools.ScanAwsLambda(req, "")
	}

	if err == nil && !ctrlCaps.CriticalVul {
		downgradeCriticalSeverityInResult(sr)
	}

	return sr, err
}

func (rs *rpcService) ScanCacheGetStat(ctx context.Context, v *share.RPCVoid) (*share.ScanCacheStatRes, error) {
	log.Debug()
	res := &share.ScanCacheStatRes{}
	if layerCacher, _ := cvetools.InitImageLayerCacher(common.ImageLayerCacherFile, common.ImageLayerLockFile, common.ImageLayersCachePath, 1); layerCacher != nil {
		defer layerCacher.LeaveLayerCacher()
		res = layerCacher.GetStat()
	}
	return res, nil
}

func (rs *rpcService) ScanCacheGetData(ctx context.Context, v *share.RPCVoid) (*share.ScanCacheDataRes, error) {
	log.Debug()
	res := share.ScanCacheDataRes{DataZb: make([]byte, 0)}
	if layerCacher, _ := cvetools.InitImageLayerCacher(common.ImageLayerCacherFile, common.ImageLayerLockFile, common.ImageLayersCachePath, 1); layerCacher != nil {
		defer layerCacher.LeaveLayerCacher()
		res.DataZb = layerCacher.GetIndexFile()
	}
	return &res, nil
}

func (rs *rpcService) SetScannerSettings(ctx context.Context, req *share.ScannerSettings) (*share.RPCVoid, error) {
	log.Debug()
	if err := ScannerSettingUpdate(req); err != nil {
		log.WithError(err).Warn("failed to update scanner settings")
	}

	return &share.RPCVoid{}, nil
}

func startGRPCServer() *cluster.GRPCServer {
	var grpc *cluster.GRPCServer
	var err error

	port := cluster.DefaultScannerGRPCPort

	log.WithFields(log.Fields{"port": port}).Info("")
	for {
		grpc, err = cluster.NewGRPCServerTCP(fmt.Sprintf(":%d", port))
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Fail to create GRPC server")
			time.Sleep(time.Second * 5)
		} else {
			break
		}
	}

	svc := new(rpcService)
	share.RegisterScannerServiceServer(grpc.GetServer(), svc)
	go grpc.Start()

	log.Info("GRPC server started")
	return grpc
}

const controller string = "controller"

func createControllerScanServiceWrapper(conn *grpc.ClientConn) cluster.Service {
	return share.NewControllerScanServiceClient(conn)
}

func getControllerServiceClient(joinIP string, joinPort uint16, cb cluster.GRPCCallback) (share.ControllerScanServiceClient, error) {
	if cluster.GetGRPCClientEndpoint(controller) == "" {
		ep := fmt.Sprintf("%s:%v", joinIP, joinPort)
		if err := cluster.CreateGRPCClient(controller, ep, true, createControllerScanServiceWrapper); err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			return nil, err
		}
	}
	c, err := cluster.GetGRPCClient(controller, nil, cb)
	if err == nil {
		return c.(share.ControllerScanServiceClient), nil
	} else {
		log.WithFields(log.Fields{"err": err}).Error("Failed to connect to grpc server")
		return nil, err
	}
}

type clientCallback struct {
	shutCh         chan interface{}
	ignoreShutdown bool
}

func (cb *clientCallback) Shutdown() {
	log.Debug()
	if !cb.ignoreShutdown {
		cb.shutCh <- nil
	}
}

const cvedbChunkMax = 32 * 1024

func scannerRegisterStream(ctx context.Context, client share.ControllerScanServiceClient, data *share.ScannerRegisterData) error {
	stream, err := client.ScannerRegisterStream(ctx)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to get stream")
		return errors.New("Failed to  to controller")
	}

	// send a block without data to test if stream API is supported
	cvedb := data.CVEDB
	defer func() {
		data.CVEDB = cvedb
	}()

	data.CVEDB = make(map[string]*share.ScanVulnerability)
	err = stream.Send(data)
	if err == io.EOF {
		log.Info("Stream register API is not supported")
		return errors.New("Stream register API is not supported")
	} else if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to send")
		return err
	}

	// clone the cvedb
	clone := make(map[string]*share.ScanVulnerability, len(cvedb))
	for k, v := range cvedb {
		clone[k] = v
	}

	for {
		var count int

		if len(clone) > cvedbChunkMax {
			count = cvedbChunkMax
		} else {
			count = len(clone)
		}

		send := make(map[string]*share.ScanVulnerability, count)

		for k, v := range clone {
			send[k] = v
			delete(clone, k)

			count--
			if count == 0 {
				break
			}
		}

		log.WithFields(log.Fields{"entries": len(send)}).Info("Stream send")

		data.CVEDB = send
		err = stream.Send(data)
		if err == io.EOF {
			log.Info("Stream register API is not supported")
			return errors.New("Stream register API is not supported")
		} else if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to send")
			return err
		}

		if len(clone) == 0 {
			break
		}
	}

	log.Info("Stream send done")
	if _, err = stream.CloseAndRecv(); err != nil && err != io.EOF {
		log.WithFields(log.Fields{"error": err}).Error("Failed to close")
		return err
	}

	return nil
}

func downgradeCriticalSeverityInResult(sr *share.ScanResult) {
	for _, v := range sr.Vuls {
		if v.Severity == string(common.Critical) {
			v.Severity = string(common.High)
		}
	}
	for _, l := range sr.Layers {
		for _, v := range l.Vuls {
			if v.Severity == string(common.Critical) {
				v.Severity = string(common.High)
			}
		}
	}
}

func downgradeCriticalSeverityInCVEDB(data *share.ScannerRegisterData) {
	for _, v := range data.CVEDB {
		if v.Severity == string(common.Critical) {
			v.Severity = string(common.High)
		}
	}
}

func ScannerSettingUpdate(settings *share.ScannerSettings) error {

	var pool *x509.CertPool

	if settings.CACerts != "" {
		pool = x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(settings.CACerts))
	}

	setGlobalConfig(globalConfig{
		tlsVerification: settings.EnableTLSVerification,
		caCerts:         settings.CACerts,
	})

	err := httpclient.SetDefaultTLSClientConfig(&httpclient.TLSClientSettings{
		TLSconfig: &tls.Config{
			InsecureSkipVerify: !settings.EnableTLSVerification, // #nosec G402
			RootCAs:            pool,
		},
	}, settings.HttpProxy, settings.HttpsProxy, settings.NoProxy)
	if err != nil {
		log.WithError(err).Warn("failed to set default TLS config")
	}

	log.WithFields(log.Fields{
		"tls_verification": settings.EnableTLSVerification,
		"ca_len":           len(settings.CACerts),
	}).Info("scanner setting is updated")

	return nil
}

func scannerRegister(joinIP string, joinPort uint16, data *share.ScannerRegisterData, cb cluster.GRPCCallback) error {
	log.WithFields(log.Fields{
		"join": fmt.Sprintf("%s:%d", joinIP, joinPort), "version": data.CVEDBVersion, "entries": len(data.CVEDB),
	}).Debug()

	client, err := getControllerServiceClient(joinIP, joinPort, cb)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to find ctrl client")
		return errors.New("Failed to connect to controller")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*180)
	defer cancel()

	caps, err := client.GetCaps(ctx, &share.RPCVoid{})
	if err != nil {
		isGetCapsActivate = false
		downgradeCriticalSeverityInCVEDB(data)
	} else {
		isGetCapsActivate = true
		log.WithField("cap", caps).Info("controller capabilities")
		ctrlCaps = *caps
		if !caps.CriticalVul {
			downgradeCriticalSeverityInCVEDB(data)
		}
	}

	haveControllerSetting := false
	if caps != nil && caps.ScannerSettings {
		settings, err := client.GetScannerSettings(ctx, &share.RPCVoid{})
		if err != nil {
			log.WithError(err).Warn("failed to get scanner settings from controller")
		} else {
			log.WithField("config", settings).Info("scanner settings")
			if err := ScannerSettingUpdate(settings); err != nil {
				log.WithError(err).Warn("failed to update scanner settings")
			} else {
				haveControllerSetting = true
			}
		}
	}

	if !haveControllerSetting {
		// Provide a default TLS config and proxy settings for backward compatibility.
		setGlobalConfig(globalConfig{
			tlsVerification: false,
			caCerts:         "",
		})

		err := httpclient.SetDefaultTLSClientConfig(&httpclient.TLSClientSettings{
			TLSconfig: &tls.Config{
				InsecureSkipVerify: true, // #nosec G402
			},
		}, "", "", "")
		if err != nil {
			log.WithError(err).Warn("failed to set default TLS config")
		}
	}

	if err = scannerRegisterStream(ctx, client, data); err == nil {
		return nil
	}

	_, err = client.ScannerRegister(ctx, data)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to register")
		return errors.New("Failed to send register request")
	}
	return nil
}

func scannerDeregister(joinIP string, joinPort uint16, id string) error {
	log.Debug()

	client, err := getControllerServiceClient(joinIP, joinPort, nil)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to find ctrl client")
		return errors.New("Failed to connect to controller")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	_, err = client.ScannerDeregister(ctx, &share.ScannerDeregisterData{ID: id})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to deregister")
		return errors.New("Failed to send deregister request")
	}
	return nil
}

func getScannerAvailable(joinIP string, joinPort uint16, data *share.ScannerRegisterData, cb cluster.GRPCCallback) (*share.ScannerAvailable, error) {
	client, err := getControllerServiceClient(joinIP, joinPort, cb)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to find ctrl client")
		return &share.ScannerAvailable{Visible: false}, errors.New("Failed to connect to controller")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	scannerAvailable, errHealthCheck := client.HealthCheck(ctx, data)

	return scannerAvailable, errHealthCheck
}

// To ensure the controller's availability, periodCheckHealth use HealthCheck to periodically check if the controller is alive.
// Additionally, if the controller is deleted or not responsive, the scanner will re-register.
func periodCheckHealth(joinIP string, joinPort uint16, data *share.ScannerRegisterData, cb *clientCallback, healthCheckCh chan struct{}, done chan bool) {
	ticker := time.NewTicker(time.Duration(period) * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			retryCnt := 0
			for retryCnt < retryMax {
				scannerAvailable, errHealthCheck := getScannerAvailable(joinIP, joinPort, data, cb)
				if errHealthCheck == nil {
					if scannerAvailable.Visible {
						break
					}
				} else {
					log.WithFields(log.Fields{"joinIP": joinIP, "joinPort": joinPort, "errHealthCheck": errHealthCheck}).Debug("periodCheckHealth has error")
				}
				retryCnt++
				time.Sleep(time.Duration(period) * time.Second) // Add a delay before retrying
			}
			if retryCnt >= retryMax {
				log.WithFields(log.Fields{"joinIP": joinIP, "joinPort": joinPort, "retryMax": retryMax}).Error("The scanner is not in the controller, restart the scanner pod.")
				done <- true
			}
		case <-healthCheckCh:
			return
		}
	}
}
