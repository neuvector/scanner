package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/healthz"
	"github.com/neuvector/neuvector/share/httpclient"
	"github.com/neuvector/neuvector/share/migration"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
	"github.com/neuvector/scanner/common"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: scan [OPTIONS]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

type globalConfig struct {
	tlsVerification bool
	caCerts         string
}

var (
	globalCfgLock sync.RWMutex
	globalCfg     globalConfig
)

func getGlobalConfig() globalConfig {
	globalCfgLock.RLock()
	defer globalCfgLock.RUnlock()
	return globalCfg
}

func setGlobalConfig(input globalConfig) {
	globalCfgLock.Lock()
	defer globalCfgLock.Unlock()
	globalCfg = input
}

const taskerPath = "/usr/local/bin/scannerTask"
const registerWaitTime = time.Duration(time.Second * 10)
const dockerSocket = "unix:///var/run/docker.sock"
const defaultDockerhubReg = "https://registry.hub.docker.com"

type outputCVE struct {
	Version    string                 `json:"Version"`
	CreateTime string                 `json:"CreateTime"`
	CVEs       []*common.OutputCVEVul `json:"Vulnerabilities"`
}

var dockerhubRegs utils.Set = utils.NewSet("registry.hub.docker.com", "index.docker.io", "registry-1.docker.io", "docker.io")
var cveDB *common.CveDB
var ctrlCaps share.ControllerCaps
var scanTasker *Tasker
var selfID string
var isGetCapsActivate bool

func dbRead(path string, maxRetry int, output string) map[string]*share.ScanVulnerability {
	dbFile := path + share.DefaultCVEDBName
	encryptKey := common.GetCVEDBEncryptKey()

	var retry int
	var dbReady bool
	var dbData map[string]*share.ScanVulnerability
	var outCVEs []*common.OutputCVEVul

	for {
		if _, err := os.Stat(dbFile); err != nil {
			log.WithFields(log.Fields{"file": dbFile}).Error("cannot find scanner db")
		} else {
			if verNew, createTime, err := common.LoadCveDb(path, cveDB.ExpandPath, encryptKey); err == nil {
				cveDB.CveDBVersion = verNew
				cveDB.CveDBCreateTime = createTime
				if dbData, outCVEs, err = common.ReadCveDbMeta(cveDB.ExpandPath, output != ""); err != nil {
					log.WithFields(log.Fields{"error": err}).Error("Failed to load scanner db")
				} else {
					dbReady = true

					if output != "" {
						out := outputCVE{
							Version:    verNew,
							CreateTime: createTime,
							CVEs:       outCVEs,
						}
						file, _ := json.MarshalIndent(out, "", "    ")
						if err := os.WriteFile(output, file, 0644); err != nil {
							log.WithFields(log.Fields{"error": err}).Error()
						}
					}
				}
			}
		}

		if !dbReady {
			retry++
			if maxRetry != 0 && retry == maxRetry {
				return nil
			}

			time.Sleep(time.Second * 4)
		} else {
			return dbData
		}
	}
}

func connectController(path, advIP, joinIP, selfID string, advPort uint32, joinPort uint16, doneCh chan bool) {
	cb := &clientCallback{
		shutCh:         make(chan interface{}, 1),
		ignoreShutdown: true,
	}

	var healthCheckCh chan struct{}
	var dbData map[string]*share.ScanVulnerability
	for {
		// forever retry
		dbData = dbRead(path, 0, "")
		scanner := share.ScannerRegisterData{
			CVEDBVersion:    cveDB.CveDBVersion,
			CVEDBCreateTime: cveDB.CveDBCreateTime,
			CVEDB:           dbData,
			RPCServer:       advIP,
			RPCServerPort:   advPort,
			ID:              selfID,
		}

		for scannerRegister(joinIP, joinPort, &scanner, cb) != nil {
			time.Sleep(registerWaitTime)
		}

		// tagging it as a released-memory
		scanner.CVEDB = nil
		clear(dbData) // zero size

		if healthCheckCh != nil {
			close(healthCheckCh)
		}

		healthCheckCh = make(chan struct{})
		// Check if the gRPC HealthCheck API is active (indicated by isGetCapsActivate being true).
		// If active, initiate periodic health checks by launching a goroutine to monitor the health status of the specified service.
		if isGetCapsActivate {
			go periodCheckHealth(joinIP, joinPort, &scanner, cb, healthCheckCh, doneCh)
		}

		// start responding shutdown notice
		cb.ignoreShutdown = false
		<-cb.shutCh
		cb.ignoreShutdown = true
	}
}

// TODO: sidecar implementation might have two app pods
func adjustContainerPod(selfID string, containers []*container.ContainerMeta) string {
	for _, c := range containers {
		if v, ok := c.Labels["io.kubernetes.sandbox.id"]; ok {
			if v == selfID {
				log.WithFields(log.Fields{"Pod": selfID, "ID": c.ID}).Debug("Update")
				return c.ID
			}
		}

		if c.Sandbox != c.ID { // a child
			if c.Sandbox != "" && c.Sandbox == selfID {
				log.WithFields(log.Fields{"Pod": selfID, "ID": c.ID}).Debug("Updated")
				return c.ID
			}
		}
	}
	return selfID
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&utils.LogFormatter{Module: "SCN"})

	dbPath := flag.String("d", "./dbgen/", "cve database file directory")
	join := flag.String("j", "", "Controller join address")
	joinPort := flag.Uint("join_port", 0, "Controller join port")
	adv := flag.String("a", "", "Advertise address")
	advPort := flag.Uint("adv_port", 0, "Advertise port")
	rtSock := flag.String("u", dockerSocket, "Container socket URL")                                                       // used for scan local image
	license := flag.String("license", "", "Scanner license")                                                               // it means on-demand stand-alone scanner
	image := flag.String("image", "", "Scan image (Docker/OCI ref: [registry/][namespace/]name[:tag] or name@sha256:...)") // overwrite registry, repository and tag
	pid := flag.Int("pid", 0, "Scan host or container")
	registry := flag.String("registry", "", "Scan image registry")
	repository := flag.String("repository", "", "Scan image repository")
	tag := flag.String("tag", "latest", "Scan image tag (or digest like sha256:...)")
	regUser := flag.String("registry_username", "", "Registry username")
	regPass := flag.String("registry_password", "", "Registry password")
	scanLayers := flag.Bool("scan_layers", false, "Scan image layers")
	baseImage := flag.String("base_image", "", "Base image")
	ctrlUser := flag.String("ctrl_username", "", "Controller REST API username")
	ctrlPass := flag.String("ctrl_password", "", "Controller REST API password")
	noWait := flag.Bool("no_wait", false, "No initial wait")
	noTask := flag.Bool("no_task", false, "Not using scanner task")
	verbose := flag.Bool("x", false, "more debug")
	tlsVerification := flag.Bool("enable-tls-verification", false, "enable tls verification")
	proxyUrl := flag.String("proxy_url", "", "A URL to the proxy to use during on demand scanning")

	output := flag.String("o", "", "Output CVEDB in json format, specify the output file")
	show := flag.String("show", "", "Standalone Mode: Stdout print options, cmd,module")
	getVer := flag.Bool("v", false, "show cve database version")
	debug := flag.String("debug", "", "debug filters. (v=CVE-2024-0001,f=jar)")
	maxCacherRecordSize := flag.Int64("maxrec", 0, "maximum record cacher size in MB") // common.MaxRecordCacherSizeMB
	capCritical := flag.Bool("cap_critical", false, "support critical level severity") // for backwards compatibility of scan plugins, will remove after a few releases.

	flag.Usage = usage
	flag.Parse()

	common.InitDebugFilters(*debug)

	// show cve database version
	if *getVer {
		if v, _, err := common.GetDbVersion(*dbPath); err == nil {
			fmt.Printf("CVE database version: %.3f\n", v)
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(-2)
		}
		return
	}

	// acquire tool
	sys := system.NewSystemTools()
	cveDB = common.NewCveDB()

	// output cvedb in json format
	if *output != "" {
		dbRead(*dbPath, 3, *output)
		return
	}

	onDemand := false
	showTaskDebug := false
	if *verbose {
		log.SetLevel(log.DebugLevel)
		showTaskDebug = true
	}

	var grpcServer *cluster.GRPCServer
	var ctx context.Context
	var internalCertControllerCancel context.CancelFunc
	var err error

	if os.Getenv("AUTO_INTERNAL_CERT") != "" {

		log.Info("start initializing k8s internal secret controller and wait for internal secret creation if it's not created")

		go func() {
			if err := healthz.StartHealthzServer(); err != nil {
				log.WithError(err).Warn("failed to start healthz server")
			}
		}()

		ctx, internalCertControllerCancel = context.WithCancel(context.Background())
		defer internalCertControllerCancel()
		// Initialize secrets.  Most of services are not running at this moment, so skip their reload functions.
		capable, err := migration.InitializeInternalSecretController(ctx, []func([]byte, []byte, []byte) error{
			// Reload grpc server
			func(cacert []byte, cert []byte, key []byte) error {
				log.Info("Reloading gRPC servers/clients")
				if err := cluster.ReloadInternalCert(); err != nil {
					return fmt.Errorf("failed to reload gRPC's certificate: %w", err)
				}
				return nil
			},
		})
		if err != nil {
			log.WithError(err).Error("failed to initialize internal secret controller")
			os.Exit(-2)
		}

		if capable {
			log.Info("internal certificate is initialized")
		} else {
			if os.Getenv("NO_FALLBACK") == "" {
				log.Warn("required permission is missing...fallback to the built-in certificate if it exists")
			} else {
				log.Error("required permission is missing...ending now")
				os.Exit(-2)
			}
		}
	}

	if *license == "" {
		// We don't need the certificate for standalone scanner.
		// For scan result, it's via RESTful.
		err = cluster.ReloadInternalCert()
		if err != nil {
			log.WithError(err).Fatal("failed to reload internal certificate")
		}
	}

	// If license parameter is given, this is an on-demand scanner, no register to the controller,
	// but if join address is given, the scan result are sent to the controller.
	if *license != "" {
		if (*repository == "" || *tag == "") && *image == "" && *pid == 0 {
			log.Error("Missing the repository name and tag of the image to be scanned")
			os.Exit(-2)
		}

		setGlobalConfig(globalConfig{
			tlsVerification: *tlsVerification,
			caCerts:         "", // In stand alone scanner, we use system default
		})
		// Default TLS config
		err := httpclient.SetDefaultTLSClientConfig(&httpclient.TLSClientSettings{
			TLSconfig: &tls.Config{
				InsecureSkipVerify: !*tlsVerification, // #nosec G402
			},
		}, "", "", "")
		if err != nil {
			log.WithError(err).Warn("failed to set default TLS config")
		}

		onDemand = true
	}

	// recovered, clean up all possible previous image folders
	if *maxCacherRecordSize <= 0 {
		os.RemoveAll(common.ImageWorkingPath)
	}

	if err := os.MkdirAll(common.ImageWorkingPath, 0755); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
	}

	if sys.IsRunningInContainer() {
		selfID, _, err = sys.GetSelfContainerID() // it is a POD ID in the k8s cgroup v2; otherwise, a real container ID
		if selfID == "" {
			log.WithFields(log.Fields{"error": err}).Error("Unsupported system. Exit!")
			os.Exit(-2)
		}
	} else {
		log.Debug("Not running in container.")
	}

	if platform, _, _, _, containers, err := global.SetGlobalObjects(*rtSock, nil); err == nil {
		if platform == share.PlatformKubernetes {
			selfID = adjustContainerPod(selfID, containers)
		}
	}

	if !*noTask {
		log.WithFields(log.Fields{"record": *maxCacherRecordSize}).Info("Scan cacher maximum sizes")
		scanTasker = newTasker(taskerPath, *rtSock, showTaskDebug, sys, *maxCacherRecordSize)
		if scanTasker != nil {
			log.Debug("Use scannerTask")
			defer scanTasker.Close()
		}
	}

	done := make(chan bool, 1)
	c_sig := make(chan os.Signal, 1)
	signal.Notify(c_sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c_sig
		done <- true
	}()

	if onDemand {
		// DB read error printed inside dbRead()
		dbData := dbRead(*dbPath, 3, "")
		if dbData == nil {
			return
		}

		if *pid != 0 {
			scanRunning(*pid, dbData, *show, *capCritical)
			return
		}

		var req *share.ScanImageRequest
		if *image != "" {
			// This normally is the case when scanner runs by the command line
			reg, repo, tag := parseImageValue(*image)
			if repo == "" || tag == "" {
				log.Error("Invalid image value.")
				return
			}

			req = &share.ScanImageRequest{
				Registry:    reg,
				Repository:  repo,
				Tag:         tag,
				Username:    *regUser,
				Password:    *regPass,
				ScanLayers:  *scanLayers,
				ScanSecrets: false,
				BaseImage:   *baseImage,
			}
		} else {
			req = &share.ScanImageRequest{
				Registry:    *registry,
				Repository:  *repository,
				Tag:         *tag,
				Username:    *regUser,
				Password:    *regPass,
				ScanLayers:  *scanLayers,
				ScanSecrets: true,
				BaseImage:   *baseImage,
			}
		}

		req.Proxy = *proxyUrl

		result := scanOnDemand(req, dbData, *show, *capCritical)

		// submit scan result if join address is given
		if result != nil && result.Error == share.ScanErrorCode_ScanErrNone &&
			*join != "" && *ctrlUser != "" && *ctrlPass != "" {
			if *adv == "" {
				_, addr, err := cluster.ResolveJoinAndBindAddr(*join, sys)
				if err != nil {
					log.WithFields(log.Fields{"error": err}).Error()
					os.Exit(-2)
				}

				adv = &addr
			}
			if *joinPort == 0 {
				port := (uint)(api.DefaultControllerRESTAPIPort)
				joinPort = &port
			}

			err := scanSubmitResult(*join, (uint16)(*joinPort), *adv, *ctrlUser, *ctrlPass, result)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to sumit scan result")
			} else {
				log.Info("Scan result submitted.")
			}
		}

		return
	}

	// Block until server is up.
	grpcServer = startGRPCServer()

	if !(*noWait) {
		// Intentionally introduce some delay so scanner IP can be populated to all enforcers
		log.Info("Wait 15s ...")
		time.Sleep(time.Second * 15)
	}

	if *adv == "" {
		_, addr, err := cluster.ResolveJoinAndBindAddr(*join, sys)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			os.Exit(-2)
		}

		adv = &addr
	}
	if *advPort == 0 {
		port := (uint)(cluster.DefaultScannerGRPCPort)
		advPort = &port
	}
	if *joinPort == 0 {
		port := (uint)(cluster.DefaultControllerGRPCPort)
		joinPort = &port
	}

	if selfID == "" {
		// if not running in container
		selfID = *adv
	}

	// Use the original address, which is the service name, so when controller changes,
	// new IP can be resolved
	go connectController(*dbPath, *adv, *join, selfID, (uint32)(*advPort), (uint16)(*joinPort), done)
	<-done

	log.Info("Exiting ...")
	if err := scannerDeregister(*join, (uint16)(*joinPort), selfID); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
	}
	grpcServer.Stop()
}
