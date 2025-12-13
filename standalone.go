package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/scan"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
	"github.com/neuvector/scanner/cvetools"
)

// The user must mount volume to /var/neuvector and the result will be written to the mounted folder
const scanOutputDir = "/var/neuvector"
const scanOutputFile = "scan_result.json"

const apiCallTimeout = time.Duration(30 * time.Second)

type scanOnDemandReportData struct {
	ErrMsg string                  `json:"error_message"`
	Report *api.RESTScanRepoReport `json:"report"`
}

func parseImageValue(value string) (string, string, string) {
	var parts []string
	var proto, registry, repository, tagOrDigest string

	if i := strings.Index(value, "://"); i != -1 {
		// The input URL includes a protocol (e.g., "http://", "https://", "docker://").
		// We remove it to parse the rest of the URL.
		proto = value[:i+3]
		parts = strings.Split(value[i+3:], "/")
	} else {
		// The input URL does not include a protocol.
		parts = strings.SplitN(value, "/", 2)
	}

	if len(parts) > 1 {
		if strings.ContainsAny(parts[0], ":.") {
			// Image has a registry
			registry = parts[0]
			parts = parts[1:]
		}
	} else {
		dot := strings.Index(parts[0], ".")
		colon := strings.Index(parts[0], ":")
		if dot != -1 && dot < colon {
			// example.com:5000, this is a wrong case anyway
			registry = parts[0]
			parts = parts[1:]
		}
	}

	if len(parts) > 0 {
		last := parts[len(parts)-1]
		// Check for digest first (name@sha256:...)
		if i := strings.Index(last, "@"); i != -1 {
			parts[len(parts)-1] = last[:i]
			tagOrDigest = last[i+1:]
		} else if i := strings.Index(last, ":"); i != -1 {
			// Tag (name:tag)
			parts[len(parts)-1] = last[:i]
			tagOrDigest = last[i+1:]
		} else {
			// No tag or digest
			tagOrDigest = "latest"
		}
		repository = strings.Join(parts, "/")
	}

	if registry != "" {
		// We don't prefix 'library' if registry is empty, as local image doesn't need it
		if dockerhubRegs.Contains(registry) && !strings.Contains(repository, "/") {
			repository = fmt.Sprintf("library/%s", repository)
		}

		if proto != "" {
			registry = fmt.Sprintf("%s%s", proto, registry)
		} else {
			registry = fmt.Sprintf("https://%s", registry)
		}
	}

	return registry, repository, tagOrDigest
}

func writeResultToFile(req *share.ScanImageRequest, result *share.ScanResult, err error) {
	var rptData scanOnDemandReportData

	switch {
	case result == nil:
		if err != nil {
			rptData.ErrMsg = err.Error()
		} else {
			rptData.ErrMsg = "scan failed: empty result"
		}
	case result.Error != share.ScanErrorCode_ScanErrNone:
		rptData.ErrMsg = scanUtils.ScanErrorToStr(result.Error)
	default:
		rpt := scanUtils.ScanRepoResult2REST(result, nil)
		rptData.Report = rpt
	}

	data, marshalErr := json.MarshalIndent(rptData, "", "    ")
	if marshalErr != nil {
		log.WithFields(log.Fields{
			"registry": req.Registry, "repo": req.Repository, "tag": req.Tag, "error": marshalErr.Error(),
		}).Error("Failed to marshal scan result")
		return
	}

	if _, statErr := os.Stat(scanOutputDir); os.IsNotExist(statErr) {
		if mkErr := os.MkdirAll(scanOutputDir, 0o775); mkErr != nil {
			log.WithFields(log.Fields{
				"registry": req.Registry, "repo": req.Repository, "tag": req.Tag, "error": mkErr.Error(), "output": scanOutputDir,
			}).Error("Failed to create output directory")
			return
		}
	}

	output := fmt.Sprintf("%s/%s", scanOutputDir, scanOutputFile)
	if writeErr := os.WriteFile(output, data, 0o644); writeErr != nil {
		log.WithFields(log.Fields{
			"registry": req.Registry, "repo": req.Repository, "tag": req.Tag, "error": writeErr.Error(), "output": output,
		}).Error("Failed to write scan result")
	} else {
		log.WithFields(log.Fields{
			"registry": req.Registry, "repo": req.Repository, "tag": req.Tag, "output": output,
		}).Debug("Write scan result to file")
	}
}

func writeResultToStdout(req *share.ScanImageRequest, result *share.ScanResult, showOptions string) {
	if result == nil || result.Error != share.ScanErrorCode_ScanErrNone {
		return
	}

	rpt := scanUtils.ScanRepoResult2REST(result, nil)

	// Only print Image line if we have a real image request
	if req != nil {
		ref := req.Tag
		sep := ":"
		if strings.HasPrefix(ref, "sha256:") {
			sep = "@"
		}

		if req.Registry != "" {
			fmt.Printf("Image: %s/%s%s%s\n", req.Registry, req.Repository, sep, ref)
		} else {
			fmt.Printf("Image: %s%s%s\n", req.Repository, sep, ref)
		}
	}

	var high, med, low, unk int
	for _, v := range rpt.Vuls {
		switch v.Severity {
		case share.VulnSeverityHigh:
			high++
		case share.VulnSeverityMedium:
			med++
		case share.VulnSeverityLow:
			low++
		default:
			unk++
		}
	}

	fmt.Printf("Base OS: %s\n", rpt.BaseOS)
	fmt.Printf("Created at: %s\n", rpt.CreatedAt)

	// Print vulnerability
	fmt.Printf("\nVulnerabilities: %d, HIGH: %d, MEDIUM: %d, LOW: %d, UNKNOWN: %d\n", len(rpt.Vuls), high, med, low, unk)

	files := make([]string, 0)
	fileMap := make(map[string][]*api.RESTVulnerability)
	for _, v := range rpt.Vuls {
		if list, ok := fileMap[v.FileName]; !ok {
			files = append(files, v.FileName)
			fileMap[v.FileName] = []*api.RESTVulnerability{v}
		} else {
			fileMap[v.FileName] = append(list, v)
		}
	}

	sort.Strings(files)

	for _, f := range files {
		list, ok := fileMap[f]
		if !ok {
			continue
		}

		if f != "" {
			fmt.Printf("\nFile: %s\n", f)
		}

		if len(list) > 0 {
			rowConfigAutoMerge := table.RowConfig{AutoMerge: true}
			t := table.NewWriter()
			t.SetOutputMirror(os.Stdout)
			t.AppendHeader(table.Row{
				"Package", "Vulnerability", "Severity", "Version", "Fixed Version", "Published",
			})
			for _, v := range list {
				t.AppendRow(table.Row{
					v.PackageName,
					v.Name,
					v.Severity,
					v.PackageVersion,
					v.FixedVersion,
					time.Unix(v.PublishedTS, 0).UTC().Format("2006-01-02"),
				}, rowConfigAutoMerge)
			}
			t.SetColumnConfigs([]table.ColumnConfig{
				{Name: "Package", AutoMerge: true},
				{Name: "Severity", AutoMerge: true},
				{Name: "Version", AutoMerge: true},
			})
			t.SortBy([]table.SortBy{
				{Name: "Package", Mode: table.Asc},
				{Name: "Severity", Mode: table.Asc},
				{Name: "Vulnerability", Mode: table.Asc},
			})
			t.SetStyle(table.StyleLight)
			t.Style().Options.SeparateRows = true
			t.Render()
		}
	}

	options := strings.Split(showOptions, ",")
	for _, o := range options {
		switch o {
		case "cmd":
			fmt.Printf("\nHistory:\n")
			for i, cmd := range rpt.Cmds {
				if i < len(rpt.Layers) {
					digest := strings.ToUpper(strings.TrimPrefix(rpt.Layers[i].Digest, "sha256:"))
					if len(digest) > 12 {
						digest = digest[:12]
					}
					fmt.Printf("%12s %s\n", digest, cmd)
				} else {
					fmt.Printf("%12s %s\n", "", cmd)
				}
			}
		case "module":
			fmt.Printf("\nModules:\n")
			for _, m := range rpt.Modules {
				fmt.Printf("%s %s\n", m.Name, m.Version)
			}
		}
	}
}

func scanRunning(pid int, cvedb map[string]*share.ScanVulnerability, showOptions string, capCritical bool) {
	newDB := &share.CLUSScannerDB{
		CVEDBVersion:    cveDB.CveDBVersion,
		CVEDBCreateTime: cveDB.CveDBCreateTime,
		CVEDB:           cvedb,
	}
	scanUtils.SetScannerDB(newDB)

	sys := system.NewSystemTools()
	sysInfo := sys.GetSystemInfo()
	scanUtil := scan.NewScanUtil(sys)
	cveTools := cvetools.NewScanTools("", sys, nil, "")

	var data share.ScanData
	data.Buffer, data.Error = scanUtil.GetRunningPackages("1", share.ScanObjectType_HOST, pid, sysInfo.Kernel.Release, "", false)
	if data.Error != share.ScanErrorCode_ScanErrNone {
		log.WithFields(log.Fields{"pid": pid, "error": data.Error}).Error("Failed to get the packages")
		return
	}

	var result *share.ScanResult
	var err error

	if scanTasker != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
		result, err = scanTasker.Run(ctx, data)
		cancel()
	} else {
		result, err = cveTools.ScanImageData(&data)
	}

	if err != nil {
		log.WithFields(log.Fields{"pid": pid, "error": err}).Error("Failed to scan the packages")
		return
	}

	if !capCritical && result != nil {
		downgradeCriticalSeverityInResult(result)
	}

	fmt.Printf("PID: %d\n", pid)
	writeResultToStdout(nil, result, showOptions)
}
func normalizeRegistry(reg string) string {
	if reg == "" {
		return reg
	}
	if strings.HasPrefix(reg, "http://") || strings.HasPrefix(reg, "https://") {
		return reg
	}
	return "https://" + reg
}
func scanOnDemand(req *share.ScanImageRequest, cvedb map[string]*share.ScanVulnerability, showOptions string, capCritical bool) *share.ScanResult {
	var result *share.ScanResult
	var err error

	newDB := &share.CLUSScannerDB{
		CVEDBVersion:    cveDB.CveDBVersion,
		CVEDBCreateTime: cveDB.CveDBCreateTime,
		CVEDB:           cvedb,
	}
	scanUtils.SetScannerDB(newDB)
	req.Registry = normalizeRegistry(req.Registry)
	var dockerRegistries = utils.NewSet("https://docker.io/", "https://index.docker.io/", "https://registry.hub.docker.com/", "https://registry-1.docker.io/")
	log.WithFields(log.Fields{"req.Registry": req.Registry, "req.Repository": req.Repository, "dockerRegistries.Contains(req.Registry)": dockerRegistries.Contains(req.Registry)}).Info("registry")
	// Add "library" for dockerhub if not exist
	if dockerRegistries.Contains(req.Registry) && !strings.Contains(req.Repository, "/") {
		req.Repository = fmt.Sprintf("library/%s", req.Repository)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*20)
	if scanTasker != nil {
		result, err = scanTasker.Run(ctx, *req)
	} else {
		cveTools := cvetools.NewScanTools("", system.NewSystemTools(), nil, "")
		result, err = cveTools.ScanImage(ctx, req, "")
	}
	cancel()

	if !capCritical && result != nil {
		downgradeCriticalSeverityInResult(result)
	}

	if req.Registry == "" && result != nil &&
		(result.Error == share.ScanErrorCode_ScanErrImageNotFound || result.Error == share.ScanErrorCode_ScanErrContainerAPI) {
		req.Registry = defaultDockerhubReg

		if !strings.Contains(req.Repository, "/") {
			req.Repository = fmt.Sprintf("library/%s", req.Repository)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Minute*20)
		if scanTasker != nil {
			result, err = scanTasker.Run(ctx, *req)
		} else {
			cveTools := cvetools.NewScanTools("", system.NewSystemTools(), nil, "")
			result, err = cveTools.ScanImage(ctx, req, "")
		}
		cancel()

		if !capCritical && result != nil {
			downgradeCriticalSeverityInResult(result)
		}
	}

	if result == nil {
		if err != nil {
			log.WithFields(log.Fields{
				"registry": req.Registry, "repo": req.Repository, "tag": req.Tag, "error": err.Error(),
			}).Error("Scan failed")
		} else {
			log.WithFields(log.Fields{
				"registry": req.Registry, "repo": req.Repository, "tag": req.Tag,
			}).Error("Scan failed: empty result")
		}
	} else if result.Error != share.ScanErrorCode_ScanErrNone {
		log.WithFields(log.Fields{
			"registry": req.Registry, "repo": req.Repository, "tag": req.Tag, "error": scanUtils.ScanErrorToStr(result.Error),
		}).Error("Failed to scan repository")
	}

	writeResultToFile(req, result, err)
	writeResultToStdout(req, result, showOptions)

	return result
}

type apiClient struct {
	urlBase string
	token   string
	client  *http.Client
}

func newAPIClient(ctrlIP string, ctrlPort uint16) *apiClient {
	return &apiClient{
		urlBase: fmt.Sprintf("https://%s:%d", ctrlIP, ctrlPort),
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: apiCallTimeout,
		},
	}
}

func apiLogin(c *apiClient, myIP string, user, pass string) error {
	data := api.RESTAuthData{ClientIP: myIP, Password: &api.RESTAuthPassword{Username: user, Password: pass}}
	body, _ := json.Marshal(&data)

	req, err := http.NewRequest("POST", c.urlBase+"/v1/auth", bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("Login failed with status code %d", resp.StatusCode)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var token api.RESTTokenData
	err = json.Unmarshal(body, &token)
	if err != nil {
		return err
	}

	c.token = token.Token.Token
	return nil
}

func apiLogout(c *apiClient) error {
	req, err := http.NewRequest("DELETE", c.urlBase+"/v1/auth", nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set(api.RESTTokenHeader, c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("Logout failed with status code %d", resp.StatusCode)
	}

	c.token = ""
	return nil
}

func apiSubmitResult(c *apiClient, result *share.ScanResult) error {
	data := api.RESTScanRepoSubmitData{Result: result}
	body, _ := json.Marshal(&data)

	req, err := http.NewRequest("POST", c.urlBase+"/v1/scan/result/repository", bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(api.RESTTokenHeader, c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("Submit scan result failed with status code %d", resp.StatusCode)
	}

	return nil
}

func scanSubmitResult(ctrlIP string, ctrlPort uint16, myIP string, user, pass string, result *share.ScanResult) error {
	log.WithFields(log.Fields{"join": fmt.Sprintf("%s:%d", ctrlIP, ctrlPort)}).Debug()

	c := newAPIClient(ctrlIP, ctrlPort)

	if err := apiLogin(c, myIP, user, pass); err != nil {
		return err
	}
	if err := apiSubmitResult(c, result); err != nil {
		return err
	}
	if err := apiLogout(c); err != nil {
		return err
	}

	return nil
}
