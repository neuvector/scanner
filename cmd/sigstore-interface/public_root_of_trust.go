package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	sigtuf "github.com/sigstore/sigstore/pkg/tuf"
	tufclient "github.com/theupdateframework/go-tuf/client"
)

var globalBuffer bytes.Buffer

type inMemoryDest struct{}

func (d inMemoryDest) Write(p []byte) (n int, err error) {
	return globalBuffer.Write(p)
}

func (d inMemoryDest) Delete() error {
	panic("inMemoryDest delete function should not run")
}

func GetSigstorePublicTufTargets(usage sigtuf.UsageKind, proxy Proxy) ([]sigtuf.TargetFile, error) {
	// client initialization
	httpClient := &http.Client{
		Timeout: 20 * time.Second,
	}
	if proxy.URL != "" {
		transport := proxy.HttpTransport()
		httpClient.Transport = transport
	} else {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}
	remoteStore, err := tufclient.HTTPRemoteStore(sigtuf.DefaultRemoteRoot, nil, httpClient)
	if err != nil {
		return nil, fmt.Errorf("could not create remote store object: %s", err.Error())
	}
	localClient := tufclient.NewClient(tufclient.MemoryLocalStore(), remoteStore)
	err = localClient.Init([]byte(SigstoreTUFRootJSON))
	if err != nil {
		return nil, fmt.Errorf("error initializing tuf client: %s", err.Error())
	}
	err = localClient.UpdateRoots()
	if err != nil {
		return nil, fmt.Errorf("error updating tuf client roots: %s", err.Error())
	}
	_, err = localClient.Update()
	if err != nil {
		return nil, fmt.Errorf("error updating tuf client metadata: %s", err.Error())
	}

	// target retrieval
	type customMetadata struct {
		Usage  sigtuf.UsageKind  `json:"usage"`
		Status sigtuf.StatusKind `json:"status"`
	}

	type sigstoreCustomMetadata struct {
		Sigstore customMetadata `json:"sigstore"`
	}

	targets, err := localClient.Targets()
	if err != nil {
		return nil, fmt.Errorf("error getting targets: %w", err)
	}
	var matchedTargets []sigtuf.TargetFile
	for name, targetMeta := range targets {
		// Skip any targets that do not include custom metadata.
		if targetMeta.Custom == nil {
			continue
		}
		var scm sigstoreCustomMetadata
		err := json.Unmarshal(*targetMeta.Custom, &scm)
		if err != nil {
			fmt.Fprintf(os.Stderr, "**Warning** Custom metadata not configured properly for target %s, skipping target\n", name)
			continue
		}
		if scm.Sigstore.Usage == usage {
			dest := inMemoryDest{}
			err = localClient.Download(name, dest)
			if err != nil {
				globalBuffer.Reset()
				return nil, fmt.Errorf("error downloading target: %s", err.Error())
			}
			globalBytes := globalBuffer.Bytes()
			targetBytes := make([]byte, len(globalBytes))
			copy(targetBytes, globalBytes)
			globalBuffer.Reset()
			matchedTargets = append(matchedTargets, sigtuf.TargetFile{Target: targetBytes, Status: scm.Sigstore.Status})
		}
	}
	return matchedTargets, nil
}
