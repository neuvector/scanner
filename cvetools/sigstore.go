package cvetools

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/scan"
)

type sigstoreInterfaceConfig struct {
	ImageDigest   string                      `json:"ImageDigest"`
	RootsOfTrust  []share.SigstoreRootOfTrust `json:"RootsOfTrust"`
	SignatureData scan.SignatureData          `json:"SignatureData"`
}

func verifyImageSignatures(imgDigest string, rootsOfTrust []*share.SigstoreRootOfTrust, sigData scan.SignatureData) (verifiers []string, err error) {
	confPath, confFile, err := createConfFile(imgDigest)
	if err != nil {
		return verifiers, fmt.Errorf("could not create interface config file for image %s: %s", imgDigest, err.Error())
	}
	confJSON, err := getConfJSON(imgDigest, rootsOfTrust, sigData)
	if err != nil {
		return verifiers, fmt.Errorf("could not marshal config json from arguments: %s", err.Error())
	}
	_, err = confFile.Write(confJSON)
	if err != nil {
		return verifiers, fmt.Errorf("could not write data to config file at %s: %s", confPath, err.Error())
	}
	binaryOutput, err := executeVerificationBinary(confPath)
	if err != nil {
		return verifiers, fmt.Errorf("error when executing verification binary: %s", err.Error())
	}
	err = os.Remove(confPath)
	if err != nil {
		return verifiers, fmt.Errorf("could not remove used interface config file at %s: %s", confPath, err.Error())
	}
	return parseVerifiersFromBinaryOutput(binaryOutput), nil
}

func getConfJSON(imgDigest string, rootsOfTrust []*share.SigstoreRootOfTrust, sigData scan.SignatureData) ([]byte, error) {
	dereferencedRoots := []share.SigstoreRootOfTrust{}
	for _, rootOfTrust := range rootsOfTrust {
		dereferencedRoots = append(dereferencedRoots, *rootOfTrust)
	}
	return json.Marshal(sigstoreInterfaceConfig{
		ImageDigest:   imgDigest,
		RootsOfTrust:  dereferencedRoots,
		SignatureData: sigData,
	})
}

func createConfFile(imgDigest string) (path string, file *os.File, err error) {
	// there is a remote possibility that concurrent scans could incur config file path collisions
	// this is handled by adding an iterator to the end of file path
	var confPath string
	i := 0
	for {
		possiblePath := fmt.Sprintf("/tmp/neuvector/sigstore_interface_config_%s_%d.json", imgDigest, i)
		_, err := os.Stat(possiblePath)
		if os.IsNotExist(err) {
			confPath = possiblePath
			break
		}
		i++
	}
	confFile, err := os.Create(confPath)
	if err != nil {
		return "", nil, fmt.Errorf("could not create interface config file at %s: %s", confPath, err.Error())
	}
	return confPath, confFile, nil
}

func parseVerifiersFromBinaryOutput(output string) []string {
	outputLines := strings.Split(output, "\n")
	lastLine := outputLines[len(outputLines)-2]
	satisfiedVerifiers := strings.Split(lastLine[1:len(lastLine)-1], ", ")
	return satisfiedVerifiers
}

func executeVerificationBinary(inputPath string) (output string, err error) {
	inputFlag := fmt.Sprintf("--config-file=%s", inputPath)
	cmd := exec.Command("/usr/local/bin/sigstore-interface", inputFlag)
	var out strings.Builder
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		return "", fmt.Errorf("error executing verification binary: %s", err.Error())
	}
	return out.String(), nil
}
