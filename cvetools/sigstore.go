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
	ImageDigest   string                    `json:"ImageDigest"`
	RootOfTrust   share.SigstoreRootOfTrust `json:"RootOfTrust"`
	Verifiers     []*share.SigstoreVerifier `json:"Verifiers"`
	SignatureData scan.SignatureData        `json:"SignatureData"`
}

func verifyImageSignatures(imgDigest string, conf share.SigstoreConfig, sigData scan.SignatureData) (verifiers []string, err error) {
	inputJSON, err := json.Marshal(sigstoreInterfaceConfig{
		ImageDigest:   imgDigest,
		RootOfTrust:   *conf.RootOfTrust,
		Verifiers:     conf.Verifiers,
		SignatureData: sigData,
	})
	if err != nil {
		return verifiers, fmt.Errorf("could not create input json from arguments: %s", err.Error())
	}
	inputPath := fmt.Sprintf("/tmp/neuvector/sigstore_interface_input_%s.json", imgDigest)
	confFile, err := os.Create(inputPath)
	if err != nil {
		return verifiers, fmt.Errorf("could not create interface input file at %s: %s", inputPath, err.Error())
	}
	_, err = confFile.Write(inputJSON)
	if err != nil {
		return verifiers, fmt.Errorf("could not write data to input file at %s: %s", inputPath, err.Error())
	}
	binaryOutput, err := executeVerificationBinary(inputPath)
	if err != nil {
		return verifiers, fmt.Errorf("error when executing verification binary: %s", err.Error())
	}
	verifiers = parseVerifiersFromBinaryOutput(binaryOutput)
	return verifiers, nil
}

func parseVerifiersFromBinaryOutput(output string) []string {
	outputLines := strings.Split(output, "\n")
	lastLine := outputLines[len(outputLines)-2]
	satisfiedVerifiers := strings.Split(lastLine[1:len(lastLine)-1], ", ")
	return satisfiedVerifiers
}

func executeVerificationBinary(inputPath string) (output string, err error) {
	inputFlag := fmt.Sprintf("--config-file=%s", inputPath)
	cmd := exec.Command("/usr/bin/sigstore-interface", inputFlag)
	var out strings.Builder
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		return "", fmt.Errorf("error executing verification binary: %s", err.Error())
	}
	return out.String(), nil
}
