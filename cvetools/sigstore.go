package cvetools

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/scan"
	log "github.com/sirupsen/logrus"
)

type sigstoreInterfaceConfig struct {
	ImageDigest   string                      `json:"ImageDigest"`
	RootsOfTrust  []share.SigstoreRootOfTrust `json:"RootsOfTrust"`
	SignatureData scan.SignatureData          `json:"SignatureData"`
}

func verifyImageSignatures(imgDigest string, rootsOfTrust []*share.SigstoreRootOfTrust, sigData scan.SignatureData, proxyURL string) (verifiers []string, err error) {
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
	binaryOutput, err := executeVerificationBinary(confPath, proxyURL)
	if err != nil {
		parseVerifiersFromBinaryOutput(imgDigest, binaryOutput)
		return verifiers, fmt.Errorf("error when executing verification binary: %s", err.Error())
	}
	err = os.Remove(confPath)
	if err != nil {
		return verifiers, fmt.Errorf("could not remove used interface config file at %s: %s", confPath, err.Error())
	}
	return parseVerifiersFromBinaryOutput(imgDigest, binaryOutput), nil
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

func parseVerifiersFromBinaryOutput(imgDigest string, output string) []string {
	var lastError string
	outputLines := strings.Split(output, "\n")
	for _, line := range outputLines {
		// sigstore-interface writes a line with prefix
		//   "ERROR: " for error encounted when verifying against a verifier
		//   "Satisfied verifiers: " for all the satisfied verifiers separated by ", "
		if strings.HasPrefix(line, "ERROR: ") {
			if line != lastError {
				log.WithFields(log.Fields{"imageDigest": imgDigest}).Error(line[len("ERROR: "):])
				lastError = line
			}
		} else {
			if strings.HasPrefix(line, "Satisfied verifiers: ") {
				if line = strings.TrimSpace(line[len("Satisfied verifiers: "):]); line != "" {
					vs := strings.Split(line, ", ")
					return vs
				}
			}
		}
	}
	return nil
}

func executeVerificationBinary(inputPath string, proxyURL string) (output string, err error) {
	var username, password string
	inputFlag := fmt.Sprintf("--config-file=%s", inputPath)
	args := []string{inputFlag}
	if proxyURL != "" {
		parsedUrl, err := url.Parse(proxyURL)
		if err != nil {
			return "", fmt.Errorf("error parsing proxy url: %s", err.Error())
		}
		if parsedUrl.User != nil {
			username = parsedUrl.User.Username()
			password, _ = parsedUrl.User.Password()
			// this removes any user info from our parsedUrl.String() call so they don't show up
			// in the sigstore-interface process arguments list
			parsedUrl.User = nil
		}
		args = append(args, fmt.Sprintf("--proxy-url=%s", parsedUrl.String()))
		if username != "" {
			args = append(args, "--proxy-has-credentials=true")
		}
	}
	cmd := exec.Command("/usr/local/bin/sigstore-interface", args...)
	stdin, _ := cmd.StdinPipe()
	var stdout strings.Builder
	var stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	var closeErr error

	if username != "" {
		go func() {
			io.WriteString(stdin, fmt.Sprintf("%s:%s", username, password))
			closeErr = stdin.Close()
		}()
	}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("could not start command: %s", err.Error())
	}

	err = cmd.Wait()
	if err != nil {
		return "", fmt.Errorf("error executing verification binary: ExitError %s: stderr: %s", err.Error(), stderr.String())
	}

	if closeErr != nil {
		return "", fmt.Errorf("error when closing stdin pipe: %s", closeErr)
	}

	return stdout.String(), nil
}
