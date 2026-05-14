package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

var proxyURL = flag.String("proxy-url", "", "")
var proxyHasCredentials = flag.Bool("proxy-has-credentials", false, "")
var configFilePath = flag.String("config-file", "", "")
var proxyLogin = flag.String("proxy-login", "", "")

// for testing stdin pipe operations
func main() {
	flag.Parse()
	cmd := exec.Command(
		"../sigstore-interface",
		fmt.Sprintf("--config-file=%s", *configFilePath),
		fmt.Sprintf("--proxy-url=%s", *proxyURL),
		fmt.Sprintf("--proxy-has-credentials=%t", *proxyHasCredentials),
	)

	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()
	stdin, _ := cmd.StdinPipe()

	var closeErr error

	go func() {
		fmt.Println("writing to stdin")
		if _, err := io.WriteString(stdin, *proxyLogin); err != nil {
			log.WithError(err).Error("Failed to write to stdin")
		}
		closeErr = stdin.Close()
	}()

	fmt.Println("starting cmd")
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}

	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}

	scanner = bufio.NewScanner(stdout)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}

	if err := cmd.Wait(); err != nil {
		log.WithError(err).Error("failed to wait for cmd")
	}

	if closeErr != nil {
		fmt.Printf("error when closing stdin pipe: %s\n", closeErr)
	}
}
