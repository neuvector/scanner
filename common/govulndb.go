package common

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	scanUtils "github.com/neuvector/neuvector/share/scan"
	log "github.com/sirupsen/logrus"
)

func ExtractGovulnDB() error {
	// Check if govulndb directory already exists and is not empty
	if info, err := os.Stat(scanUtils.GovulcheckDBPath); err == nil && info.IsDir() {
		if entries, err := os.ReadDir(scanUtils.GovulcheckDBPath); err == nil && len(entries) > 0 {
			log.WithFields(log.Fields{"path": scanUtils.GovulcheckDBPath}).Debug("govulndb already exists, skipping extraction")
			return nil
		}
	}

	zipPath := fmt.Sprintf("%s.zip", scanUtils.GovulcheckDBPath)

	if _, err := os.Stat(zipPath); os.IsNotExist(err) {
		log.WithFields(log.Fields{"path": zipPath}).Error("govulndb.zip not found, skipping extraction")
		return err
	}

	if err := os.RemoveAll(scanUtils.GovulcheckDBPath); err != nil {
		return fmt.Errorf("failed to remove existing govulndb directory: %w", err)
	}

	if err := os.MkdirAll(scanUtils.GovulcheckDBPath, 0o755); err != nil {
		return fmt.Errorf("failed to create govulndb directory: %w", err)
	}

	if err := unzipFile(zipPath, scanUtils.GovulcheckDBPath); err != nil {
		return fmt.Errorf("failed to extract govulndb.zip: %w", err)
	}

	log.WithFields(log.Fields{"target": scanUtils.GovulcheckDBPath}).Info("govulndb extracted successfully")
	return nil
}

func unzipFile(zipPath, targetPath string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %w", err)
	}
	defer reader.Close()

	for _, file := range reader.File {
		if err := extractZipFile(file, targetPath); err != nil {
			return fmt.Errorf("failed to extract %s: %w", file.Name, err)
		}
	}

	return nil
}

func extractZipFile(file *zip.File, targetPath string) error {
	filePath := filepath.Join(targetPath, file.Name)

	if !strings.HasPrefix(filePath, filepath.Clean(targetPath)+string(os.PathSeparator)) {
		return fmt.Errorf("illegal file path: %s", file.Name)
	}

	if file.FileInfo().IsDir() {
		return os.MkdirAll(filePath, file.Mode())
	}

	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return err
	}

	outFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
	if err != nil {
		return err
	}
	defer outFile.Close()

	rc, err := file.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	_, err = io.Copy(outFile, rc)
	return err
}
