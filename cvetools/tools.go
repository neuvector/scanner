package cvetools

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

const imageWorkingPath = "/tmp/images"

func downloadFromUrl(url, fileName string) error {
	output, err := os.Create(fileName)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "filename": fileName}).Debug("Error creating file")
		return err
	}
	defer output.Close() // clean up

	response, err := http.Get(url)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "filename": fileName}).Debug("Error downloading file")
		return err
	}
	defer response.Body.Close()

	_, err = io.Copy(output, response.Body)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "filename": fileName}).Debug("Error copy file")
		return err
	}
	return nil
}

// Get an unique image folder under /tmp, return "" if can not allocate a good folder
func createImagePath(uid string) string {
	var imgPath string

	// existing uid
	if uid != "" {
		imgPath = filepath.Join(imageWorkingPath, uid)
	} else {
		for i := 0; i < 16; i++ {
			imgPath = filepath.Join(imageWorkingPath, uuid.New().String())
			if _, err := os.Stat(imgPath); os.IsNotExist(err) {
				break
			}
		}
	}

	///
	os.MkdirAll(imgPath, 0755)
	return imgPath
}

// collectImageFileMap creates a virtual file map for a image to save real copy efforts
func collectImageFileMap(rootPath string, fmap map[string]string) (int, error) {
	if len(rootPath) == 0 {
		return 0, nil
	}

	//
	rootLen := len(filepath.Clean(rootPath))
	errorCnt := 0
	cnt := 0
	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if strings.Contains(err.Error(), "no such file") ||
				strings.Contains(err.Error(), "permission denied") {
				errorCnt++
				if errorCnt < 1000 {
					return nil
				}
			}
			return err
		}

		if info.Mode().IsRegular() || info.Mode().IsDir() {
			inpath := path[rootLen:] // include the root "/"
			cnt++
			fmap[inpath] = path // always update
			//	log.WithFields(log.Fields{"path": inpath}).Debug()
		}
		return nil
	})

	return cnt, err
}
