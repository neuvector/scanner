package cvetools

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

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

// collectImageFileMap creates a virtual file map for a image to save real copy efforts
func collectImageFileMap(rootPath string, fmap map[string]string) (int, []string, error) {
	if len(rootPath) == 0 {
		return 0, nil, nil
	}
	//
	var opqDirs []string
	curfmap := make(map[string]string)

	rootLen := len(filepath.Clean(rootPath))
	errorCnt := 0
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

		if info.Mode().IsDir() {
			inpath := path[rootLen:] // include the root "/"
			curfmap[inpath] = path
		} else if info.Mode().IsRegular() {
			inpath := path[rootLen:] // include the root "/"
			dir := filepath.Dir(inpath)
			file := filepath.Base(inpath)
			switch {
			case file == "_.wh..wh..opq":
				// In a Docker image, there can be an opaque whiteout, ".wh..wh..opq", entry under a directory
				// which indicates all siblings under that directory should be removed.
				// log.WithFields(log.Fields{"path": inpath, "rootPath": rootPath}).Info("opq dir")
				opqDirs = append(opqDirs, dir)
			case strings.HasPrefix(file, "_.wh."):
				// In this case, a "unique whiteout file", like ".wh.myapps", is generated for each entry.
				// If there were more children of this directory in the base layer,
				// there would be an entry for each. Note that this opaque file will apply to all children,
				// including sub-directories, other resources and all descendants.
				// log.WithFields(log.Fields{"path": inpath, "rootPath": rootPath}).Info("opq unique dir")
				opqDirs = append(opqDirs, filepath.Join(dir, file[len("_.wh."):]))
			default:
				curfmap[inpath] = path
			}
		}
		return nil
	})

	// (1) remove the opaque directories from lower layers
	for _, dir := range opqDirs {
		for path := range fmap {
			if strings.HasPrefix(path, dir) {
				// log.WithFields(log.Fields{"path": path, "dir": dir}).Info("Remove")
				delete(fmap, path)
			}
		}
	}

	// (2) add the new added files
	for path, ref := range curfmap {
		if path != "" {
			fmap[path] = ref
			// log.WithFields(log.Fields{"path": path, "ref": ref}).Info("Add")
		}
	}
	return len(curfmap), opqDirs, err
}
