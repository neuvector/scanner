package scan

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/utils"
)

const (
	AppFileName = "apps_pkg"

	nodeModules1 = "/usr/lib/node_modules"
	nodeModules2 = "/usr/local/lib/node_modules"
	nodeModules  = "node_modules"
	nodePackage  = "package.json"
	nodeJs       = "node.js"

	wpname           = "Wordpress"
	WPVerFileSuffix  = "wp-includes/version.php"
	wpVersionMaxSize = 4 * 1024

	jar                = "jar"
	javaPOMXML         = "/pom.xml"
	pomReadSize        = 1024 * 1024
	javaServerInfo     = "/ServerInfo.properties"
	serverInfoMaxLines = 100
	tomcatName         = "Tomcat"
	jarMaxDepth        = 2

	javaPOMproperty    = "/pom.properties"
	javaPOMgroupId     = "groupId="
	javaPOMartifactId  = "artifactId="
	javaPOMversion     = "version="
	javaManifest       = "MANIFEST.MF"
	javaMnfstVendorId  = "Implementation-Vendor-Id:"
	javaMnfstVersion   = "Implementation-Version:"
	javaMnfstTitle     = "Implementation-Title:"

	python            = "python"
	ruby              = "ruby"
	dotnetDepsMaxSize = 10 * 1024 * 1024
)

var verRegexp = regexp.MustCompile(`<([a-zA-Z0-9\.]+)>([0-9\.]+)</([a-zA-Z0-9\.]+)>`)
var pyRegexp = regexp.MustCompile(`/([a-zA-Z0-9_\.]+)-([a-zA-Z0-9\.]+)[\-a-zA-Z0-9\.]*\.(egg-info\/PKG-INFO|dist-info\/WHEEL)$`)
var rubyRegexp = regexp.MustCompile(`/([a-zA-Z0-9_\-]+)-([0-9\.]+)\.gemspec$`)

type AppPackage struct {
	AppName    string `json:"app_name"`
	ModuleName string `json:"module_name"`
	Version    string `json:"version"`
	FileName   string `json:"file_name"`
}

type mvnProject struct {
	Parent       mvnParent       `xml:"parent"`
	ArtifactId   string          `xml:"artifactId"`
	Dependencies []mvnDependency `xml:"dependencies>dependency"`
}

type mvnParent struct {
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type mvnDependency struct {
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

type dotnetDependency struct {
	Deps map[string]string `json:"dependencies"`
}

type dotnetRuntime struct {
	Name      string `json:"name"`
	Signature string `json:"signature"`
}

type dotnetPackage struct {
	Runtime dotnetRuntime                          `json:"runtimeTarget"`
	Targets map[string]map[string]dotnetDependency `json:"targets"`
}

type ScanApps struct {
	dedup   utils.Set               // Used by some apps to remove duplicated modules
	pkgs    map[string][]AppPackage // AppPackage set
	replace bool
}

func NewScanApps(v2 bool) *ScanApps {
	return &ScanApps{pkgs: make(map[string][]AppPackage), dedup: utils.NewSet(), replace: v2}
}

func isAppsPkgFile(filename string) bool {
	return isNodejs(filename) || isJava(filename) || isPython(filename) ||
		isRuby(filename) || isDotNet(filename) || isWordpress(filename)
}

func (s *ScanApps) name() string {
	return AppFileName
}

func (s *ScanApps) empty() bool {
	return len(s.pkgs) == 0
}

func (s *ScanApps) data() map[string][]AppPackage {
	return s.pkgs
}

func (s *ScanApps) marshal() []byte {
	buf := new(bytes.Buffer)
	for _, pkg := range s.pkgs {
		// write by 64-entry chunk, so we don't hit the scanner limit when reading it
		for len(pkg) > 64 {
			if b, err := json.Marshal(pkg[:64]); err == nil {
				buf.WriteString(fmt.Sprintf("%s\n", string(b)))
			}
			pkg = pkg[64:]
		}
		if len(pkg) > 0 {
			if b, err := json.Marshal(pkg); err == nil {
				buf.WriteString(fmt.Sprintf("%s\n", string(b)))
			}
		}
	}
	return buf.Bytes()
}

func (s *ScanApps) extractAppPkg(filename, fullpath string) {
	if _, ok := s.pkgs[filename]; ok && !s.replace {
		return
	}

	if isNodejs(filename) {
		s.parseNodePackage(filename, fullpath)
	} else if isJava(filename) {
		r, err := zip.OpenReader(fullpath)
		if err == nil {
			s.parseJarPackage(r.Reader, filename, fullpath, 0)
			r.Close()
		} else {
			log.WithFields(log.Fields{"err": err}).Error("open jar file fail")
		}
	} else if isPython(filename) {
		s.parsePythonPackage(filename)
	} else if isRuby(filename) {
		s.parseRubyPackage(filename)
	} else if isDotNet(filename) {
		s.parseDotNetPackage(filename, fullpath)
	} else if isWordpress(filename) {
		s.parseWordpressPackage(filename, fullpath)
	}
}

func (s *ScanApps) DerivePkg(data map[string][]byte) []AppPackage {
	f, hasFile := data[s.name()]
	if !hasFile {
		return nil
	}

	pkgs := make([]AppPackage, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(f[:])))
	for scanner.Scan() {
		line := scanner.Text()
		var list []AppPackage
		if err := json.Unmarshal([]byte(line), &list); err == nil {
			pkgs = append(pkgs, list...)
		} else {
			log.WithFields(log.Fields{"err": err, "line": line}).Error("unmarshal app pkg fail")
		}
	}
	return pkgs
}

func isNodejs(filename string) bool {
	return strings.Contains(filename, nodeModules) &&
		strings.HasSuffix(filename, nodePackage)
}

func (s *ScanApps) parseNodePackage(filename, fullpath string) {
	var version string
	var name string
	inputFile, err := os.Open(fullpath)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "fullpath": fullpath, "filename": filename}).Debug("read file fail")
		return
	}
	defer inputFile.Close()

	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		s := scanner.Text()
		if strings.HasPrefix(s, "  \"version\":") {
			a := len("  \"version\": \"")
			b := strings.LastIndex(s, "\"")
			if b < 0 {
				continue
			}
			version = s[a:b]
		} else if strings.HasPrefix(s, "  \"name\": \"") {
			a := len("  \"name\": \"")
			b := strings.LastIndex(s, "\"")
			if b < 0 {
				continue
			}
			name = s[a:b]
		}
		if name != "" && version != "" {
			break
		}
	}

	if name == "" || version == "" {
		return
	}

	// Cannot change the filename, which is the key of s.pkgs and used for resolve
	// overwrite among layers
	// filename = strings.Replace(filename, "/package.json", "", -1)
	pkg := AppPackage{
		AppName:    nodeJs,
		ModuleName: name,
		Version:    version,
		FileName:   filename,
	}
	s.pkgs[filename] = []AppPackage{pkg}
}

func isJavaJar(filename string) bool {
	return strings.HasSuffix(filename, ".jar")
}

func isJava(filename string) bool {
	return strings.HasSuffix(filename, ".war") ||
		strings.HasSuffix(filename, ".jar") ||
		strings.HasSuffix(filename, ".ear")
}

func (s *ScanApps) parseJarPackage(r zip.Reader, filename, fullpath string, depth int) {
	tempDir, err := ioutil.TempDir(filepath.Dir(fullpath), "")
	if err == nil {
		defer os.RemoveAll(tempDir)
	} else {
		log.WithFields(log.Fields{"fullpath": fullpath}).Error("unable to create temp dir")
	}

	pkgs := make(map[string][]AppPackage)
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}

		if depth+1 < jarMaxDepth && isJava(f.Name) {
			// Parse jar file recursively
			if jarFile, err := f.Open(); err == nil {
				// Unzip the jar file to disk then walk through. Can we unzip on the fly?
				dstPath := filepath.Join(tempDir, filepath.Base(f.Name)) // retain the filename
				if dstFile, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode()); err == nil {
					if _, err := io.Copy(dstFile, jarFile); err == nil {
						jarReader, err := zip.OpenReader(fullpath)
						if err == nil {
							s.parseJarPackage(jarReader.Reader, f.Name, dstPath, depth+1)
							jarReader.Close()
						}
					} else {
						log.WithFields(log.Fields{"dst": dstPath, "filename": filename, "err": err}).Error("unable to copy jar file")
					}
					os.Remove(dstPath)
				} else {
					log.WithFields(log.Fields{"dst": dstPath, "err": err}).Error("unable to create dst file")
				}
				jarFile.Close()
			} else {
				log.WithFields(log.Fields{"fullpath": fullpath, "filename": filename, "depth": depth, "err": err}).Error("open jar file fail")
			}
		} else if strings.HasSuffix(f.Name, javaServerInfo) {
			rc, err := f.Open()
			if err != nil {
				log.WithFields(log.Fields{"err": err, "file": f.Name}).Error("Open file fail")
				continue
			}
			defer rc.Close()

			scanner := bufio.NewScanner(rc)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "server.info=") {
					prod := strings.TrimPrefix(line, "server.info=")
					if strings.HasPrefix(prod, "Apache Tomcat/") {
						if ver := strings.TrimPrefix(prod, "Apache Tomcat/"); len(ver) > 0 {
							pkg := AppPackage{
								AppName:    tomcatName,
								ModuleName: tomcatName,
								Version:    ver,
								FileName:   filename,
							}
							pkgs[filename] = []AppPackage{pkg}
						}
					}
				}
			}
		} else if strings.HasSuffix(f.Name, javaPOMproperty) {
			var groupId, version, artifactId string
			rc, err := f.Open()
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Error("open pom file fail")
				continue
			}
			defer rc.Close()

			scanner := bufio.NewScanner(rc)
			for scanner.Scan() {
				line := scanner.Text()
				switch {
				case strings.HasPrefix(line, javaPOMgroupId):
					groupId = strings.TrimSpace(strings.TrimPrefix(line, javaPOMgroupId))
				case strings.HasPrefix(line, javaPOMversion):
					version = strings.TrimSpace(strings.TrimPrefix(line, javaPOMversion))
				case strings.HasPrefix(line, javaPOMartifactId):
					artifactId = strings.TrimSpace(strings.TrimPrefix(line, javaPOMartifactId))
				}

				if len(groupId) > 0  && len(version) > 0 && len(artifactId) > 0 {
					break
				}
			}

			pkg := AppPackage{
				AppName:    jar,
				FileName:   filename,
				ModuleName: fmt.Sprintf("%s:%s", groupId, artifactId),
				Version:    version,
			}

			pkgs[filename] = []AppPackage{pkg}
			break	// higher priority
		} else if strings.HasSuffix(f.Name, javaManifest) {
			var vendorId, version, title string
			rc, err := f.Open()
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Error("open pom.xml file fail")
				continue
			}
			defer rc.Close()

			scanner := bufio.NewScanner(rc)
			for scanner.Scan() {
				line := scanner.Text()
				switch {
				case strings.HasPrefix(line, javaMnfstVendorId):
					vendorId = strings.TrimSpace(strings.TrimPrefix(line, javaMnfstVendorId))
				case strings.HasPrefix(line, javaMnfstVersion):
					version = strings.TrimSpace(strings.TrimPrefix(line, javaMnfstVersion))
				case strings.HasPrefix(line, javaMnfstTitle):
					title = strings.TrimSpace(strings.TrimPrefix(line, javaMnfstTitle))
				}

				if len(vendorId) > 0  && len(title) > 0 && len(version) > 0 {
					break
				}
			}

			pkg := AppPackage{
				AppName:    jar,
				FileName:   filename,
				ModuleName: fmt.Sprintf("%s:%s", vendorId, title),
				Version:    version,
			}

			pkgs[filename] = []AppPackage{pkg}
		}
	}

	// If no package found, use filename
	if len(pkgs) == 0 && isJavaJar(filename) {
		fn := filepath.Base(filename)
		dash := strings.LastIndex(fn, "-")
		dot := strings.LastIndex(fn, ".")
		if dash > 0 && dash+1 < dot {
			pkg := AppPackage{
				AppName:    jar,
				ModuleName: fmt.Sprintf("jar:%s", fn[:dash]),
				Version:    fn[dash+1 : dot],
				FileName:   filename,
			}
			pkgs[filename] = []AppPackage{pkg}
		}
	}

	for filename, list := range pkgs {
		s.pkgs[filename] = list
	}
}

func isPython(filename string) bool {
	return pyRegexp.MatchString(filename)
}

func isRuby(filename string) bool {
	return rubyRegexp.MatchString(filename)
}

func isDotNet(filename string) bool {
	return strings.HasSuffix(filename, ".deps.json")
}

func isWordpress(filename string) bool {
	return strings.HasSuffix(filename, WPVerFileSuffix)
}

func (s *ScanApps) parsePythonPackage(filename string) {
	match := pyRegexp.FindAllStringSubmatch(filename, 1)
	if len(match) > 0 {
		sub := match[0]
		name := sub[1]
		ver := sub[2]
		var pkgPath string
		pkgPath = strings.TrimRight(filename, ".egg-info/PKG-INFO")
		pkgPath = strings.TrimRight(pkgPath, ".dist-info/WHEEL")
		pkg := AppPackage{
			AppName:    python,
			ModuleName: python + ":" + name,
			Version:    ver,
			FileName:   pkgPath,
		}
		s.pkgs[filename] = []AppPackage{pkg}
	}
}

func (s *ScanApps) parseRubyPackage(filename string) {
	match := rubyRegexp.FindAllStringSubmatch(filename, 1)
	if len(match) > 0 {
		sub := match[0]
		name := sub[1]
		ver := sub[2]
		var pkgPath string
		pkgPath = strings.TrimRight(filename, ".gemspec")
		pkg := AppPackage{
			AppName:    ruby,
			ModuleName: ruby + ":" + name,
			Version:    ver,
			FileName:   pkgPath,
		}
		s.pkgs[filename] = []AppPackage{pkg}
	}
}

func (s *ScanApps) parseWordpressPackage(filename, fullpath string) {
	if fi, err := os.Stat(fullpath); err != nil {
		log.WithFields(log.Fields{"err": err, "fullpath": fullpath, "filename": filename}).Error("Failed to stat file")
		return
	} else if fi.Size() > wpVersionMaxSize {
		log.WithFields(log.Fields{"max": wpVersionMaxSize, "fullpath": fullpath, "filename": filename}).Error("File size too large")
		return
	}

	inputFile, err := os.Open(fullpath)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "fullpath": fullpath, "filename": filename}).Debug("Open file fail")
		return
	}
	defer inputFile.Close()

	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "$wp_version = '") {
			a := len("$wp_version = '")
			b := strings.LastIndex(line, "'")
			if b > a {
				version := line[a:b]
				pkg := AppPackage{
					AppName:    wpname,
					ModuleName: wpname,
					Version:    version,
					FileName:   filename,
				}
				s.pkgs[filename] = []AppPackage{pkg}
				return
			}
		}
	}

	return
}

func (s *ScanApps) parseDotNetPackage(filename, fullpath string) {
	if fi, err := os.Stat(fullpath); err != nil {
		log.WithFields(log.Fields{"err": err, "fullpath": fullpath, "filename": filename}).Error("Failed to stat file")
		return
	} else if fi.Size() > dotnetDepsMaxSize {
		log.WithFields(log.Fields{"max": dotnetDepsMaxSize, "fullpath": fullpath, "filename": filename}).Error("File size too large")
		return
	}

	var dotnet dotnetPackage

	if data, err := ioutil.ReadFile(fullpath); err != nil {
		log.WithFields(log.Fields{"err": err, "fullpath": fullpath, "filename": filename}).Error("Failed to read file")
		return
	} else if err = json.Unmarshal(data, &dotnet); err != nil {
		log.WithFields(log.Fields{"err": err, "fullpath": fullpath, "filename": filename}).Error("Failed to unmarshal file")
		return
	}

	var coreVersion string

	pkgs := make([]AppPackage, 0)
	/*
		// Not reliable
		if strings.HasPrefix(dotnet.Runtime.Name, ".NETCoreApp") {
			tokens := strings.Split(dotnet.Runtime.Name, ",")
			for _, token := range tokens {
				// .NETCoreApp,Version=v3.1/linux-x64, .NETCoreApp,Version=v3.1
				if strings.HasPrefix(token, "Version=v") {
					version := token[9:]
					if o := strings.Index(version, "/"); o != -1 {
						version = version[:o]
					}
					coreVersion = version
					break
				}
			}
		}
	*/

	// parse filename
	tokens := strings.Split(filename, "/")
	for i, token := range tokens {
		if token == "Microsoft.NETCore.App" || token == "Microsoft.AspNetCore.App" {
			if i < len(tokens)-1 {
				coreVersion = tokens[i+1]
			}
			break
		}
	}

	if targets, ok := dotnet.Targets[dotnet.Runtime.Name]; ok {
		for target, dep := range targets {
			// "Microsoft.NETCore.App/3.1.15-servicing.21214.3"
			if strings.HasPrefix(target, "Microsoft.NETCore.App") || strings.HasPrefix(target, "Microsoft.AspNetCore.App") {
				if o := strings.Index(target, "/"); o != -1 {
					version := target[o+1:]
					if o = strings.Index(version, "-"); o != -1 {
						version = version[:o]
					}
					coreVersion = version
				}
			}

			for app, v := range dep.Deps {
				pkg := AppPackage{
					AppName:    ".NET",
					ModuleName: ".NET:" + app,
					Version:    v,
					FileName:   filename,
				}

				// There can be several files that list the same dependency, such as .NET Core, so to dedup them
				key := fmt.Sprintf("%s-%s-%s", pkg.AppName, pkg.ModuleName, pkg.Version)
				if !s.dedup.Contains(key) {
					s.dedup.Add(key)
					pkgs = append(pkgs, pkg)
				}
			}
		}
	}

	if coreVersion != "" {
		pkg := AppPackage{
			AppName:    ".NET",
			ModuleName: ".NET:Core",
			Version:    coreVersion,
			FileName:   filename,
		}

		// There can be several files that list the same dependency, such as .NET Core, so to dedup them
		key := fmt.Sprintf("%s-%s-%s", pkg.AppName, pkg.ModuleName, pkg.Version)
		if !s.dedup.Contains(key) {
			s.dedup.Add(key)
			pkgs = append(pkgs, pkg)
		}
	}

	if len(pkgs) > 0 {
		s.pkgs[filename] = pkgs
	}
}
