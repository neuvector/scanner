package cvetools

import (
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

// goGluedPreRelease matches versions like "1.21rc2" or "1.22beta1" that are
// missing the semver dash before the pre-release label.
var goGluedPreRelease = regexp.MustCompile(`^(v?\d+\.\d+(?:\.\d+)?)([a-zA-Z].*)$`)

// toGoSemver normalises a Go toolchain version string to canonical semver so
// that golang.org/x/mod/semver.Compare can be used directly.
//
//	"1.27.0"       → "v1.27.0"
//	"1.27.0-rc.3"  → "v1.27.0-rc.3"
//	"go1.27.0"     → "v1.27.0"
//	"1.21rc2"      → "v1.21-rc2"   (glued pre-release)
func toGoSemver(v string) string {
	v = strings.TrimPrefix(v, "go")
	v = goGluedPreRelease.ReplaceAllString(v, "$1-$2")
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

// compareGoVersions compares two Go version strings using semver semantics.
// Returns (result, true) where result follows the sign convention of
// utils.Version.Compare: negative = a < b, 0 = equal, positive = a > b.
// Returns (0, false) if either version cannot be parsed as semver.
func compareGoVersions(a, b string) (int, bool) {
	sa, sb := toGoSemver(a), toGoSemver(b)
	if !semver.IsValid(sa) || !semver.IsValid(sb) {
		return 0, false
	}
	return semver.Compare(sa, sb), true
}
