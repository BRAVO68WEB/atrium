// Package version is the build identity stamped into the binaries.
// Release builds set Version, Commit, and Date with -X.
// A local build leaves Version as dev.
package version

import (
	"strings"
)

// Version, Commit, and Date are set with -ldflags -X.
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// Info is the JSON body of GET /version.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Date    string `json:"date,omitempty"`
}

// Current returns the stamped build identity.
func Current() Info {
	return Info{
		Version: displayVersion(),
		Commit:  strings.TrimSpace(Commit),
		Date:    strings.TrimSpace(Date),
	}
}

// Line is the text printed by --version after the program name.
func Line() string {
	info := Current()
	switch {
	case info.Commit != "" && info.Date != "":
		return info.Version + " (" + info.Commit + ", " + info.Date + ")"
	case info.Commit != "":
		return info.Version + " (" + info.Commit + ")"
	case info.Date != "":
		return info.Version + " (" + info.Date + ")"
	default:
		return info.Version
	}
}

func displayVersion() string {
	value := strings.TrimSpace(Version)
	if value == "" {
		return "dev"
	}
	return value
}
