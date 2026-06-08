package buildinfo

import "fmt"

// Version is the release version injected at build time.
var Version = "dev"

// Commit is the short Git commit injected at build time.
var Commit = "unknown"

// BuiltAt is the build timestamp injected at build time.
var BuiltAt = "unknown"

// Info describes the application build metadata.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	BuiltAt string `json:"builtAt"`
}

// Current returns the build metadata for this binary.
func Current() Info {
	return Info{
		Version: Version,
		Commit:  Commit,
		BuiltAt: BuiltAt,
	}
}

// String formats the build metadata for command-line output.
func String() string {
	info := Current()
	return fmt.Sprintf("EmbyProxy %s (%s, built %s)", info.Version, info.Commit, info.BuiltAt)
}
