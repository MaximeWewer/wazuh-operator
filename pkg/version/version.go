/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package version provides version information for the operator
package version

import (
	"fmt"
	"runtime"
)

// Version information set at build time
var (
	// Version is the operator version
	Version = "0.0.0-dev"

	// GitCommit is the git commit hash
	GitCommit = "unknown"

	// GitTreeState is the git tree state (clean/dirty)
	GitTreeState = "unknown"

	// BuildDate is the build date
	BuildDate = "unknown"
)

// Info holds the version information
type Info struct {
	Version      string `json:"version"`
	GitCommit    string `json:"gitCommit"`
	GitTreeState string `json:"gitTreeState"`
	BuildDate    string `json:"buildDate"`
	GoVersion    string `json:"goVersion"`
	Compiler     string `json:"compiler"`
	Platform     string `json:"platform"`
}

// Get returns the version info
func Get() Info {
	return Info{
		Version:      Version,
		GitCommit:    GitCommit,
		GitTreeState: GitTreeState,
		BuildDate:    BuildDate,
		GoVersion:    runtime.Version(),
		Compiler:     runtime.Compiler,
		Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// String returns the version as a string
func (i Info) String() string {
	return fmt.Sprintf(
		"Version: %s, GitCommit: %s, GitTreeState: %s, BuildDate: %s, GoVersion: %s, Platform: %s",
		i.Version, i.GitCommit, i.GitTreeState, i.BuildDate, i.GoVersion, i.Platform,
	)
}

// Short returns a short version string
func (i Info) Short() string {
	return fmt.Sprintf("%s (%s)", i.Version, i.GitCommit[:7])
}
