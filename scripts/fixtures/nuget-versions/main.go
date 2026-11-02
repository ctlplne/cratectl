// SPDX-License-Identifier: BUSL-1.1
// This owned test executable compares the Go contract with NuGet.Versioning.
package main

import (
	"encoding/json"
	"io"
	"os"
	"runtime"
	"runtime/debug"

	"ctlplne.dev/cratectl/internal/nuget"
)

type row struct {
	Valid bool   `json:"valid"`
	Key   string `json:"key"`
}

func main() {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, (2<<20)+1))
	var values []string
	if err != nil || len(raw) > 2<<20 || json.Unmarshal(raw, &values) != nil || len(values) > 4096 {
		panic("owned version oracle input is invalid")
	}
	rows := make([]row, 0, len(values))
	for _, value := range values {
		key, err := nuget.VersionKey(value)
		rows = append(rows, row{Valid: err == nil, Key: key})
	}
	identity := map[string]string{}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" || setting.Key == "vcs.modified" {
				identity[setting.Key] = setting.Value
			}
		}
	}
	if json.NewEncoder(os.Stdout).Encode(map[string]any{"os": runtime.GOOS, "architecture": runtime.GOARCH, "build": identity, "rows": rows}) != nil {
		panic("owned version oracle output failed")
	}
}
