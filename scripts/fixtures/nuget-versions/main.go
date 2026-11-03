// SPDX-License-Identifier: BUSL-1.1
// This owned test executable compares Go contracts with installed SDK libraries.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"unicode"

	"ctlplne.dev/cratectl/internal/nuget"
)

type row struct {
	Valid bool   `json:"valid"`
	Key   string `json:"key"`
}

type nuspecRow struct {
	Valid      bool   `json:"valid"`
	ID         string `json:"id"`
	VersionKey string `json:"version_key"`
}

type archiveRow struct {
	Valid      bool   `json:"valid"`
	ID         string `json:"id"`
	VersionKey string `json:"version_key"`
	NuspecPath string `json:"nuspec_path"`
	Nuspec     string `json:"nuspec"`
}

func emit(rows any) {
	identity := map[string]string{}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" || setting.Key == "vcs.modified" {
				identity[setting.Key] = setting.Value
			}
		}
	}
	if json.NewEncoder(os.Stdout).Encode(map[string]any{"os": runtime.GOOS, "architecture": runtime.GOARCH, "build": identity, "go_unicode_version": unicode.Version, "rows": rows}) != nil {
		panic("owned version oracle output failed")
	}
}

func main() {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, (2<<20)+1))
	var values []string
	caseLimit := 4096
	if len(os.Args) == 2 && os.Args[1] == "--id" {
		caseLimit = 65536
	}
	if err != nil || len(raw) > 2<<20 || json.Unmarshal(raw, &values) != nil || len(values) > caseLimit {
		panic("owned version oracle input is invalid")
	}
	if len(os.Args) == 2 && os.Args[1] == "--id" {
		rows := make([]row, 0, len(values))
		for _, value := range values {
			key, err := nuget.IDKey(value)
			rows = append(rows, row{Valid: err == nil, Key: key})
		}
		emit(rows)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--nuspec" {
		rows := make([]nuspecRow, 0, len(values))
		for _, value := range values {
			data, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				rows = append(rows, nuspecRow{})
				continue
			}
			identity, err := nuget.ParseNuspecIdentity(context.Background(), data)
			rows = append(rows, nuspecRow{Valid: err == nil, ID: identity.ID, VersionKey: identity.VersionKey})
		}
		emit(rows)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--archive" {
		rows := make([]archiveRow, 0, len(values))
		for _, value := range values {
			data, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				rows = append(rows, archiveRow{})
				continue
			}
			identity, err := nuget.InspectArchive(context.Background(), bytes.NewReader(data), int64(len(data)), nuget.ArchiveLimits{CompressedBytes: 2 << 20, ExpandedBytes: 4 << 20, DirectoryBytes: 128 << 10, Files: 64})
			rows = append(rows, archiveRow{Valid: err == nil, ID: identity.Identity.ID, VersionKey: identity.Identity.VersionKey, NuspecPath: identity.NuspecPath, Nuspec: base64.StdEncoding.EncodeToString(identity.Nuspec)})
		}
		emit(rows)
		return
	}
	rows := make([]row, 0, len(values))
	for _, value := range values {
		key, err := nuget.VersionKey(value)
		rows = append(rows, row{Valid: err == nil, Key: key})
	}
	emit(rows)
}
