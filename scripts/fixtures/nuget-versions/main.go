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

type comparisonRow struct {
	Valid bool `json:"valid"`
	Order int  `json:"order"`
}

type propertyRow struct {
	Valid  bool              `json:"valid"`
	Values map[string]string `json:"values"`
}

type rangeRow struct {
	Valid          bool                    `json:"valid"`
	Info           *nuget.VersionRangeInfo `json:"info"`
	VersionValid   bool                    `json:"version_valid"`
	Satisfies      bool                    `json:"satisfies"`
	FloatSatisfies bool                    `json:"float_satisfies"`
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
	if json.NewEncoder(os.Stdout).Encode(map[string]any{"os": runtime.GOOS, "architecture": runtime.GOARCH, "build": identity, "go_unicode_version": unicode.Version, "id_profile": nuget.IDKeyProfile, "rows": rows}) != nil {
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
	if len(os.Args) == 2 && os.Args[1] == "--range" {
		rows := make([]rangeRow, 0, len(values))
		for _, value := range values {
			var pair []string
			if json.Unmarshal([]byte(value), &pair) != nil || len(pair) != 2 {
				rows = append(rows, rangeRow{})
				continue
			}
			r, e := nuget.ParseVersionRange(pair[0])
			if e != nil {
				rows = append(rows, rangeRow{})
				continue
			}
			info := r.Info()
			_, e = nuget.VersionKey(pair[1])
			satisfies, _ := r.Satisfies(pair[1])
			floating, _ := r.FloatSatisfies(pair[1])
			rows = append(rows, rangeRow{true, &info, e == nil, satisfies, floating})
		}
		emit(rows)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--compare" {
		rows := make([]comparisonRow, 0, len(values))
		for _, value := range values {
			var pair []string
			if json.Unmarshal([]byte(value), &pair) != nil || len(pair) != 2 {
				rows = append(rows, comparisonRow{})
				continue
			}
			order, e := nuget.CompareVersions(pair[0], pair[1])
			rows = append(rows, comparisonRow{Valid: e == nil, Order: order})
		}
		emit(rows)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--properties" {
		rows := make([]propertyRow, 0, len(values))
		for _, value := range values {
			data, e := base64.StdEncoding.DecodeString(value)
			if e != nil {
				rows = append(rows, propertyRow{Values: map[string]string{}})
				continue
			}
			properties, e := nuget.ParseNuspecProperties(context.Background(), data)
			if e != nil {
				properties.Values = map[string]string{}
			}
			rows = append(rows, propertyRow{Valid: e == nil, Values: properties.Values})
		}
		emit(rows)
		return
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
