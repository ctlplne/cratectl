// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"encoding/base64"
	"encoding/xml"

	"ctlplne.dev/cratectl/internal/nuget"
)

type dependencyProjectionRow struct {
	Valid      bool   `json:"valid"`
	Projection string `json:"projection"`
}

func dependencyProjections(values []string) []dependencyProjectionRow {
	rows := make([]dependencyProjectionRow, 0, len(values))
	for _, value := range values {
		raw, e := base64.StdEncoding.DecodeString(value)
		if e != nil {
			rows = append(rows, dependencyProjectionRow{})
			continue
		}
		parsed, e := nuget.ParseNuspecDependencies(context.Background(), raw)
		if e != nil {
			rows = append(rows, dependencyProjectionRow{})
			continue
		}
		type dependency struct {
			ID      string `xml:"id,attr"`
			Version string `xml:"version,attr,omitempty"`
			Include string `xml:"include,attr,omitempty"`
			Exclude string `xml:"exclude,attr,omitempty"`
		}
		type group struct {
			Framework string       `xml:"targetFramework,attr,omitempty"`
			Items     []dependency `xml:"dependency"`
		}
		var output struct {
			XMLName  xml.Name `xml:"package"`
			Metadata struct {
				ID      string  `xml:"id"`
				Version string  `xml:"version"`
				Groups  []group `xml:"dependencies>group"`
			} `xml:"metadata"`
		}
		output.Metadata.ID, output.Metadata.Version = parsed.Identity.ID, parsed.Identity.RawVersion
		for _, selected := range parsed.Groups {
			g := group{Framework: selected.TargetFramework}
			for _, d := range selected.Dependencies {
				g.Items = append(g.Items, dependency{d.ID, d.RawRange, d.Include, d.Exclude})
			}
			output.Metadata.Groups = append(output.Metadata.Groups, g)
		}
		encoded, e := xml.Marshal(output)
		if e != nil {
			rows = append(rows, dependencyProjectionRow{})
			continue
		}
		rows = append(rows, dependencyProjectionRow{true, base64.StdEncoding.EncodeToString(encoded)})
	}
	return rows
}
