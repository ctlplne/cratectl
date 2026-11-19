// SPDX-License-Identifier: BUSL-1.1
package composer

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"testing"
)

func TestDistributionNormalizesTaggedAndDevelopmentVersions(t *testing.T) {
	for _, entry := range []struct {
		version, manifest, normalized string
		development                   bool
	}{
		{"1.2.3", "v1.2.3", "1.2.3.0", false},
		{"1.2.3-alpha1", "v1.2.3-alpha1", "1.2.3.0-alpha1", false},
		{"1.2.3-beta2", "1.2.3-BETA2", "1.2.3.0-beta2", false},
		{"1.2.3-rc3", "v1.2.3-RC3", "1.2.3.0-RC3", false},
		{"dev-fixture", "dev-fixture", "dev-fixture", true},
	} {
		published := "dist/cratectl/library/" + entry.version + ".zip"
		coordinate, ok := ParseDistribution(published)
		if !ok || coordinate.Path() != published || coordinate.NormalizedVersion() != entry.normalized ||
			coordinate.Development() != entry.development || !(Package{Name: coordinate.Name, Version: entry.manifest}).ValidFor(coordinate) {
			t.Fatalf("Composer identity disagrees with the supported version %q: %+v", entry.version, coordinate)
		}
	}
	for _, version := range []string{"v1.2.3", "1.2.3-rc03", "1.2.3-beta.1", "1.2.3-preview1", "1.2.3-dev", "dev-Fixture", "dev-branch/other"} {
		if _, ok := ParseDistribution("dist/cratectl/library/" + version + ".zip"); ok {
			t.Fatalf("accepted a noncanonical publication path for %q", version)
		}
	}
}

func TestInspectBindsOnlyOneComposerLibraryManifest(t *testing.T) {
	coordinate := Coordinate{Name: "cratectl/app", Version: "1.2.3"}
	const good = `{"name":"cratectl/app","version":"v1.2.3","require":{"php":">=8.2","cratectl/lib":"^1.0"},"autoload":{"psr-4":{"Cratectl\\":"src/"}}}`
	for _, tc := range []struct {
		label, manifest, filename, other string
		valid                            bool
	}{
		{label: "root", manifest: good, filename: "composer.json", other: "src/file.php", valid: true},
		{label: "wrapper", manifest: good, filename: "owned/composer.json", other: "owned/src/file.php", valid: true},
		{label: "mixed wrapper", manifest: good, filename: "owned/composer.json", other: "src/file.php"},
		{label: "ambiguous manifest", manifest: good, filename: "composer.json", other: "child/composer.json"},
		{label: "coordinate mismatch", manifest: `{"name":"cratectl/app","version":"1.2.4"}`, filename: "composer.json"},
		{label: "duplicate dependencies", manifest: `{"name":"cratectl/app","require":{"cratectl/lib":"^1","cratectl/lib":"^2"}}`, filename: "composer.json"},
		{label: "unsupported package type", manifest: `{"name":"cratectl/app","type":"composer-plugin"}`, filename: "composer.json"},
		{label: "outside autoload", manifest: `{"name":"cratectl/app","autoload":{"files":["../outside.php"]}}`, filename: "composer.json"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			var raw bytes.Buffer
			writer := zip.NewWriter(&raw)
			items := map[string]string{tc.filename: tc.manifest}
			if tc.other != "" {
				items[tc.other] = "owned inert content"
			}
			for name, data := range items {
				file, err := writer.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(file, data); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := Inspect(context.Background(), bytes.NewReader(raw.Bytes()), int64(raw.Len()), coordinate)
			if !tc.valid {
				if err == nil || got.Name != "" {
					t.Fatal("accepted an invalid package identity", got, err)
				}
			} else if err != nil || got.Name != coordinate.Name || got.Version != coordinate.Version || got.Type != "library" ||
				got.Require["cratectl/lib"] != "^1.0" || got.Autoload == nil || len(got.Autoload.PSR4[`Cratectl\`]) != 1 {
				t.Fatal("lost native Composer metadata", got, err)
			}
		})
	}
}
