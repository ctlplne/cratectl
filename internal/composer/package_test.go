// SPDX-License-Identifier: BUSL-1.1
package composer

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"testing"
)

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
