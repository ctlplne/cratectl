// SPDX-License-Identifier: BUSL-1.1
package composer

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestComposerCatalogExpandsBoundMetadataAndRejectsAmbiguity(t *testing.T) {
	const name = "cratectl/library"
	digest := strings.Repeat("a", 64)
	dist := fmt.Sprintf(`{"type":"zip","url":"https://archive.example/owned.zip","sha256":%q}`, digest)
	raw := fmt.Sprintf(`{"minified":"composer/2.0","packages":{%q:[
{"name":%q,"version":"v1.2.3","version_normalized":"1.2.3.0","dist":%s,"require":{"php":"^8.3"}},
{"version":"1.2.4-rc2","version_normalized":"1.2.4.0-RC2","require":"__unset"}
]}}`, name, name, dist)
	entries, err := ParseCatalog(context.Background(), []byte(raw), name, false, 10, CatalogBytes)
	if err != nil || len(entries) != 2 || entries[0].Package.Version != "1.2.3" || entries[0].Package.Require["php"] != "^8.3" ||
		entries[1].Package.Version != "1.2.4-rc2" || entries[1].Package.Require != nil || entries[1].SHA256 != digest {
		t.Fatal("incorrect bounded Composer metadata expansion", entries, err)
	}
	for label, data := range map[string]string{
		"wrong package":            strings.Replace(raw, `"name":"cratectl/library"`, `"name":"cratectl/other"`, 1),
		"duplicate version":        strings.ReplaceAll(strings.ReplaceAll(raw, "1.2.4-rc2", "1.2.3"), "1.2.4.0-RC2", "1.2.3.0"),
		"duplicate key":            strings.Replace(raw, `"require":"__unset"`, `"require":"__unset","require":"__unset"`, 1),
		"wrong normalization":      strings.Replace(raw, "1.2.4.0-RC2", "1.2.4.0", 1),
		"query locator":            strings.Replace(raw, "owned.zip", "owned.zip?credential=owned-fixture", 1),
		"conflicting provider set": strings.Replace(raw, `]}}`, `],"cratectl/other":[]}}`, 1),
	} {
		t.Run(label, func(t *testing.T) {
			if read, err := ParseCatalog(context.Background(), []byte(data), name, false, 10, CatalogBytes); err == nil || read != nil {
				t.Fatal("accepted inconsistent Composer metadata", read, err)
			}
		})
	}
	if _, err := ParseCatalog(context.Background(), []byte(raw), name, false, 1, CatalogBytes); err == nil {
		t.Fatal("Composer metadata bypassed the version count")
	}
	if _, err := ParseCatalog(context.Background(), []byte(raw), name, false, 10, int64(len(raw)-1)); err == nil {
		t.Fatal("Composer metadata bypassed the byte limit")
	}
}
