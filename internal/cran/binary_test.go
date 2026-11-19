// SPDX-License-Identifier: BUSL-1.1
package cran

import "testing"

func TestBinaryChannelBindsNativeCoordinatesAndBuiltMetadata(t *testing.T) {
	for _, row := range []struct {
		directory, extension, built string
		requiresCompilation         bool
		valid                       bool
	}{
		{"bin/macosx/sonoma-arm64/contrib/4.6/", ".tgz", "R 4.6.2; aarch64-apple-darwin23; owned date; unix", true, true},
		{"bin/macosx/big-sur-arm64/contrib/4.5/", ".tgz", "R 4.5.3; ; owned date; unix", false, true},
		{"bin/macosx/big-sur-x86_64/contrib/4.6/", ".tgz", "R 4.6.1; x86_64-apple-darwin20.0; owned date; unix", true, true},
		{"bin/windows/contrib/4.6/", ".zip", "R 4.6.0; x86_64-w64-mingw32; owned date; windows", true, true},
		{"bin/windows/contrib/4.6/", ".zip", "R 4.6.0; ; owned date; windows", false, true},
		{"bin/windows/contrib/4.6/", ".zip", "R 4.5.3; ; owned date; windows", false, false},
		{"bin/windows/contrib/4.6/", ".zip", "R 4.6.0; ; owned date; unix", false, false},
		{"bin/windows/contrib/4.6/", ".zip", "R 4.6.0; ; owned date; windows", true, false},
		{"bin/macosx/sonoma-arm64/contrib/4.6/", ".tgz", "R 4.6.2; x86_64-apple-darwin20; owned date; unix", true, false},
	} {
		path := row.directory + "CratectlBinary_1.2-3" + row.extension
		channel, coordinate, ok := ParseBinaryPath(path)
		if !ok || coordinate.Name != "CratectlBinary" || coordinate.Version != "1.2-3" {
			t.Fatal("did not parse exact binary coordinate", path)
		}
		metadata := Package{}
		if row.requiresCompilation {
			metadata["NeedsCompilation"] = "yes"
		}
		if valid := channel.ValidBuilt(row.built, metadata); valid != row.valid {
			t.Errorf("%s with Built %q returned %v", path, row.built, valid)
		}
	}
	for _, path := range []string{
		"bin/macosx/sonoma-arm64/contrib/4.6.2/CratectlBinary_1.0.tgz",
		"bin/macosx/other/contrib/4.6/CratectlBinary_1.0.tgz",
		"bin/macosx/sonoma-arm64/contrib/4.6/CratectlBinary_1.0.zip",
		"bin/windows/contrib/4.06/CratectlBinary_1.0.zip",
		"bin/windows/contrib/4.6/other/CratectlBinary_1.0.zip",
		"bin/windows/contrib/4.6/CratectlBinary_1.0.tgz",
	} {
		if _, _, ok := ParseBinaryPath(path); ok {
			t.Errorf("accepted unsupported binary coordinate %s", path)
		}
	}
}
