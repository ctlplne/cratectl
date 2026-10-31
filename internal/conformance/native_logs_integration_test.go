//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package conformance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func nativeClientEnvironment() []string {
	values := []string{}
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "CRATECTL_OWNER_DSN=") && !strings.HasPrefix(value, "CRATECTL_DSN=") {
			values = append(values, value)
		}
	}
	return values
}

// Raw native output is evidence, including on a failed test. testing.T.TempDir
// removes it during cleanup, so keep it under the owned private evidence root.
func retainedNativeDir(t *testing.T) string {
	t.Helper()
	root, e := filepath.Abs("../../.private/native-client-integration")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll(root, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	name, e := os.MkdirTemp(root, "cratectl-"+strings.ReplaceAll(t.Name(), "/", "-")+"-")
	if e != nil {
		t.Fatal(e)
	}
	t.Log("Retained native fixture directory:", name)
	return name
}

func retainNativeOutput(t *testing.T, directory string, output []byte) {
	t.Helper()
	file, e := os.CreateTemp(directory, "command-*.log")
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	if _, e = file.Write(output); e != nil {
		t.Fatal(e)
	}
	if e = file.Sync(); e != nil {
		t.Fatal(e)
	}
	t.Log("Native command output retained:", file.Name())
}
