// SPDX-License-Identifier: BUSL-1.1
package configfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigurationRejectsUnsafeOrAmbiguousInput(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "config.json")
	for _, s := range []string{`{"version":1,"url":"https://localhost","token_file":"x","owner_database_dsn":"secret"}`, `{"version":1} {}`, `null`} {
		if e := os.WriteFile(p, []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
		var c Client
		e := Read(p, &c)
		// Null is structurally JSON; the caller rejects its zero version.
		if e == nil && c.Version != 0 {
			t.Fatal("accepted unknown fields or trailing JSON")
		}
	}
	if e := os.WriteFile(p, []byte(`{"version":1}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadBytes(p, 1, true); e == nil {
		t.Fatal("oversized configuration accepted")
	}
	if e := os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadBytes(p, 100, true); e == nil {
		t.Fatal("public credential configuration accepted")
	}
	link := filepath.Join(d, "link")
	if e := os.Symlink(p, link); e == nil {
		if _, e = ReadBytes(link, 100, false); e == nil {
			t.Fatal("configuration symlink accepted")
		}
	}
}
