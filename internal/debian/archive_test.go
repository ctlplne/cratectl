// SPDX-License-Identifier: BUSL-1.1
package debian

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const exampleControl = `Package: cratectl-example
Version: 2:1.0~rc1-2+b1
Architecture: arm64
Maintainer: cratectl owned fixture
Depends: cratectl-data (>= 1.0),
 cratectl-reserve | cratectl-alternative
Description: Owned package fixture
 The inert data are used for a stock dependency fixture.
 .
 No package program is executed.
`

func debFixture(t *testing.T, stanza string, compressed bool) []byte {
	t.Helper()
	var inner bytes.Buffer
	archive := tar.NewWriter(&inner)
	for _, entry := range []struct{ name, body string }{
		{"./control", stanza},
		{"./postinst", "Opaque maintainer data in the archive fixture.\n"},
	} {
		if err := archive.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o644, Size: int64(len(entry.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	control := inner.Bytes()
	name := "control.tar"
	if compressed {
		var buffer bytes.Buffer
		zip := gzip.NewWriter(&buffer)
		if _, err := zip.Write(control); err != nil {
			t.Fatal(err)
		}
		if err := zip.Close(); err != nil {
			t.Fatal(err)
		}
		control, name = buffer.Bytes(), "control.tar.gz"
	}
	var raw bytes.Buffer
	raw.WriteString("!<arch>\n")
	for _, entry := range []struct {
		name string
		data []byte
	}{{"debian-binary", []byte("2.0\n")}, {name, control}, {"data.tar", make([]byte, 1024)}} {
		fmt.Fprintf(&raw, "%-16s%-12d%-6d%-6d%-8d%-10d`\n", entry.name, 0, 0, 0, 644, len(entry.data))
		raw.Write(entry.data)
		if len(entry.data)%2 != 0 {
			raw.WriteByte('\n')
		}
	}
	return raw.Bytes()
}

func TestInspectPreservesDebianControlIdentityAndDependencies(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		archive := debFixture(t, exampleControl, compressed)
		control, err := Inspect(context.Background(), bytes.NewReader(archive), int64(len(archive)))
		if err != nil || control != (Control{Package: "cratectl-example", Version: "2:1.0~rc1-2+b1", Architecture: "arm64", Stanza: exampleControl}) {
			t.Fatal("failed to preserve the bounded binary package control stanza", control, err)
		}
		if _, err := Inspect(context.Background(), bytes.NewReader(archive[:len(archive)-1]), int64(len(archive)-1)); !errors.Is(err, ErrArchive) {
			t.Fatal("accepted a shortened data member", err)
		}
	}
}

func TestControlRejectsAmbiguousIdentityAndIndexFields(t *testing.T) {
	for _, extra := range []string{"package: cratectl-duplicate\n", "Filename: pool/other.deb\n", "SHA256: caller-provided\n", "\nX-Custom: second stanza\n"} {
		if _, err := ParseControl([]byte(exampleControl + extra)); !errors.Is(err, ErrControl) {
			t.Fatal("accepted ambiguous control fields", extra, err)
		}
	}
	for _, version := range []string{"0.1", "1.0+what~1-3", "1:2.0+dfsg-1~bpo12+1", "4:1.2:3-1"} {
		if !ValidVersion(version) {
			t.Fatal("refused a canonical Debian version", version)
		}
	}
	for _, version := range []string{"1.0/2", "not-a-version", "1.0-", "v:2.0", "1.0:2", "1:2-3_4", strings.Repeat("1", 257)} {
		if ValidVersion(version) {
			t.Fatal("accepted an invalid Debian version", version)
		}
	}
}
