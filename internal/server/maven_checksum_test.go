// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"strings"
	"testing"
)

func TestMavenChecksumAliasesBindTheExactParent(t *testing.T) {
	for _, parent := range []string{"org/example/tool/1.0/tool-1.0.jar", "org/example/tool/maven-metadata.xml"} {
		for suffix, want := range map[string]string{
			"sha1": "sha1", "md5": "md5", "sha256": "sha256", "sha512": "sha512", "sha384": "sha384",
			"SHA-256": "sha256", "SHA-512": "sha512", "SHA-384": "sha384",
		} {
			t.Run(parent+"."+suffix, func(t *testing.T) {
				gotParent, gotAlgorithm := splitMavenChecksumPath(parent + "." + suffix)
				if gotParent != parent || gotAlgorithm != want {
					t.Fatalf("checksum URL escaped parent binding: parent=%q algorithm=%q want=%q/%q", gotParent, gotAlgorithm, parent, want)
				}
			})
		}
	}
	for _, p := range []string{"org/example/checksums.sha256/tool.jar", "tool.SHA256", "tool.sha-256", "tool.SHA-256/child", "maven-metadata.xml"} {
		if parent, algorithm := splitMavenChecksumPath(p); parent != p || algorithm != "" {
			t.Fatalf("undocumented checksum spelling changed an artifact path: %q", p)
		}
	}
}

func FuzzMavenChecksumParentBinding(f *testing.F) {
	for _, p := range []string{"g/a/1/a-1.jar.SHA-256", "g/a/maven-metadata.xml.SHA-384", "g/a/1/a-1.jar.sha512", "g/a/SHA-256/ordinary.jar"} {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, p string) {
		parent, algorithm := splitMavenChecksumPath(p)
		if algorithm == "" {
			if parent != p {
				t.Fatal("ordinary artifact path changed")
			}
			return
		}
		aliases := map[string][]string{"sha1": {"sha1"}, "md5": {"md5"}, "sha256": {"sha256", "SHA-256"}, "sha512": {"sha512", "SHA-512"}, "sha384": {"sha384", "SHA-384"}}
		for _, suffix := range aliases[algorithm] {
			if p == parent+"."+suffix && strings.HasSuffix(p, "."+suffix) {
				return
			}
		}
		t.Fatal("checksum changed more than its documented suffix")
	})
}
