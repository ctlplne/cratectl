// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"strings"
	"testing"
)

func TestMavenNonuniqueSnapshotPathDoesNotAdmitOtherCoordinates(t *testing.T) {
	base := "org/example/tool/1.0-SNAPSHOT/"
	for _, file := range []string{"tool-1.0-SNAPSHOT.jar", "tool-1.0-SNAPSHOT.pom", "tool-1.0-SNAPSHOT-sources.jar", "tool-1.0-SNAPSHOT-bin.tar.gz", "tool-1.0-SNAPSHOT.jar.asc"} {
		if !MavenNonuniqueSnapshotPath(base + file) {
			t.Fatal("base-version representation rejected", file)
		}
	}
	for _, p := range []string{
		"org/example/tool/1.0/tool-1.0.jar", base + "tool-1.0-20261104.170000-1.jar",
		base + "other-1.0-SNAPSHOT.jar", base + "tool-2.0-SNAPSHOT.jar", base + "tool-1.0-SNAPSHOT2.jar",
		base + "tool-1.0-SNAPSHOT-.jar", base + "tool-1.0-SNAPSHOT.", base + "maven-metadata.xml",
		base + "tool-1.0-SNAPSHOT.jar.sha256", base + "tool-1.0-SNAPSHOT.pom.SHA-512", base + "tool-1.0-SNAPSHOT.pom.md5",
		"/" + base + "tool-1.0-SNAPSHOT.jar", "../" + base + "tool-1.0-SNAPSHOT.jar", "org//example/tool/1.0-SNAPSHOT/tool-1.0-SNAPSHOT.jar",
		base + "tool-1.0-SNAPSHOT/a.jar", base + "tool-1.0-SNAPSHOT.%2fjar", base + "tool-1.0-SNAPSHOT.jar\n",
		base + "tool-1.0-SNAPSHOT.jar?token=value", base + "tool-1.0-SNAPSHOT.\\jar", base + "tool-1.0-SNAPSHOT." + strings.Repeat("j", 257),
	} {
		if MavenNonuniqueSnapshotPath(p) {
			t.Fatal("not an exact nonunique snapshot", p)
		}
	}
	classifier, extension, ok := MavenNonuniqueSnapshotFile("tool", "1.0-SNAPSHOT", "tool-1.0-SNAPSHOT-bin.tar.gz")
	if !ok || classifier != "bin" || extension != "tar.gz" {
		t.Fatal("compound extension/classifier", classifier, extension, ok)
	}
}

func TestMavenSnapshotRedeploymentRequiresExplicitHostedPolicy(t *testing.T) {
	for _, policy := range []string{"", "immutable", MavenSnapshotRedeployNonunique, "always", "REDEPLOY_NONUNIQUE"} {
		for _, format := range []string{"maven", "generic", "npm"} {
			r := Repository{Name: "proof", Format: format, Settings: RepositorySettings{MavenSnapshotPolicy: policy}}
			e := ValidateRepository(&r)
			want := policy == "" || format == "maven" && (policy == "immutable" || policy == MavenSnapshotRedeployNonunique)
			if (e == nil) != want {
				t.Fatalf("%s %s accepted=%v wanted=%v", format, policy, e == nil, want)
			}
		}
	}
	r := Repository{Name: "group", Format: "maven", Mode: "group", Settings: RepositorySettings{MavenSnapshotPolicy: MavenSnapshotRedeployNonunique, Members: []string{"source"}}}
	if ValidateRepository(&r) == nil {
		t.Fatal("group admitted a hosted publication policy")
	}
}

func FuzzMavenNonuniqueSnapshotPath(f *testing.F) {
	f.Add("org/example/tool/1.0-SNAPSHOT/tool-1.0-SNAPSHOT.jar")
	f.Add("org/example/tool/1.0-SNAPSHOT/tool-1.0-20261104.170000-1.jar")
	f.Fuzz(func(t *testing.T, p string) {
		if !MavenNonuniqueSnapshotPath(p) {
			return
		}
		parts := strings.Split(p, "/")
		artifact, version, filename := parts[len(parts)-3], parts[len(parts)-2], parts[len(parts)-1]
		classifier, extension, ok := MavenNonuniqueSnapshotFile(artifact, version, filename)
		if !ok || !strings.HasSuffix(version, "-SNAPSHOT") || len(p) > 2048 {
			t.Fatal("unbound snapshot admitted", p)
		}
		rebuilt := artifact + "-" + version
		if classifier != "" {
			rebuilt += "-" + classifier
		}
		if rebuilt+"."+extension != filename {
			t.Fatal("snapshot filename did not roundtrip", p)
		}
	})
}
