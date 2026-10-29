// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"ctlplne.dev/cratectl/internal/store"
	"encoding/xml"
	"testing"
	"time"
)

func TestMavenProxyHintsDoNotUseCacheDownloadTime(t *testing.T) {
	repo := store.Repository{Name: "remote", Mode: "proxy", Format: "maven"}
	member := store.MavenMember{Repository: repo, Artifacts: []store.Artifact{{Path: "org/example/tool/1.0/tool-1.0.pom", Decision: "allowed", Created: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}}}
	model := mavenMetadata{Group: "org.example", Artifact: "tool", Versioning: &mavenVersioning{Latest: "2.0", Release: "2.0", Versions: []string{"1.0", "2.0"}, Updated: "20261029120000"}}
	data, e := renderMavenMetadata(store.MavenView{Group: repo, Members: []store.MavenMember{member}}, []mavenDocument{{model, member}}, "org/example/tool/maven-metadata.xml", 100, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	var result mavenMetadata
	if e = xml.Unmarshal(data, &result); e != nil {
		t.Fatal(e)
	}
	if result.Versioning.Latest != "2.0" || result.Versioning.Release != "2.0" {
		t.Fatalf("cache download age replaced upstream hints: latest=%s release=%s; want 2.0", result.Versioning.Latest, result.Versioning.Release)
	}
}

func TestMavenProxyHintSourceOrderAndOptionalVersionList(t *testing.T) {
	first := store.Repository{Name: "first", Mode: "proxy", Format: "maven"}
	second := store.Repository{Name: "second", Mode: "proxy", Format: "maven"}
	group := store.Repository{Name: "group", Mode: "group", Settings: store.RepositorySettings{Members: []string{"first", "second"}}}
	left, right := store.MavenMember{Repository: first}, store.MavenMember{Repository: second}
	one := mavenMetadata{Group: "org.example", Artifact: "tool", Versioning: &mavenVersioning{Latest: "1.0", Release: "1.0", Updated: "20261029120000"}}
	two := mavenMetadata{Group: "org.example", Artifact: "tool", Versioning: &mavenVersioning{Latest: "2.0", Release: "2.0", Updated: "20261029120000"}}
	for _, newer := range []bool{false, true} {
		if newer {
			two.Versioning.Updated = "20261029120001"
		}
		data, e := renderMavenMetadata(store.MavenView{Group: group, Members: []store.MavenMember{left, right}}, []mavenDocument{{one, left}, {two, right}}, "org/example/tool/maven-metadata.xml", 100, 1<<20)
		if e != nil {
			t.Fatal(e)
		}
		var md mavenMetadata
		if e = xml.Unmarshal(data, &md); e != nil {
			t.Fatal(e)
		}
		expected := "1.0"
		if newer {
			expected = "2.0"
		}
		if md.Versioning.Latest != expected || md.Versioning.Release != expected || len(md.Versioning.Versions) != 2 {
			t.Fatal("source timestamp/precedence or optional list", string(data))
		}
	}
}
