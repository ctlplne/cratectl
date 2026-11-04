// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/xml"
	"errors"
	"strings"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/store"
)

func TestMavenMetadataRejectsAmbiguousOrUnboundXML(t *testing.T) {
	p := "org/example/tool/maven-metadata.xml"
	valid := `<metadata><groupId>org.example</groupId><artifactId>tool</artifactId><versioning><versions><version>1.0</version></versions><lastUpdated>20261029120000</lastUpdated></versioning></metadata>`
	if _, e := parseMavenMetadata([]byte(valid), p, 100, 1<<20); e != nil {
		t.Fatal(e)
	}
	for name, data := range map[string]string{
		"coordinate":             strings.Replace(valid, "org.example", "org.other", 1),
		"external entity":        `<!DOCTYPE metadata [<!ENTITY e SYSTEM "file:///etc/passwd">]>` + valid,
		"duplicate scalar":       strings.Replace(valid, "<artifactId>tool</artifactId>", "<artifactId>tool</artifactId><artifactId>other</artifactId>", 1),
		"duplicate version":      strings.Replace(valid, "<version>1.0</version>", "<version>1.0</version><version>1.0</version>", 1),
		"multiple roots":         valid + valid,
		"namespace substitution": strings.Replace(valid, "<metadata>", `<metadata xmlns="https://untrusted.invalid/">`, 1),
		"path in version":        strings.Replace(valid, "<version>1.0</version>", "<version>../elsewhere</version>", 1),
		"invalid date":           strings.Replace(valid, "20261029120000", "20261399120000", 1),
		"nested leaf":            strings.Replace(valid, "<version>1.0</version>", "<version><value>1.0</value></version>", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := parseMavenMetadata([]byte(data), p, 100, 1<<20); e == nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
	if _, e := parseMavenMetadata([]byte(valid), p, 100, 32); !errors.Is(e, store.ErrMetadataLimit) {
		t.Fatal("byte budget", e)
	}
	if _, e := parseMavenMetadata([]byte(strings.Replace(valid, "<version>1.0</version>", "<version>1.0</version><version>2.0</version>", 1)), p, 1, 1<<20); !errors.Is(e, store.ErrMetadataLimit) {
		t.Fatal("record budget", e)
	}
}

func TestMavenSnapshotBindingAndNumericCounter(t *testing.T) {
	p := "org/example/tool/1.0-SNAPSHOT/maven-metadata.xml"
	valid := `<metadata><groupId>org.example</groupId><artifactId>tool</artifactId><version>1.0-SNAPSHOT</version><versioning><snapshot><timestamp>20261029.120000</timestamp><buildNumber>10</buildNumber></snapshot><snapshotVersions><snapshotVersion><extension>jar</extension><classifier>sources</classifier><value>1.0-20261029.120000-10</value><updated>20261029120000</updated></snapshotVersion></snapshotVersions></versioning></metadata>`
	if _, e := parseMavenMetadata([]byte(valid), p, 100, 1<<20); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"2.0-20261029.120000-10", "1.0-20261399.120000-10", "1.0-20261029.120000-0", "../elsewhere", "1.0-20261029.120000-99999999999999"} {
		if _, e := parseMavenMetadata([]byte(strings.Replace(valid, "<value>1.0-20261029.120000-10</value>", "<value>"+bad+"</value>", 1)), p, 100, 1<<20); e == nil {
			t.Fatal("snapshot binding", bad)
		}
	}
	a, ok := snapshotFilename("tool", "1.0-SNAPSHOT", "tool-1.0-20261029.120000-10-sources.jar")
	if !ok || a.Classifier != "sources" || a.Extension != "jar" {
		t.Fatal(a, ok)
	}
	b, ok := snapshotFilename("tool", "1.0-SNAPSHOT", "tool-1.0-20261029.120000-9-sources.jar")
	if !ok || !mavenSnapshotNewer(a, b) {
		t.Fatal("build 10 did not follow 9")
	}
}

func TestMavenNonuniqueSnapshotDiscoveryUsesCurrentReferences(t *testing.T) {
	when := time.Date(2026, 11, 4, 17, 0, 0, 0, time.UTC)
	repo := store.Repository{Name: "snapshots", Format: "maven", Mode: "hosted"}
	member := store.MavenMember{Repository: repo}
	for _, suffix := range []string{".pom", ".jar", "-sources.jar"} {
		member.Artifacts = append(member.Artifacts, store.Artifact{Repository: repo.Name, Path: "org/example/tool/1.0-SNAPSHOT/tool-1.0-SNAPSHOT" + suffix, Decision: "allowed", Created: when})
	}
	view := store.MavenView{Group: repo, Members: []store.MavenMember{member}}
	for _, version := range []string{"", "1.0-SNAPSHOT"} {
		model := mavenMetadata{Group: "org.example", Artifact: "tool", Version: version}
		p := "org/example/tool/"
		if version != "" {
			p += version + "/"
		}
		data, e := renderMavenMetadata(view, []mavenDocument{{model, member}}, p+"maven-metadata.xml", 100, 1<<20)
		if e != nil {
			t.Fatal("stored nonunique snapshot is absent from native discovery", version, e)
		}
		var result mavenMetadata
		if e = xml.Unmarshal(data, &result); e != nil {
			t.Fatal(e)
		}
		v := result.Versioning
		if version == "" {
			if strings.Join(v.Versions, ",") != "1.0-SNAPSHOT" || v.Latest != "1.0-SNAPSHOT" || v.Release != "" {
				t.Fatal("artifact discovery lost base-version POM", string(data))
			}
		} else {
			if v.Snapshot == nil || !v.Snapshot.Local || v.Snapshot.Timestamp != "" || v.Snapshot.Build != 0 || len(v.Snapshots) != 3 {
				t.Fatal("nonunique snapshot mapping differs", string(data))
			}
			for _, entry := range v.Snapshots {
				if entry.Value != version || entry.Updated != "20261104170000" {
					t.Fatal("mapping does not identify current base-version bytes", entry)
				}
			}
		}
	}
}

func TestMavenNonuniqueSnapshotsDoNotFallThroughBlockedFirstSource(t *testing.T) {
	first := store.Repository{Name: "first", Format: "maven", Mode: "hosted"}
	second := store.Repository{Name: "second", Format: "maven", Mode: "hosted"}
	group := store.Repository{Name: "group", Format: "maven", Mode: "group", Settings: store.RepositorySettings{Members: []string{"first", "second"}}}
	when := time.Date(2026, 11, 4, 17, 0, 0, 0, time.UTC)
	for _, version := range []string{"", "1.0-SNAPSHOT"} {
		members := []store.MavenMember{}
		for _, r := range []store.Repository{first, second} {
			member := store.MavenMember{Repository: r}
			for _, ext := range []string{"pom", "jar"} {
				decision := "allowed"
				if r.Name == "first" && (ext == "jar" || version == "") {
					decision = "denied"
				}
				member.Artifacts = append(member.Artifacts, store.Artifact{Repository: r.Name, Path: "org/example/tool/1.0-SNAPSHOT/tool-1.0-SNAPSHOT." + ext, Decision: decision, Created: when})
			}
			members = append(members, member)
			when = when.Add(time.Minute)
		}
		model := mavenMetadata{Group: "org.example", Artifact: "tool", Version: version}
		p := "org/example/tool/"
		if version != "" {
			p += version + "/"
		}
		data, e := renderMavenMetadata(store.MavenView{Group: group, Members: members}, []mavenDocument{{model, members[0]}, {model, members[1]}}, p+"maven-metadata.xml", 100, 1<<20)
		if version == "" {
			if !errors.Is(e, store.ErrNotFound) {
				t.Fatal("lower-source POM replaced denied first version", string(data), e)
			}
			continue
		}
		var result mavenMetadata
		if e != nil || xml.Unmarshal(data, &result) != nil || len(result.Versioning.Snapshots) != 1 || result.Versioning.Snapshots[0].Extension != "pom" {
			t.Fatal("lower-source JAR replaced denied first snapshot", string(data), e)
		}
	}
}

func TestMavenMergePolicyOwnershipAndStableBytes(t *testing.T) {
	p := "org/example/tool/maven-metadata.xml"
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	first := store.Repository{Name: "first", Format: "maven", Mode: "hosted"}
	second := store.Repository{Name: "second", Format: "maven", Mode: "hosted"}
	group := store.Repository{Name: "group", Format: "maven", Mode: "group", Settings: store.RepositorySettings{Members: []string{"first", "second"}}}
	artifact := func(repo, version, decision string, when time.Time) store.Artifact {
		return store.Artifact{Repository: repo, Path: "org/example/tool/" + version + "/tool-" + version + ".pom", Decision: decision, Created: when}
	}
	left := store.MavenMember{Repository: first, Artifacts: []store.Artifact{artifact("first", "1.0", "allowed", now), artifact("first", "2.0", "denied", now)}}
	right := store.MavenMember{Repository: second, Artifacts: []store.Artifact{artifact("second", "2.0", "allowed", now.Add(time.Second)), artifact("second", "3.0", "allowed", now.Add(2*time.Second))}}
	view := store.MavenView{Group: group, Members: []store.MavenMember{left, right}}
	model := mavenMetadata{Group: "org.example", Artifact: "tool"}
	docs := []mavenDocument{{model, left}, {model, right}}
	data, e := renderMavenMetadata(view, docs, p, 100, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	var result mavenMetadata
	if e = xml.Unmarshal(data, &result); e != nil {
		t.Fatal(e)
	}
	if strings.Join(result.Versioning.Versions, ",") != "1.0,3.0" || result.Versioning.Latest != "3.0" || result.Versioning.Release != "3.0" {
		t.Fatal(string(data))
	}
	for n := 0; n < 20; n++ {
		again, e := renderMavenMetadata(view, docs, p, 100, 1<<20)
		if e != nil || string(again) != string(data) {
			t.Fatal("unstable metadata", e)
		}
	}
	view.Group.Settings.NamespaceOwners = map[string]string{"org/example/tool/3.0/": "first"}
	data, e = renderMavenMetadata(view, docs, p, 100, 1<<20)
	if e != nil || strings.Contains(string(data), "3.0") {
		t.Fatal("owned missing version fell through", string(data), e)
	}
	if _, e = renderMavenMetadata(view, docs, p, 1, 1<<20); !errors.Is(e, store.ErrMetadataLimit) {
		t.Fatal("aggregate record budget", e)
	}
}

func FuzzMavenMetadata(f *testing.F) {
	f.Add([]byte(`<metadata><groupId>org.example</groupId><artifactId>tool</artifactId><versioning><versions><version>1.0</version></versions></versioning></metadata>`))
	f.Add([]byte(`<!DOCTYPE metadata SYSTEM "https://example.invalid/entity"><metadata/>`))
	f.Add([]byte(`<metadata><groupId>org.example</groupId><artifactId>tool</artifactId><version>1.0-SNAPSHOT</version><versioning><snapshotVersions><snapshotVersion><extension>jar</extension><value>1.0-20261029.120000-1</value><updated>20261029120000</updated></snapshotVersion></snapshotVersions></versioning></metadata>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, p := range []string{"org/example/tool/maven-metadata.xml", "org/example/tool/1.0-SNAPSHOT/maven-metadata.xml"} {
			md, e := parseMavenMetadata(data, p, 100, 16384)
			if e != nil {
				continue
			}
			repo := store.Repository{Name: "fuzz", Format: "maven", Mode: "proxy"}
			member := store.MavenMember{Repository: repo}
			encoded, e := renderMavenMetadata(store.MavenView{Group: repo, Members: []store.MavenMember{member}}, []mavenDocument{{md, member}}, p, 100, 16384)
			if errors.Is(e, store.ErrNotFound) || errors.Is(e, store.ErrMetadataLimit) {
				continue
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = parseMavenMetadata(encoded, p, 100, 16384); e != nil {
				t.Fatalf("rendered native metadata does not parse: %v", e)
			}
		}
	})
}

func TestMavenPluginPrefixMergeKeepsDeniedAuthority(t *testing.T) {
	first := store.MavenMember{Repository: store.Repository{Name: "first", Mode: "hosted"}, Artifacts: []store.Artifact{{Path: "org/example/first-plugin/1/first-plugin-1.pom", Decision: "denied"}}}
	second := store.MavenMember{Repository: store.Repository{Name: "second", Mode: "hosted"}, Artifacts: []store.Artifact{{Path: "org/example/second-plugin/1/second-plugin-1.pom", Decision: "allowed"}}}
	group := store.Repository{Name: "group", Mode: "group", Settings: store.RepositorySettings{Members: []string{"first", "second"}}}
	docs := []mavenDocument{{mavenMetadata{Plugins: []mavenPlugin{{Name: "First", Prefix: "shared", Artifact: "first-plugin"}}}, first}, {mavenMetadata{Plugins: []mavenPlugin{{Name: "Second", Prefix: "shared", Artifact: "second-plugin"}, {Name: "Unique", Prefix: "unique", Artifact: "second-plugin"}}}, second}}
	data, e := renderMavenMetadata(store.MavenView{Group: group, Members: []store.MavenMember{first, second}}, docs, "org/example/maven-metadata.xml", 100, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	var md mavenMetadata
	if e = xml.Unmarshal(data, &md); e != nil || len(md.Plugins) != 1 || md.Plugins[0].Prefix != "unique" {
		t.Fatal("denied plugin replaced by lower source", string(data), e)
	}
}

func TestMavenSnapshotPOMVisibilityUsesNativeBuildOrder(t *testing.T) {
	when := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	r := store.Repository{Name: "snapshots", Mode: "hosted"}
	m := store.MavenMember{Repository: r, Artifacts: []store.Artifact{
		{Path: "org/example/tool/1.0-SNAPSHOT/tool-1.0-20261029.120000-10.pom", Decision: "allowed", Created: when},
		{Path: "org/example/tool/1.0-SNAPSHOT/tool-1.0-20261029.120000-9.pom", Decision: "denied", Created: when.Add(time.Hour)},
	}}
	data, e := renderMavenMetadata(store.MavenView{Group: r, Members: []store.MavenMember{m}}, []mavenDocument{{mavenMetadata{Group: "org.example", Artifact: "tool"}, m}}, "org/example/tool/maven-metadata.xml", 100, 1<<20)
	if e != nil || !strings.Contains(string(data), "<version>1.0-SNAPSHOT</version>") {
		t.Fatal("an older reimported POM hid the current snapshot", string(data), e)
	}
}
