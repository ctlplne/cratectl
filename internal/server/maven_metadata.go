// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"

	"ctlplne.dev/cratectl/internal/store"
)

var errMavenMetadata = errors.New("invalid Maven metadata or coordinate binding")

func splitMavenChecksumPath(p string) (string, string) {
	extension := path.Ext(p)
	algorithm := ""
	switch extension {
	case ".sha1":
		algorithm = "sha1"
	case ".md5":
		algorithm = "md5"
	case ".sha256", ".SHA-256":
		algorithm = "sha256"
	case ".sha512", ".SHA-512":
		algorithm = "sha512"
	case ".sha384", ".SHA-384":
		algorithm = "sha384"
	default:
		return p, ""
	}
	return strings.TrimSuffix(p, extension), algorithm
}

type mavenMetadata struct {
	XMLName    xml.Name         `xml:"metadata"`
	Model      string           `xml:"modelVersion,attr,omitempty"`
	Group      string           `xml:"groupId,omitempty"`
	Artifact   string           `xml:"artifactId,omitempty"`
	Version    string           `xml:"version,omitempty"`
	Versioning *mavenVersioning `xml:"versioning,omitempty"`
	Plugins    []mavenPlugin    `xml:"plugins>plugin,omitempty"`
}
type mavenVersioning struct {
	Latest    string                 `xml:"latest,omitempty"`
	Release   string                 `xml:"release,omitempty"`
	Versions  []string               `xml:"versions>version,omitempty"`
	Updated   string                 `xml:"lastUpdated,omitempty"`
	Snapshot  *mavenSnapshot         `xml:"snapshot,omitempty"`
	Snapshots []mavenSnapshotVersion `xml:"snapshotVersions>snapshotVersion,omitempty"`
}
type mavenSnapshot struct {
	Timestamp string `xml:"timestamp,omitempty"`
	Build     int    `xml:"buildNumber,omitempty"`
	Local     bool   `xml:"localCopy,omitempty"`
}
type mavenSnapshotVersion struct {
	Classifier string `xml:"classifier,omitempty"`
	Extension  string `xml:"extension"`
	Value      string `xml:"value"`
	Updated    string `xml:"updated,omitempty"`
}
type mavenPlugin struct {
	Name     string `xml:"name"`
	Prefix   string `xml:"prefix"`
	Artifact string `xml:"artifactId"`
}

func mavenComponent(s string) bool {
	if s == "" || len(s) > 256 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune("/\\%?#:<>&\"'", r) {
			return false
		}
	}
	return true
}
func mavenTime(s, layout string) bool { _, e := time.Parse(layout, s); return e == nil }

// Inspect tokens before allocating the model. No DTD, external entities,
// namespace substitution, duplicate scalars, deep trees or unbounded records.
func parseMavenMetadata(data []byte, p string, limit int, maxBytes int64) (mavenMetadata, error) {
	var md mavenMetadata
	if int64(len(data)) > maxBytes || limit < 1 {
		return md, store.ErrMetadataLimit
	}
	allowed := map[string]string{
		"": "metadata", "metadata": "groupId artifactId version versioning plugins",
		"metadata/versioning":          "latest release versions lastUpdated snapshot snapshotVersions",
		"metadata/versioning/versions": "version", "metadata/plugins": "plugin", "metadata/plugins/plugin": "name prefix artifactId",
		"metadata/versioning/snapshot": "timestamp buildNumber localCopy", "metadata/versioning/snapshotVersions": "snapshotVersion",
		"metadata/versioning/snapshotVersions/snapshotVersion": "classifier extension value updated",
	}
	repeated := map[string]bool{"metadata/versioning/versions/version": true, "metadata/plugins/plugin": true, "metadata/versioning/snapshotVersions/snapshotVersion": true}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	stack := []string{}
	seen := []map[string]bool{{}}
	tokens, roots := 0, 0
	for {
		token, e := decoder.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return md, errMavenMetadata
		}
		tokens++
		if tokens > limit*40+256 {
			return md, store.ErrMetadataLimit
		}
		switch value := token.(type) {
		case xml.StartElement:
			if len(stack) >= 8 || len(value.Attr) > 8 {
				return md, store.ErrMetadataLimit
			}
			if value.Name.Space != "" && value.Name.Space != "http://maven.apache.org/METADATA/1.1.0" {
				return md, errMavenMetadata
			}
			parent := strings.Join(stack, "/")
			full := strings.TrimPrefix(parent+"/"+value.Name.Local, "/")
			if !strings.Contains(" "+allowed[parent]+" ", " "+value.Name.Local+" ") || (!repeated[full] && seen[len(seen)-1][value.Name.Local]) {
				return md, errMavenMetadata
			}
			seen[len(seen)-1][value.Name.Local] = true
			if len(stack) == 0 {
				roots++
				if roots != 1 {
					return md, errMavenMetadata
				}
			}
			stack = append(stack, value.Name.Local)
			seen = append(seen, map[string]bool{})
		case xml.EndElement:
			stack = stack[:len(stack)-1]
			seen = seen[:len(seen)-1]
		case xml.CharData:
			if len(stack) == 0 && len(bytes.TrimSpace(value)) != 0 {
				return md, errMavenMetadata
			}
		case xml.Directive:
			return md, errMavenMetadata
		case xml.ProcInst:
			if value.Target != "xml" || roots != 0 {
				return md, errMavenMetadata
			}
		}
	}
	if roots != 1 || xml.Unmarshal(data, &md) != nil {
		return md, errMavenMetadata
	}
	if md.Model != "" && md.Model != "1.0.0" && md.Model != "1.1.0" {
		return md, errMavenMetadata
	}
	dir := path.Dir(p)
	if md.Artifact != "" {
		if !mavenComponent(md.Artifact) || md.Group == "" {
			return md, errMavenMetadata
		}
		coordinate := strings.ReplaceAll(md.Group, ".", "/") + "/" + md.Artifact
		if md.Version != "" {
			if !mavenComponent(md.Version) || !strings.HasSuffix(md.Version, "-SNAPSHOT") {
				return md, errMavenMetadata
			}
			coordinate += "/" + md.Version
		}
		if coordinate != dir {
			return md, errMavenMetadata
		}
	} else if md.Version != "" || md.Versioning != nil || md.Group != "" && strings.ReplaceAll(md.Group, ".", "/") != dir {
		return md, errMavenMetadata
	}
	if v := md.Versioning; v != nil {
		if len(v.Versions)+len(v.Snapshots) > limit {
			return md, store.ErrMetadataLimit
		}
		versions := map[string]bool{}
		for _, version := range v.Versions {
			if !mavenComponent(version) || versions[version] {
				return md, errMavenMetadata
			}
			versions[version] = true
		}
		if v.Latest != "" && !mavenComponent(v.Latest) || v.Release != "" && (!mavenComponent(v.Release) || strings.HasSuffix(v.Release, "-SNAPSHOT")) || v.Updated != "" && !mavenTime(v.Updated, "20060102150405") {
			return md, errMavenMetadata
		}
		if md.Version == "" && (v.Snapshot != nil || len(v.Snapshots) > 0) {
			return md, errMavenMetadata
		}
		if md.Version != "" && (len(v.Versions) > 0 || v.Latest != "" || v.Release != "") {
			return md, errMavenMetadata
		}
		if v.Snapshot != nil && (v.Snapshot.Build < 0 || v.Snapshot.Build > 2147483647 || v.Snapshot.Timestamp != "" && v.Snapshot.Build == 0 || v.Snapshot.Timestamp != "" && !mavenTime(v.Snapshot.Timestamp, "20060102.150405")) {
			return md, errMavenMetadata
		}
		keys := map[string]bool{}
		for _, snapshot := range v.Snapshots {
			key := snapshot.Extension + "/" + snapshot.Classifier
			if !mavenComponent(snapshot.Extension) || snapshot.Classifier != "" && !mavenComponent(snapshot.Classifier) || keys[key] || !mavenSnapshotValue(snapshot.Value, md.Version) || snapshot.Updated != "" && !mavenTime(snapshot.Updated, "20060102150405") {
				return md, errMavenMetadata
			}
			keys[key] = true
		}
	}
	if len(md.Plugins) > limit {
		return md, store.ErrMetadataLimit
	}
	prefixes := map[string]bool{}
	for _, plugin := range md.Plugins {
		if !mavenComponent(plugin.Prefix) || !mavenComponent(plugin.Artifact) || len(plugin.Name) > 512 || prefixes[plugin.Prefix] {
			return md, errMavenMetadata
		}
		prefixes[plugin.Prefix] = true
	}
	return md, nil
}

func mavenSnapshotValue(value, base string) bool {
	if !strings.HasSuffix(base, "-SNAPSHOT") {
		return false
	}
	if value == base {
		return true
	}
	prefix := strings.TrimSuffix(base, "SNAPSHOT")
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	tail := strings.TrimPrefix(value, prefix)
	if len(tail) < 17 || tail[15] != '-' || !mavenTime(tail[:15], "20060102.150405") {
		return false
	}
	n, e := strconv.ParseUint(tail[16:], 10, 31)
	return e == nil && n > 0
}

func snapshotFilename(artifact, base, filename string) (mavenSnapshotVersion, bool) {
	var v mavenSnapshotVersion
	prefix := artifact + "-" + strings.TrimSuffix(base, "SNAPSHOT")
	if !strings.HasPrefix(filename, prefix) {
		return v, false
	}
	tail := strings.TrimPrefix(filename, prefix)
	if len(tail) < 18 || !mavenTime(tail[:15], "20060102.150405") || tail[15] != '-' {
		return v, false
	}
	n := 16
	for n < len(tail) && tail[n] >= '0' && tail[n] <= '9' {
		n++
	}
	v.Value = strings.TrimSuffix(base, "SNAPSHOT") + tail[:n]
	if !mavenSnapshotValue(v.Value, base) || n == len(tail) {
		return v, false
	}
	rest := tail[n:]
	if rest[0] == '-' {
		dot := strings.IndexByte(rest, '.')
		if dot < 2 {
			return v, false
		}
		v.Classifier = rest[1:dot]
		rest = rest[dot:]
	}
	if len(rest) < 2 || rest[0] != '.' {
		return v, false
	}
	v.Extension = rest[1:]
	if !mavenComponent(v.Extension) || v.Classifier != "" && !mavenComponent(v.Classifier) {
		return v, false
	}
	v.Updated = strings.ReplaceAll(tail[:15], ".", "")
	return v, true
}

func referenceSnapshotFilename(artifact, base string, a store.Artifact) (mavenSnapshotVersion, bool) {
	if v, ok := snapshotFilename(artifact, base, path.Base(a.Path)); ok {
		return v, true
	}
	classifier, extension, ok := store.MavenNonuniqueSnapshotFile(artifact, base, path.Base(a.Path))
	if !ok {
		return mavenSnapshotVersion{}, false
	}
	return mavenSnapshotVersion{Classifier: classifier, Extension: extension, Value: base, Updated: a.Created.UTC().Format("20060102150405")}, true
}
