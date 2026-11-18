// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

const mavenIndexBase = ".index/nexus-maven-repository-index"
const mavenIndexChunk = mavenIndexBase + ".gz"
const mavenIndexProperties = mavenIndexBase + ".properties"

var mavenIndexComponent = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.+-]{0,255}$`)

func mavenIndexCoordinate(file string) (string, bool) {
	parts := strings.Split(file, "/")
	end := len(parts) - 3
	if end < 1 {
		return "", false
	}
	artifact, version := parts[end], parts[end+1]
	if strings.HasSuffix(strings.ToUpper(version), "-SNAPSHOT") || parts[end+2] != artifact+"-"+version+".jar" ||
		!mavenIndexComponent.MatchString(artifact) || !mavenIndexComponent.MatchString(version) {
		return "", false
	}
	for _, group := range parts[:end] {
		if !mavenIndexComponent.MatchString(group) || strings.Contains(group, ".") {
			return "", false
		}
	}
	return strings.Join([]string{strings.Join(parts[:end], "."), artifact, version, "NA"}, "|"), true
}

type mavenIndexField struct {
	name, value string
	flags       byte
}

// Maven Indexer v1 chunks use big-endian record sizes and Java modified UTF-8.
// The coordinate and numeric fields emitted here are nonzero ASCII, which has
// the same wire bytes in modified UTF-8.
func mavenIndexRecord(fields ...mavenIndexField) []byte {
	record := binary.BigEndian.AppendUint32(nil, uint32(len(fields)))
	for _, field := range fields {
		record = append(record, field.flags)
		record = binary.BigEndian.AppendUint16(record, uint16(len(field.name)))
		record = append(record, field.name...)
		record = binary.BigEndian.AppendUint32(record, uint32(len(field.value)))
		record = append(record, field.value...)
	}
	return record
}

func mavenIndexArchive(repo string, observed time.Time, files []store.MavenIndexFile, maxBytes int64) ([]byte, error) {
	const indexed, stored = byte(7), byte(4)
	var body bytes.Buffer
	zip := gzip.NewWriter(&body)
	remaining := maxBytes
	write := func(data []byte) error {
		remaining -= int64(len(data))
		if remaining < 0 {
			return store.ErrMetadataLimit
		}
		_, err := zip.Write(data)
		return err
	}
	if err := write(binary.BigEndian.AppendUint64([]byte{1}, uint64(observed.UnixMilli()))); err != nil {
		return nil, err
	}
	if err := write(mavenIndexRecord(mavenIndexField{"DESCRIPTOR", "NexusIndex", indexed},
		mavenIndexField{"IDXINFO", "1.0|" + repo, indexed})); err != nil {
		return nil, err
	}
	for _, file := range files {
		coordinate, ok := mavenIndexCoordinate(file.Path)
		if !ok {
			continue
		}
		modified := file.Modified.UnixMilli()
		if err := write(mavenIndexRecord(mavenIndexField{"u", coordinate, indexed},
			mavenIndexField{"i", fmt.Sprintf("jar|%d|%d|0|0|0|jar", modified, file.Size), stored},
			mavenIndexField{"m", fmt.Sprint(modified), stored}, mavenIndexField{"sha256", file.Digest, indexed})); err != nil {
			return nil, err
		}
	}
	if err := zip.Close(); err != nil {
		return nil, err
	}
	if int64(body.Len()) > maxBytes {
		return nil, store.ErrMetadataLimit
	}
	return body.Bytes(), nil
}

func (s *Server) serveMavenIndex(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, name, algorithm string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		fail(w, http.StatusMethodNotAllowed, "method_not_allowed", "Read the generated repository index with GET or HEAD.")
		return
	}
	if name != mavenIndexProperties && name != mavenIndexChunk {
		fail(w, http.StatusNotFound, "maven_index_unavailable", "Use the full Maven repository index.")
		return
	}
	maxBytes := min(s.NativeMetadataBytes, 32<<20)
	files, err := s.DB.MavenRepositoryIndex(r.Context(), i, repo.Name, s.NativeVersionLimit, maxBytes)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, "maven_index_unavailable", "Read the full index from a Maven repository.")
		return
	}
	if err != nil {
		respondErr(w, err)
		return
	}
	modified := time.Unix(0, 0)
	for _, file := range files {
		if file.Modified.After(modified) {
			modified = file.Modified
		}
	}
	body, err := mavenIndexArchive(repo.Name, modified, files, maxBytes)
	if err != nil {
		respondErr(w, err)
		return
	}
	contentType := "application/gzip"
	if name == mavenIndexProperties {
		body = fmt.Appendf(nil, "nexus.index.id=%s\nnexus.index.timestamp=%s\ncratectl.index.sha256=%s\n", repo.Name,
			modified.UTC().Format("20060102150405.000 -0700"), crypt.Digest(body))
		contentType = "text/plain; charset=utf-8"
	}
	if int64(len(body)) > maxBytes {
		respondErr(w, store.ErrMetadataLimit)
		return
	}
	if algorithm != "" {
		hash := crypt.CompatibilityHash(algorithm)
		_, _ = hash.Write(body)
		body = hex.AppendEncode(nil, hash.Sum(nil))
		contentType = "text/plain; charset=utf-8"
	}
	digest := crypt.Digest(body)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("ETag", `"sha256:`+digest+`"`)
	w.Header().Set("X-Checksum-Sha256", digest)
	// Each full snapshot is generated for this authenticated request.
	http.ServeContent(w, r, path.Base(r.URL.Path), time.Time{}, bytes.NewReader(body))
}
