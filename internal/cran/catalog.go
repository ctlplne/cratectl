// SPDX-License-Identifier: BUSL-1.1
package cran

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
)

const MaxCatalogBytes = 8 << 20

var ErrCatalog = errors.New("invalid or unsupported CRAN source catalog")
var sha256Checksum = regexp.MustCompile(`^[a-f0-9]{64}$`)
var md5Checksum = regexp.MustCompile(`^[a-f0-9]{32}$`)

type CatalogEntry struct {
	Description Package `json:"description"`
	SHA256      string  `json:"sha256"`
	MD5         string  `json:"md5"`
}

func (e CatalogEntry) Coordinate() Coordinate {
	return Coordinate{Name: e.Description["Package"], Version: e.Description["Version"]}
}

func (e CatalogEntry) Valid() bool {
	return sha256Checksum.MatchString(e.SHA256) && md5Checksum.MatchString(e.MD5) && e.Description.ValidFor(e.Coordinate())
}

func (e CatalogEntry) Matches(description Package, md5 string) bool {
	if e.MD5 != md5 {
		return false
	}
	for _, key := range indexFields {
		if key == "Title" || key == "Description" {
			continue
		}
		if e.Description[key] != description[key] {
			return false
		}
	}
	return true
}

// PinnedSourcePath identifies an already selected digest in stock R's Path
// field. The final filename remains the package archive's native filename.
func PinnedSourcePath(c Coordinate, digest string) string {
	return SourceDirectory + DigestDirectory + digest + "/" + strings.TrimPrefix(c.Path(), SourceDirectory)
}

func ParsePinnedSourcePath(value string) (Coordinate, string, bool) {
	rest, prefixed := strings.CutPrefix(value, SourceDirectory+DigestDirectory)
	digest, file, split := strings.Cut(rest, "/")
	c, valid := ParsePath(SourceDirectory + file)
	return c, digest, prefixed && split && valid && sha256Checksum.MatchString(digest)
}

// ParseProxyCatalog admits the DCF PACKAGES format with one SHA256sum per
// record. The origin's plain relative archive layout supplies URL authority.
func ParseProxyCatalog(ctx context.Context, data []byte, limit int, byteLimit int64) ([]CatalogEntry, error) {
	if int64(len(data)) > min(byteLimit, MaxCatalogBytes) || limit < 1 {
		return nil, ErrCatalog
	}
	limit = min(limit, 10000)
	entries := make([]CatalogEntry, 0)
	seen := map[Coordinate]bool{}
	start, offset := 0, 0
	for line := range bytes.SplitSeq(data, []byte("\n")) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(line)) == 0 {
			if start < offset {
				entry, err := parseCatalogRecord(data[start:offset])
				if err != nil || len(entries) >= limit || seen[entry.Coordinate()] {
					return nil, ErrCatalog
				}
				seen[entry.Coordinate()] = true
				entries = append(entries, entry)
			}
			start = offset + len(line) + 1
		}
		offset += len(line) + 1
	}
	if start < len(data) {
		entry, err := parseCatalogRecord(data[start:])
		if err != nil || len(entries) >= limit || seen[entry.Coordinate()] {
			return nil, ErrCatalog
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func parseCatalogRecord(record []byte) (CatalogEntry, error) {
	fields, err := descriptionFields(record)
	if err != nil || len(fields["Path"]) != 0 || len(fields["Built"]) != 0 {
		return CatalogEntry{}, ErrCatalog
	}
	coordinate := Coordinate{Name: normalizedDescriptionField(fields["Package"]), Version: normalizedDescriptionField(fields["Version"])}
	packageInfo, err := descriptionPackage(fields, coordinate)
	entry := CatalogEntry{Description: packageInfo, MD5: normalizedDescriptionField(fields["MD5sum"]), SHA256: normalizedDescriptionField(fields["SHA256sum"])}
	if err != nil || !entry.Valid() {
		return CatalogEntry{}, ErrCatalog
	}
	return entry, nil
}
