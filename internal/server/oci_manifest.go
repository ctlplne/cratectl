// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

const ociManifestBytes = 4 << 20
const ociDescriptorLimit = 4096

var errOCIManifest = errors.New("invalid or ambiguous OCI manifest or descriptor")
var ociMedia = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$`)

type ociChild struct {
	Kind string
	store.OCIDescriptor
}
type parsedOCIManifest struct {
	MediaType, ArtifactType string
	Annotations             map[string]string
	Children                []ociChild
	Subject                 *store.OCIDescriptor
}

// Reject duplicate JSON members before decoding. Otherwise different readers can
// disagree about the digest's dependency graph. Unknown extension fields remain
// opaque. This walk has fixed depth and document-size bounds and never executes
// or decompresses any referenced payload.
func uniqueOCIJSON(data []byte) error {
	if len(data) == 0 || len(data) > ociManifestBytes || !utf8.Valid(data) {
		return errOCIManifest
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return errOCIManifest
		}
		t, e := d.Token()
		if e != nil {
			return errOCIManifest
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				keys := map[string]bool{}
				for d.More() {
					key, e := d.Token()
					name, ok := key.(string)
					if e != nil || !ok || keys[name] {
						return errOCIManifest
					}
					keys[name] = true
					if e = value(depth + 1); e != nil {
						return e
					}
				}
				if t, e = d.Token(); e != nil || t != json.Delim('}') {
					return errOCIManifest
				}
			case '[':
				for d.More() {
					if e = value(depth + 1); e != nil {
						return e
					}
				}
				if t, e = d.Token(); e != nil || t != json.Delim(']') {
					return errOCIManifest
				}
			default:
				return errOCIManifest
			}
		}
		return nil
	}
	if e := value(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errOCIManifest
	}
	return nil
}

func ociObject(data json.RawMessage) (map[string]json.RawMessage, error) {
	var out map[string]json.RawMessage
	if json.Unmarshal(data, &out) != nil || out == nil {
		return nil, errOCIManifest
	}
	return out, nil
}
func ociString(raw json.RawMessage, optional bool) (string, error) {
	if len(raw) == 0 && optional {
		return "", nil
	}
	var value string
	if bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &value) != nil {
		return "", errOCIManifest
	}
	return value, nil
}
func ociAnnotations(raw json.RawMessage) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	fields, e := ociObject(raw)
	if e != nil {
		return nil, errOCIManifest
	}
	annotations := map[string]string{}
	for key, raw := range fields {
		if key == "" || strings.IndexFunc(key, unicode.IsControl) >= 0 {
			return nil, errOCIManifest
		}
		value, e := ociString(raw, false)
		if e != nil {
			return nil, e
		}
		annotations[key] = value
	}
	return annotations, nil
}
func parseOCIDescriptor(raw json.RawMessage) (store.OCIDescriptor, error) {
	var descriptor store.OCIDescriptor
	fields, e := ociObject(raw)
	if e != nil {
		return descriptor, e
	}
	descriptor.Digest, e = ociString(fields["digest"], false)
	if e != nil || !ociDigest.MatchString(descriptor.Digest) {
		return descriptor, errOCIManifest
	}
	descriptor.MediaType, e = ociString(fields["mediaType"], false)
	if e != nil || !ociMedia.MatchString(descriptor.MediaType) {
		return descriptor, errOCIManifest
	}
	if len(fields["size"]) == 0 || bytes.Equal(fields["size"], []byte("null")) || json.Unmarshal(fields["size"], &descriptor.Size) != nil || descriptor.Size < 0 {
		return descriptor, errOCIManifest
	}
	if raw, ok := fields["data"]; ok {
		encoded, e := ociString(raw, false)
		if e != nil {
			return descriptor, e
		}
		data, e := base64.StdEncoding.Strict().DecodeString(encoded)
		if e != nil || strings.ContainsAny(encoded, "\r\n") || int64(len(data)) != descriptor.Size || "sha256:"+crypt.Digest(data) != descriptor.Digest {
			return descriptor, errOCIManifest
		}
	}
	if raw, ok := fields["urls"]; ok {
		var urls []string
		if json.Unmarshal(raw, &urls) != nil || urls == nil {
			return descriptor, errOCIManifest
		}
		for _, uri := range urls {
			u, e := url.Parse(uri)
			if e != nil || !u.IsAbs() || strings.IndexFunc(uri, unicode.IsControl) >= 0 {
				return descriptor, errOCIManifest
			}
		}
	}
	if _, e = ociAnnotations(fields["annotations"]); e != nil {
		return descriptor, e
	}
	if raw, ok := fields["artifactType"]; ok {
		kind, e := ociString(raw, false)
		if e != nil || !ociMedia.MatchString(kind) {
			return descriptor, errOCIManifest
		}
	}
	if raw, ok := fields["platform"]; ok {
		platform, e := ociObject(raw)
		if e != nil {
			return descriptor, e
		}
		for _, key := range []string{"architecture", "os"} {
			v, e := ociString(platform[key], false)
			if e != nil || v == "" {
				return descriptor, errOCIManifest
			}
		}
	}
	return descriptor, nil
}

func parseOCIManifest(data []byte, contentType string) (parsedOCIManifest, error) {
	m := parsedOCIManifest{}
	if e := uniqueOCIJSON(data); e != nil {
		return m, e
	}
	fields, e := ociObject(data)
	if e != nil {
		return m, e
	}
	var schema int
	if json.Unmarshal(fields["schemaVersion"], &schema) != nil || schema != 2 {
		return m, errOCIManifest
	}
	m.MediaType, e = ociString(fields["mediaType"], true)
	if e != nil || (len(fields["mediaType"]) > 0 && m.MediaType == "") {
		return m, errOCIManifest
	}
	headerMedia := ""
	if contentType != "" {
		headerMedia, _, e = mime.ParseMediaType(contentType)
		if e != nil {
			return m, errOCIManifest
		}
	}
	if m.MediaType == "" {
		m.MediaType = headerMedia
	} else if headerMedia != "" && headerMedia != m.MediaType {
		return m, errOCIManifest
	}
	image := false
	switch m.MediaType {
	case "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json":
		image = true
	case "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json":
	default:
		return m, errOCIManifest
	}
	m.ArtifactType, e = ociString(fields["artifactType"], true)
	if e != nil || (len(fields["artifactType"]) > 0 && !ociMedia.MatchString(m.ArtifactType)) {
		return m, errOCIManifest
	}
	if m.Annotations, e = ociAnnotations(fields["annotations"]); e != nil {
		return m, e
	}
	if raw, ok := fields["subject"]; ok {
		d, e := parseOCIDescriptor(raw)
		if e != nil {
			return m, e
		}
		m.Subject = &d
	}
	array, kind := "manifests", "manifests"
	if image {
		if _, exists := fields["manifests"]; exists {
			return m, errOCIManifest
		}
		d, e := parseOCIDescriptor(fields["config"])
		if e != nil || (d.MediaType == "application/vnd.oci.empty.v1+json" && m.ArtifactType == "") {
			return m, errOCIManifest
		}
		m.Children = append(m.Children, ociChild{"blobs", d})
		if m.ArtifactType == "" {
			m.ArtifactType = d.MediaType
		}
		array, kind = "layers", "blobs"
	} else {
		if _, exists := fields["config"]; exists {
			return m, errOCIManifest
		}
		if _, exists := fields["layers"]; exists {
			return m, errOCIManifest
		}
	}
	var descriptors []json.RawMessage
	if json.Unmarshal(fields[array], &descriptors) != nil || descriptors == nil || len(descriptors)+len(m.Children) > ociDescriptorLimit {
		return m, errOCIManifest
	}
	for _, raw := range descriptors {
		d, e := parseOCIDescriptor(raw)
		if e != nil {
			return m, e
		}
		m.Children = append(m.Children, ociChild{kind, d})
	}
	seen := map[string]store.OCIDescriptor{}
	for _, child := range m.Children {
		key := child.Kind + "/" + child.Digest
		if old, exists := seen[key]; exists && old != child.OCIDescriptor {
			return m, errOCIManifest
		}
		seen[key] = child.OCIDescriptor
	}
	return m, nil
}

func parseOCIPath(p string) (image, operation, ref string) {
	if strings.HasSuffix(p, "/blobs/uploads/") {
		p = strings.TrimSuffix(p, "/")
	}
	parts := strings.Split(p, "/")
	n := len(parts)
	if n >= 3 {
		switch parts[n-2] {
		case "manifests", "blobs", "referrers":
			if parts[n-2] == "blobs" && parts[n-1] == "uploads" {
				return strings.Join(parts[:n-2], "/"), "blobs/uploads", ""
			}
			return strings.Join(parts[:n-2], "/"), parts[n-2], parts[n-1]
		case "tags":
			if parts[n-1] == "list" {
				return strings.Join(parts[:n-2], "/"), "tags/list", ""
			}
		case "uploads":
			if n >= 4 && parts[n-3] == "blobs" {
				return strings.Join(parts[:n-3], "/"), "blobs/uploads", parts[n-1]
			}
		}
	}
	return "", "", ""
}

func ociAcceptsMedia(accept, media string) bool {
	if accept == "" {
		return true
	}
	specificity, quality := -1, 0.0
	for _, part := range strings.Split(accept, ",") {
		kind, params, e := mime.ParseMediaType(strings.TrimSpace(part))
		if e != nil {
			continue
		}
		q := 1.0
		if value, ok := params["q"]; ok {
			q, e = strconv.ParseFloat(value, 64)
			if e != nil || math.IsNaN(q) || q < 0 || q > 1 {
				continue
			}
		}
		score := -1
		if kind == media {
			score = 2
		} else if kind == strings.SplitN(media, "/", 2)[0]+"/*" {
			score = 1
		} else if kind == "*/*" {
			score = 0
		}
		if score > specificity {
			specificity, quality = score, q
		} else if score == specificity {
			quality = max(quality, q)
		}
	}
	return specificity >= 0 && quality > 0
}

func (m parsedOCIManifest) metadata(image string) store.OCIManifestMetadata {
	metadata := store.OCIManifestMetadata{Validated: true, References: []string{}, Descriptors: map[string]store.OCIDescriptor{}, Subject: m.Subject, ArtifactType: m.ArtifactType, Annotations: m.Annotations}
	for _, child := range m.Children {
		p := image + "/" + child.Kind + "/" + child.Digest
		metadata.References = append(metadata.References, p)
		metadata.Descriptors[p] = child.OCIDescriptor
	}
	return metadata
}
