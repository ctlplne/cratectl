// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"golang.org/x/net/html"
)

var errPythonIndex = errors.New("invalid Python project index")

func pythonIndexHashes(raw string) (map[string]string, error) {
	values, e := url.ParseQuery(raw)
	if e != nil {
		return nil, e
	}
	hashes := map[string]string{}
	for key, values := range values {
		if len(values) != 1 {
			return nil, errPythonIndex
		}
		hashes[key] = values[0]
	}
	return hashes, nil
}
func pythonIndexCore(value any) (bool, string, error) {
	if value == nil {
		return false, "", nil
	}
	if enabled, ok := value.(bool); ok {
		return enabled, "", nil
	}
	if text, ok := value.(string); ok {
		if text == "true" {
			return true, "", nil
		}
		hashes, e := pythonIndexHashes(text)
		if e != nil {
			return false, "", e
		}
		pin, e := crypt.SourceIntegrityFromHex(hashes)
		return true, pin.Canonical, e
	}
	if values, ok := value.(map[string]any); ok {
		hashes := map[string]string{}
		for algorithm, v := range values {
			digest, ok := v.(string)
			if !ok {
				return false, "", errPythonIndex
			}
			hashes[algorithm] = digest
		}
		pin, e := crypt.SourceIntegrityFromHex(hashes)
		return true, pin.Canonical, e
	}
	return false, "", errPythonIndex
}
func (s *Server) pythonIndexSource(name, filename, rawURL, base string, hashes map[string]string, file store.PythonFile, repo store.Repository) (store.NativeSource, error) {
	project, version, kind, e := pythonDistribution(filename)
	if e != nil || project != name {
		return store.NativeSource{}, errPythonIndex
	}
	parsed, e := url.Parse(rawURL)
	if e != nil {
		return store.NativeSource{}, errPythonIndex
	}
	parent, e := url.Parse(base)
	if e != nil {
		return store.NativeSource{}, errPythonIndex
	}
	resolved := parent.ResolveReference(parsed)
	if resolved.Fragment != "" {
		fragment, e := pythonIndexHashes(resolved.Fragment)
		if e != nil {
			return store.NativeSource{}, e
		}
		if hashes == nil {
			hashes = fragment
		} else {
			for key, value := range fragment {
				if current, ok := hashes[key]; ok && current != value {
					return store.NativeSource{}, errPythonIndex
				}
				hashes[key] = value
			}
		}
		resolved.Fragment = ""
		resolved.RawFragment = ""
	}
	if path.Base(resolved.Path) != filename {
		return store.NativeSource{}, errPythonIndex
	}
	if _, e = downloadSource(repo, resolved.String()); e != nil {
		return store.NativeSource{}, e
	}
	pin, e := crypt.SourceIntegrityFromHex(hashes)
	if e != nil {
		return store.NativeSource{}, e
	}
	if len(file.RequiresPython) > 4096 || strings.ContainsAny(file.RequiresPython, "\x00\r\n") || (file.Yanked != nil && len(*file.Yanked) > 4096) {
		return store.NativeSource{}, errPythonIndex
	}
	file.Name, file.Version, file.Filename, file.Integrity = name, version, filename, pin.Canonical
	if kind == "wheel" {
		file.CoreAvailable = true
	}
	encoded, e := json.Marshal(file)
	if e != nil {
		return store.NativeSource{}, e
	}
	source := store.NativeSource{Format: "pypi", Name: name, Coordinate: filename, Version: version, URL: resolved.String(), Integrity: pin.Canonical, Metadata: encoded}
	identity, _ := json.Marshal(source)
	source.Key = crypt.Digest(identity)
	return source, nil
}
func (s *Server) parsePythonIndex(data []byte, contentType, base, name string, repo store.Repository) (store.PythonCatalog, []store.NativeSource, error) {
	catalog := store.PythonCatalog{Name: name, Files: map[string]string{}}
	sources := []store.NativeSource{}
	if !utf8.Valid(data) || int64(len(data)) > s.NativeMetadataBytes {
		return catalog, nil, errPythonIndex
	}
	add := func(source store.NativeSource) error {
		if old, ok := catalog.Files[source.Coordinate]; ok {
			if old != source.Key {
				return errPythonIndex
			}
			return nil
		}
		if len(sources) >= s.NativeVersionLimit {
			return store.ErrMetadataLimit
		}
		catalog.Files[source.Coordinate] = source.Key
		sources = append(sources, source)
		return nil
	}
	media, _, e := mime.ParseMediaType(contentType)
	if e != nil {
		return catalog, nil, errPythonIndex
	}
	if media == "application/vnd.pypi.simple.v1+json" || media == "application/json" {
		var document struct {
			Meta struct {
				Version string `json:"api-version"`
			} `json:"meta"`
			Name  string `json:"name"`
			Files []struct {
				Filename       string            `json:"filename"`
				URL            string            `json:"url"`
				Hashes         map[string]string `json:"hashes"`
				RequiresPython string            `json:"requires-python"`
				Yanked         any               `json:"yanked"`
				Core           any               `json:"core-metadata"`
				LegacyCore     any               `json:"dist-info-metadata"`
				Size           *int64            `json:"size"`
				UploadTime     string            `json:"upload-time"`
			} `json:"files"`
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		if decoder.Decode(&document) != nil || NormalizePython(document.Name) != name || document.Files == nil {
			return catalog, nil, errPythonIndex
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return catalog, nil, errPythonIndex
		}
		parts := strings.Split(document.Meta.Version, ".")
		if len(parts) != 2 || parts[0] != "1" {
			return catalog, nil, errPythonIndex
		}
		minor, e := strconv.Atoi(parts[1])
		if e != nil || minor < 0 || len(document.Files) > s.NativeVersionLimit {
			return catalog, nil, errPythonIndex
		}
		for _, raw := range document.Files {
			file := store.PythonFile{RequiresPython: raw.RequiresPython, Size: raw.Size}
			if (minor >= 1 && raw.Size == nil) || (raw.Size != nil && *raw.Size < 0) {
				return catalog, nil, errPythonIndex
			}
			if raw.UploadTime != "" {
				if _, e := time.Parse(time.RFC3339Nano, raw.UploadTime); e != nil {
					return catalog, nil, errPythonIndex
				}
			}
			switch value := raw.Yanked.(type) {
			case nil:
			case bool:
				if value {
					reason := ""
					file.Yanked = &reason
				}
			case string:
				if value != "" {
					file.Yanked = &value
				}
			default:
				return catalog, nil, errPythonIndex
			}
			core := raw.Core
			if core == nil {
				core = raw.LegacyCore
			}
			file.CoreAvailable, file.CoreIntegrity, e = pythonIndexCore(core)
			if e != nil {
				return catalog, nil, e
			}
			source, e := s.pythonIndexSource(name, raw.Filename, raw.URL, base, raw.Hashes, file, repo)
			if e != nil {
				return catalog, nil, e
			}
			if e = add(source); e != nil {
				return catalog, nil, e
			}
		}
	} else if media == "text/html" || media == "application/vnd.pypi.simple.v1+html" {
		tokens := html.NewTokenizer(bytes.NewReader(data))
		var attributes map[string]string
		var text strings.Builder
		indexBase := base
		for {
			typeID := tokens.Next()
			if typeID == html.ErrorToken {
				if tokens.Err() != io.EOF || attributes != nil {
					return catalog, nil, errPythonIndex
				}
				break
			}
			switch typeID {
			case html.StartTagToken, html.SelfClosingTagToken:
				token := tokens.Token()
				if token.Data == "base" {
					for _, a := range token.Attr {
						if a.Key == "href" {
							parent, e := url.Parse(base)
							if e != nil {
								return catalog, nil, e
							}
							relative, e := url.Parse(a.Val)
							if e != nil {
								return catalog, nil, e
							}
							indexBase = parent.ResolveReference(relative).String()
						}
					}
				}
				if token.Data == "a" {
					if attributes != nil {
						return catalog, nil, errPythonIndex
					}
					attributes = map[string]string{}
					text.Reset()
					for _, a := range token.Attr {
						if _, exists := attributes[a.Key]; exists {
							return catalog, nil, errPythonIndex
						}
						attributes[a.Key] = a.Val
					}
				}
			case html.TextToken:
				if attributes != nil {
					value := tokens.Text()
					if text.Len()+len(value) > 512 {
						return catalog, nil, errPythonIndex
					}
					text.Write(value)
				}
			case html.EndTagToken:
				if tokens.Token().Data != "a" || attributes == nil {
					continue
				}
				filename := strings.TrimSpace(text.String())
				href := attributes["href"]
				if _, _, _, e := pythonDistribution(filename); e == nil {
					file := store.PythonFile{RequiresPython: attributes["data-requires-python"]}
					if reason, ok := attributes["data-yanked"]; ok {
						file.Yanked = &reason
					}
					value, present := attributes["data-core-metadata"]
					if !present {
						value, present = attributes["data-dist-info-metadata"]
					}
					if present {
						file.CoreAvailable, file.CoreIntegrity, e = pythonIndexCore(value)
						if e != nil {
							return catalog, nil, e
						}
					}
					source, e := s.pythonIndexSource(name, filename, href, indexBase, nil, file, repo)
					if e != nil {
						return catalog, nil, e
					}
					if e = add(source); e != nil {
						return catalog, nil, e
					}
				}
				attributes = nil
			}
		}
	} else {
		return catalog, nil, errPythonIndex
	}
	return catalog, sources, nil
}
