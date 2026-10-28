// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"path"
	"regexp"
	"strings"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	pep "github.com/aquasecurity/go-pep440-version"
)

var pyNormalize = regexp.MustCompile(`[-_.]+`)
var pyName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)

func NormalizePython(name string) string {
	return pyNormalize.ReplaceAllString(strings.ToLower(name), "-")
}
func (s *Server) pypi(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, p string) {
	if strings.HasPrefix(p, "files/") {
		s.pythonDownload(w, r, i, repo, strings.TrimPrefix(p, "files/"))
		return
	}
	if r.Method == "POST" && p == "" {
		r.Body = http.MaxBytesReader(w, r.Body, s.PythonUploadBytes)
		mr, e := r.MultipartReader()
		if e != nil {
			fail(w, 400, "invalid_upload", "Use twine multipart publication.")
			return
		}
		fields := map[string]string{}
		var obj *blob.Object
		filename := ""
		parts := 0
		for {
			part, e := mr.NextPart()
			if e == io.EOF {
				break
			}
			parts++
			if e != nil || parts > 128 {
				fail(w, 400, "invalid_upload", "Limit the upload to 128 multipart fields.")
				return
			}
			// Inspect the raw disposition to avoid silently accepting a basename after
			// the MIME library has removed traversal segments from a filename.
			_, params, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
			if err != nil {
				fail(w, 400, "invalid_upload", "Use valid multipart disposition.")
				return
			}
			if part.FormName() == "content" {
				if obj != nil {
					fail(w, 400, "invalid_upload", "Publish one file at a time.")
					return
				}
				filename = params["filename"]
				if !ValidPath(filename) || path.Base(filename) != filename || len(filename) > 255 {
					fail(w, 400, "invalid_filename", "Use a package basename without directories.")
					return
				}
				staged, err := s.Blobs.Put(r.Context(), i.Tenant, part, "", -1)
				if err != nil {
					respondErr(w, err)
					return
				}
				obj = &staged
			} else {
				b, e := io.ReadAll(io.LimitReader(part, 64<<10+1))
				if e != nil || len(b) > 64<<10 {
					fail(w, 400, "metadata_limit", "Use smaller package metadata.")
					return
				}
				field := part.FormName()
				if _, exists := fields[field]; exists && (field == "name" || field == "version" || field == "requires_python" || field == "sha256_digest") {
					fail(w, 400, "ambiguous_metadata", "Send each identity and checksum field once.")
					return
				}
				fields[field] = string(b)
			}
		}
		name := NormalizePython(fields["name"])
		version := fields["version"]
		if !pyName.MatchString(name) || len(name) > 200 || version == "" || len(version) > 100 || obj == nil {
			fail(w, 400, "invalid_metadata", "Include a valid package name, version and content.")
			return
		}
		if !strings.HasSuffix(filename, ".whl") && !strings.HasSuffix(filename, ".tar.gz") && !strings.HasSuffix(filename, ".zip") {
			fail(w, 400, "invalid_distribution", "Publish a wheel or source distribution.")
			return
		}
		if expected := fields["sha256_digest"]; expected != "" && expected != obj.Digest {
			fail(w, 400, "checksum_mismatch", "The uploaded bytes must match the declared SHA-256.")
			return
		}
		file, e := s.Blobs.OpenVerified(r.Context(), i.Tenant, obj.Digest, obj.Size)
		if e != nil {
			respondErr(w, e)
			return
		}
		core, e := inspectPythonDistribution(r.Context(), file, obj.Size, filename, pythonArchiveBudget{s.PythonExpandedBytes, s.PythonFileLimit, s.PythonMetadataBytes})
		file.Close()
		declared, parseErr := pep.Parse(version)
		actual, otherErr := pep.Parse(core.Version)
		if e != nil || parseErr != nil || otherErr != nil || core.Name != name || !declared.Equal(actual) || (fields["requires_python"] != "" && strings.Join(strings.Fields(fields["requires_python"]), "") != strings.Join(strings.Fields(core.RequiresPython), "")) {
			fail(w, 400, "python_archive_mismatch", "Match the filename, Name, Version and Requires-Python to the bounded distribution's embedded metadata.")
			return
		}
		metadata, _ := json.Marshal(store.PythonFile{Name: core.Name, Version: core.Version, Filename: filename, RequiresPython: core.RequiresPython, CoreAvailable: strings.HasSuffix(filename, ".whl"), CoreMetadata: core.Raw, CoreSHA256: crypt.Digest([]byte(core.Raw)), Validated: true, Size: &obj.Size})
		if e = s.DB.PublishPython(r.Context(), i, repo.Name, store.Artifact{Path: filename, Digest: obj.Digest, Size: obj.Size, MediaType: "application/octet-stream", Metadata: metadata}); e != nil {
			respondErr(w, e)
			return
		}
		w.WriteHeader(200)
		return
	}
	s.pythonSimple(w, r, i, repo, p)
}
