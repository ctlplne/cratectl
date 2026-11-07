// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/ziparchive"
)

const maxOfflineGoZIP = 512 << 20

type goOfflineReceipt struct {
	Profile                  string                      `json:"profile"`
	Publication              store.GoHostedPublication   `json:"publication"`
	Journal                  *checksumJournalAttribution `json:"journal_attribution"`
	ZIPHash                  string                      `json:"zip_h1"`
	ModHash                  string                      `json:"mod_h1"`
	Proxy                    string                      `json:"goproxy"`
	CurrentRegistryAdmission bool                        `json:"current_registry_admission"`
	ChecksumAuthority        bool                        `json:"checksum_authority_verified"`
	Trust                    string                      `json:"trust"`
}

func runGoModuleOffline(args []string, out io.Writer) error {
	f := flag.NewFlagSet("go-module-offline", flag.ContinueOnError)
	j := checksumJournalArguments(f)
	repo := f.String("repository", "", "exact original hosted repository")
	module := f.String("module", "", "exact canonical published module path")
	version := f.String("version", "", "exact canonical published version")
	zipFile := f.String("zip-file", "", "private original module ZIP")
	modFile := f.String("mod-file", "", "private original go.mod representation")
	infoFile := f.String("info-file", "", "private original .info representation")
	destination := f.String("output-directory", "", "new private directory; must not exist")
	timeout := f.Duration("timeout", 5*time.Minute, "byte-copy and archive-verification budget, positive through 1h")
	if err := f.Parse(args); err != nil {
		return err
	}
	c, err := gomodule.Canonical(*module, *version)
	if err != nil || f.NArg() != 0 || !store.Name.MatchString(*repo) || *j.file == "" || *zipFile == "" || *modFile == "" || *infoFile == "" || *destination == "" || *timeout <= 0 || *timeout > time.Hour {
		return errors.New("supply exact hosted repository/module/version, three private representation files, a new output-directory and a complete externally signed publication journal")
	}
	attribution, event, err := j.selectEvent(f)
	if err != nil {
		return err
	}
	publication, err := store.BindGoHostedPublication(*j.tenant, *repo, c, event)
	if err != nil {
		return errors.New("selected event does not bind this exact original hosted publication and its three representation digests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	receipt, err := prepareOfflineGo(ctx, publication, attribution, [3]string{*zipFile, *modFile, *infoFile}, *destination)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(receipt)
}

type offlineGoReader struct {
	ctx context.Context
	r   io.Reader
}

func (r offlineGoReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// All inspection uses newly copied private bytes, not a previously checked
// source pathname. No native proxy tree exists until every digest and archive
// check passes. This command never fetches, signs, executes code or imports into
// a live registry. The caller supplies independently verified publication trust.
func prepareOfflineGo(ctx context.Context, publication store.GoHostedPublication, attribution *checksumJournalAttribution, inputs [3]string, destination string) (goOfflineReceipt, error) {
	var empty goOfflineReceipt
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return empty, errors.New("offline proxy preparation requires Linux or macOS private-file and directory-sync semantics; this platform is unsupported")
	}
	c, err := gomodule.Canonical(publication.Coordinate.Module, publication.Coordinate.Version)
	if err != nil || !store.Name.MatchString(publication.Tenant) || !store.Name.MatchString(publication.Repository) {
		return empty, errors.New("invalid exact offline publication identity")
	}
	digests := [3]string{publication.ZIP, publication.Mod, publication.Info}
	for _, d := range digests {
		if !checksumEvidenceDigest.MatchString(d) {
			return empty, errors.New("invalid original publication digest")
		}
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return empty, errors.New("invalid output-directory")
	}
	// A private containing directory keeps incomplete output from other users.
	parent, err := os.Lstat(filepath.Dir(destination))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return empty, errors.New("output-directory requires an existing owner-private parent directory")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return empty, errors.New("cannot exclusively create output-directory; existing files are preserved")
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(destination)
		}
	}()
	root, err := os.OpenRoot(destination)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	prefix := "staging/" + c.Prefix()
	if err := root.MkdirAll(filepath.Dir(prefix), 0700); err != nil {
		return empty, err
	}
	limits := [3]int64{maxOfflineGoZIP, gomodule.MaxGoMod, gomodule.MaxVersionInfo}
	var sizes [3]int64
	for n, kind := range []string{"zip", "mod", "info"} {
		input, err := configfile.OpenBounded(inputs[n], limits[n], true)
		if err != nil {
			return empty, errors.New("cannot open bounded private regular representation file")
		}
		target, err := root.OpenFile(prefix+"."+kind, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			input.Close()
			return empty, err
		}
		hash := crypt.SHA256()
		sizes[n], err = io.CopyBuffer(io.MultiWriter(target, hash), io.LimitReader(offlineGoReader{ctx, input}, limits[n]+1), make([]byte, 64<<10))
		input.Close()
		if err == nil && (sizes[n] > limits[n] || hex.EncodeToString(hash.Sum(nil)) != digests[n]) {
			err = errors.New("copied representation differs from original publication or exceeds its byte budget")
		}
		if err == nil {
			err = target.Sync()
		}
		closeErr := target.Close()
		if err != nil {
			return empty, err
		}
		if closeErr != nil {
			return empty, closeErr
		}
	}
	readSmall := func(kind string) ([]byte, error) {
		f, err := root.Open(prefix + "." + kind)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return io.ReadAll(io.LimitReader(offlineGoReader{ctx, f}, gomodule.MaxGoMod+1))
	}
	mod, err := readSmall("mod")
	if err != nil {
		return empty, err
	}
	info, err := readSmall("info")
	if err != nil {
		return empty, err
	}
	zip, err := root.Open(prefix + ".zip")
	if err != nil {
		return empty, err
	}
	inspected, err := gomodule.InspectRepresentations(ctx, zip, sizes[0], c, mod, info, ziparchive.Limits{CompressedBytes: maxOfflineGoZIP, ExpandedBytes: 512 << 20, DirectoryBytes: 16 << 20, Files: 16384})
	zip.Close()
	if err != nil {
		return empty, errors.New("original representation bytes fail bounded native Go archive/metadata consistency checks")
	}
	proxy := (&url.URL{Scheme: "file", Path: filepath.Join(destination, "proxy")}).String()
	receipt := goOfflineReceipt{"cratectl.go.hosted.offline.v1", publication, attribution, inspected.ZIPHash, inspected.GoModHash, proxy, false, false,
		"Historical hosted publication integrity under the independently trusted journal signer. This does not prove current registry authorization, scan approval, latest/revoked history, a checksum authority, dependency closure or a consistent server export snapshot. Use only after approving these exact packages for the disconnected environment."}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return empty, err
	}
	record, err := root.OpenFile("receipt.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return empty, err
	}
	_, err = record.Write(append(raw, '\n'))
	if err == nil {
		err = record.Sync()
	}
	closeErr := record.Close()
	if err != nil {
		return empty, err
	}
	if closeErr != nil {
		return empty, closeErr
	}
	// Sync every created directory from the leaf to the root before making the
	// complete native file-proxy path visible.
	for p := filepath.Dir(prefix); ; p = filepath.Dir(p) {
		dir, err := root.Open(p)
		if err != nil {
			return empty, err
		}
		err = dir.Sync()
		dir.Close()
		if err != nil {
			return empty, err
		}
		if p == "." {
			break
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := root.Rename("staging", "proxy"); err != nil {
		return empty, err
	}
	dir, err := root.Open(".")
	if err != nil {
		return empty, err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return empty, err
	}
	parentDir, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return empty, err
	}
	err = parentDir.Sync()
	parentDir.Close()
	if err != nil {
		return empty, err
	}
	complete = true
	return receipt, nil
}
