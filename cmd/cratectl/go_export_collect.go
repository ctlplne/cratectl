// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
)

const goCollectionProfile = "cratectl.go.hosted.collection.v1"

type collectionMember struct {
	Name   string      `json:"name"`
	Object blob.Object `json:"object"`
}
type collectionBinding struct {
	Profile   string                     `json:"profile"`
	Authority string                     `json:"authority"`
	ExportID  string                     `json:"export_id"`
	Journal   checksumJournalAttribution `json:"journal"`
	Members   []collectionMember         `json:"members"`
}
type goCollectionReceipt struct {
	Binding                  collectionBinding `json:"binding"`
	CollectedGeneration      int64             `json:"collected_generation"`
	BytesVerified            bool              `json:"bytes_verified"`
	CurrentRegistryAdmission bool              `json:"current_registry_admission"`
	ChecksumAuthority        bool              `json:"checksum_authority_verified"`
	DependencyClosure        bool              `json:"dependency_closure"`
	DeliveryVerified         bool              `json:"delivery_verified"`
}
type collectionHTTP struct {
	client            *http.Client
	base, token, id   string
	generation, chunk int64
	requests          int
}

func (c *collectionHTTP) get(ctx context.Context, kind, method string, start, end int64) (*http.Response, error) {
	if c.requests >= 16384 {
		return nil, errors.New("collection request budget exceeded")
	}
	c.requests++
	path := "/api/v1/go/exports/" + c.id
	if kind != "" {
		path += "/" + kind + "?generation=" + strconv.FormatInt(c.generation, 10)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept-Encoding", "identity")
	if start >= 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	}
	response, err := c.client.Do(req)
	if err != nil {
		return nil, errors.New("collection request failed; check current access, TLS and network before resuming")
	}
	if response.Header.Get("Content-Encoding") != "" {
		response.Body.Close()
		return nil, errors.New("compressed export response refused")
	}
	return response, nil
}
func collectionHeaders(r *http.Response, object blob.Object, generation int64) bool {
	return len(r.Header.Values("ETag")) == 1 && r.Header.Get("ETag") == `"sha256:`+object.Digest+`"` && len(r.Header.Values("X-Checksum-Sha256")) == 1 && r.Header.Get("X-Checksum-Sha256") == object.Digest && len(r.Header.Values("X-Cratectl-Export-Generation")) == 1 && r.Header.Get("X-Cratectl-Export-Generation") == strconv.FormatInt(generation, 10)
}
func (c *collectionHTTP) checkCurrent(ctx context.Context, m store.GoExportManifest, manifest blob.Object, event int64) error {
	r, err := c.get(ctx, "", "GET", -1, 0)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8193))
	if err != nil || r.StatusCode != 200 || len(raw) > 8192 {
		return errors.New("current export session unavailable")
	}
	var s store.GoExportSession
	if json.Unmarshal(raw, &s) != nil {
		return errors.New("invalid export session")
	}
	canonical, _ := json.Marshal(s)
	if !bytes.Equal(raw, append(canonical, '\n')) || s.ID != c.id || s.Generation != c.generation || s.Manifest != manifest || s.CreatedSequence != event || s.Repository != m.Repository || s.Module != m.Module || s.Version != m.Version || s.SourceRevision != m.SourceRevision || (s.State != "open" && s.State != "acknowledged") || !s.ExpiresAt.After(s.ServerTime) || s.ServerTime.IsZero() {
		return errors.New("export session or generation changed; inspect its current state before resuming")
	}
	return nil
}
func (c *collectionHTTP) download(ctx context.Context, root *os.Root, name, kind string, object blob.Object) error {
	f, err := openCollectionMember(root, name)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() > object.Size {
		return errors.New("partial export file exceeds its authenticated size")
	}
	for offset := st.Size(); offset < object.Size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := min(object.Size-1, offset+c.chunk-1)
		r, err := c.get(ctx, kind, "GET", offset, end)
		if err != nil {
			return err
		}
		expected := end - offset + 1
		good := r.StatusCode == 206 && collectionHeaders(r, object, c.generation) && r.ContentLength == expected && len(r.Header.Values("Content-Range")) == 1 && r.Header.Get("Content-Range") == fmt.Sprintf("bytes %d-%d/%d", offset, end, object.Size)
		if !good {
			r.Body.Close()
			return errors.New("export range status, length, digest or generation changed")
		}
		if _, err = f.Seek(offset, io.SeekStart); err != nil {
			r.Body.Close()
			return err
		}
		n, copyErr := io.CopyBuffer(f, io.LimitReader(offlineGoReader{ctx, r.Body}, expected), make([]byte, 64<<10))
		var extra [1]byte
		if copyErr == nil && n == expected {
			_, copyErr = io.ReadFull(r.Body, extra[:])
			if copyErr == io.EOF {
				copyErr = nil
			} else if copyErr == nil {
				copyErr = errors.New("export range has excess bytes")
			}
		}
		r.Body.Close()
		syncErr := f.Sync()
		if copyErr != nil || n != expected {
			return errors.New("interrupted export range; private partial bytes retained for explicit resume")
		}
		if syncErr != nil {
			return syncErr
		}
		offset += n
	}
	return verifyCollectionFile(ctx, f, object)
}
func openCollectionMember(root *os.Root, name string) (*os.File, error) {
	before, err := root.Lstat(name)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil && !privateCollectionFile(before, false) {
		return nil, errors.New("collection member must be an owner-private regular file with one link")
	}
	flags := os.O_RDWR | collectionOpenFlags()
	if os.IsNotExist(err) {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, err := root.OpenFile(name, flags, 0600)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !privateCollectionFile(after, false) || (before != nil && !os.SameFile(before, after)) {
		f.Close()
		return nil, errors.New("collection member changed or is not private")
	}
	if before == nil {
		if err := syncCollectionRoot(root); err != nil {
			f.Close()
			return nil, err
		}
	}
	return f, nil
}
func syncCollectionRoot(root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func verifyCollectionFile(ctx context.Context, f *os.File, object blob.Object) error {
	before, err := f.Stat()
	if err != nil || before.Size() != object.Size || !privateCollectionFile(before, false) {
		return errors.New("incomplete or unsafe collected file")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hash := crypt.SHA256()
	n, err := io.CopyBuffer(hash, io.LimitReader(offlineGoReader{ctx, f}, object.Size+1), make([]byte, 64<<10))
	after, se := f.Stat()
	if err != nil || se != nil || n != object.Size || hex.EncodeToString(hash.Sum(nil)) != object.Digest || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || !privateCollectionFile(after, false) {
		return errors.New("collected bytes do not match the authenticated snapshot; preserve them and choose a new directory")
	}
	return f.Sync()
}
func copyCollectionLocal(ctx context.Context, root *os.Root, name string, source io.ReaderAt, object blob.Object, chunk int64) error {
	f, err := openCollectionMember(root, name)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() > object.Size {
		return errors.New("local proof file exceeds its original size")
	}
	for offset := st.Size(); offset < object.Size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return err
		}
		n, err := io.CopyBuffer(f, io.NewSectionReader(source, offset, min(chunk, object.Size-offset)), make([]byte, 64<<10))
		syncErr := f.Sync()
		if err != nil {
			return err
		}
		if syncErr != nil {
			return syncErr
		}
		if n == 0 {
			return errors.New("local proof source changed or truncated")
		}
		offset += n
	}
	return verifyCollectionFile(ctx, f, object)
}
func collectionJSON(value any) []byte { raw, _ := json.Marshal(value); return append(raw, '\n') }
func bindCollection(root *os.Root, binding collectionBinding, resume bool) error {
	expected := collectionJSON(binding)
	f, err := root.OpenFile("bindings.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		if _, err = f.Write(expected); err == nil {
			err = f.Sync()
		}
		ce := f.Close()
		if err != nil {
			return err
		}
		return ce
	}
	if !resume || !os.IsExist(err) {
		return errors.New("cannot create immutable collection bindings")
	}
	f, err = openCollectionMember(root, "bindings.json")
	if err != nil {
		return err
	}
	defer f.Close()
	actual, err := io.ReadAll(io.LimitReader(f, int64(len(expected))+1))
	if err != nil || !bytes.Equal(actual, expected) {
		return errors.New("resume authority, export, signed proof or immutable file identities changed")
	}
	return nil
}
func openCollectionDirectory(path string, resume bool) (*os.Root, *os.File, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, err
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !privateCollectionFile(parent, true) {
		return nil, nil, errors.New("collection requires an existing owner-private parent directory")
	}
	if !resume {
		if err := os.Mkdir(path, 0700); err != nil {
			return nil, nil, errors.New("output directory already exists; use explicit --resume only for this same collection")
		}
	}
	before, err := os.Lstat(path)
	if err != nil || !privateCollectionFile(before, true) {
		return nil, nil, errors.New("collection directory must be owner-private and cannot be a symlink")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, nil, err
	}
	dir, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, nil, err
	}
	after, err := dir.Stat()
	if err != nil || !privateCollectionFile(after, true) || !os.SameFile(before, after) {
		dir.Close()
		root.Close()
		return nil, nil, errors.New("collection directory changed")
	}
	if err := lockCollection(dir); err != nil {
		dir.Close()
		root.Close()
		return nil, nil, err
	}
	if !resume {
		containing, err := os.Open(filepath.Dir(path))
		if err != nil {
			dir.Close()
			root.Close()
			return nil, nil, err
		}
		actual, se := containing.Stat()
		if se == nil && (!os.SameFile(parent, actual) || !privateCollectionFile(actual, true)) {
			se = errors.New("collection parent changed")
		}
		if se == nil {
			se = containing.Sync()
		}
		containing.Close()
		if se != nil {
			dir.Close()
			root.Close()
			return nil, nil, se
		}
	}
	entries, err := dir.ReadDir(12)
	allowed := map[string]bool{"bindings.json": true, "receipt.json": true, "manifest.json": true, "original.zip": true, "original.mod": true, "original.info": true, "journal.jsonl": true, "checkpoint.json": true, "checkpoint.sig": true, "signer-public.pem": true}
	if err != nil && err != io.EOF {
		dir.Close()
		root.Close()
		return nil, nil, err
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			dir.Close()
			root.Close()
			return nil, nil, errors.New("collection contains an unexpected member; preserve it and choose another directory")
		}
	}
	return root, dir, nil
}

func runGoExportCollect(args []string, out io.Writer) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return errors.New("resumable collection requires Linux/macOS private-file and directory-lock semantics; Windows remains unsupported by this path")
	}
	f := flag.NewFlagSet("go-export-collect", flag.ContinueOnError)
	j := checksumJournalArguments(f)
	config := f.String("config", "", "owner-private client config; no redirects or insecure TLS")
	id := f.String("export-id", "", "exact original durable export ID")
	generation := f.Int64("generation", 0, "explicit current serving generation; renewal does not change immutable snapshot")
	repository := f.String("repository", "", "exact original repository")
	module := f.String("module", "", "exact original module")
	version := f.String("version", "", "exact original version")
	destination := f.String("output-directory", "", "private collection directory")
	resume := f.Bool("resume", false, "resume only this exact immutable collection; existing bytes are rehashed")
	chunk := f.Int64("chunk-bytes", 4<<20, "range/checkpoint bytes,64KiB–8MiB")
	budget := f.Int64("max-bytes", 2<<30, "combined retained member budget, at most65GiB")
	timeout := f.Duration("timeout", 5*time.Minute, "total collection time, positive through1h")
	if err := f.Parse(args); err != nil {
		return err
	}
	coordinate, err := gomodule.Canonical(*module, *version)
	if err != nil || f.NArg() != 0 || *config == "" || !store.ValidGoExportID(*id) || *generation < 1 || !store.Name.MatchString(*repository) || *destination == "" || *j.file == "" || *chunk < 64<<10 || *chunk > 8<<20 || *budget < 1 || *budget > 65<<30 || *timeout <= 0 || *timeout > time.Hour {
		return errors.New("supply config, exact export/generation/repository/module/version, complete signed journal, private output and bounded transfer budgets")
	}
	attribution, event, err := j.selectEvent(f)
	if err != nil {
		return err
	}
	client, base, token, closeClient, err := collectionClient(*config)
	if err != nil {
		return err
	}
	defer closeClient()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	httpState := &collectionHTTP{client: client, base: base, token: token, id: *id, generation: *generation, chunk: *chunk}
	response, err := httpState.get(ctx, "manifest", "GET", -1, 0)
	if err != nil {
		return err
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, store.MaxGoExportManifest+1))
	response.Body.Close()
	if readErr != nil || response.StatusCode != 200 || len(raw) > store.MaxGoExportManifest {
		return errors.New("cannot collect bounded original manifest with current access/generation")
	}
	manifest, err := store.BindGoExportManifest(raw, *j.tenant, *repository, *id, coordinate, event)
	if err != nil {
		return errors.New("server manifest is not bound to the exact original event and independently verified complete journal")
	}
	mo := blob.Object{Digest: crypt.Digest(raw), Size: int64(len(raw))}
	if !collectionHeaders(response, mo, *generation) {
		return errors.New("manifest serving identity changed")
	}
	if err := httpState.checkCurrent(ctx, manifest, mo, event.Sequence); err != nil {
		return err
	}
	// Capture small public proof bytes and bind the selected key before any output.
	statement, err := configfile.ReadBytes(*j.checkpoint.statement, crypt.MaxJournalCheckpointStatement, true)
	if err != nil {
		return err
	}
	signature, err := configfile.ReadBytes(*j.checkpoint.signature, crypt.JournalCheckpointSignatureBytes, false)
	if err != nil {
		return err
	}
	key, err := configfile.ReadBytes(*j.checkpoint.key, crypt.MaxJournalCheckpointPublicKey, false)
	if err != nil {
		return err
	}
	head := crypt.JournalAnchor{Tenant: attribution.Journal.Tenant, Sequence: attribution.Journal.HeadSequence, Hash: attribution.Journal.HeadHash}
	proof, err := crypt.VerifyJournalCheckpoint(statement, signature, key, head)
	if err != nil || proof != attribution.CheckpointSignature {
		return errors.New("selected checkpoint or public key changed during collection")
	}
	journal, err := configfile.OpenBounded(*j.file, *j.maxBytes, true)
	if err != nil {
		return err
	}
	defer journal.Close()
	js, err := journal.Stat()
	if err != nil {
		return err
	}
	binding := collectionBinding{Profile: goCollectionProfile, Authority: base, ExportID: *id, Journal: *attribution}
	var sources []io.ReaderAt
	for _, entry := range []struct {
		name string
		raw  []byte
	}{{"manifest.json", raw}, {"checkpoint.json", statement}, {"checkpoint.sig", signature}, {"signer-public.pem", key}} {
		binding.Members = append(binding.Members, collectionMember{entry.name, blob.Object{Digest: crypt.Digest(entry.raw), Size: int64(len(entry.raw))}})
		sources = append(sources, bytes.NewReader(entry.raw))
	}
	binding.Members = append(binding.Members, collectionMember{"journal.jsonl", blob.Object{Digest: attribution.Journal.ExportSHA256, Size: js.Size()}})
	sources = append(sources, journal)
	for n, kind := range []string{"zip", "mod", "info"} {
		a := manifest.Artifacts[n]
		binding.Members = append(binding.Members, collectionMember{"original." + kind, blob.Object{Digest: a.Digest, Size: a.Size}})
	}
	var total int64
	for _, member := range binding.Members {
		if member.Object.Size < 0 || member.Object.Size > *budget-total {
			return errors.New("combined collection exceeds max-bytes before any output")
		}
		total += member.Object.Size
	}
	root, dir, err := openCollectionDirectory(*destination, *resume)
	if err != nil {
		return err
	}
	defer root.Close()
	defer dir.Close()
	if err := bindCollection(root, binding, *resume); err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	for n, source := range sources {
		m := binding.Members[n]
		if err := copyCollectionLocal(ctx, root, m.Name, source, m.Object, *chunk); err != nil {
			return collectionFailure(err)
		}
	}
	for n, kind := range []string{"zip", "mod", "info"} {
		m := binding.Members[5+n]
		if err := httpState.download(ctx, root, m.Name, kind, m.Object); err != nil {
			return collectionFailure(err)
		}
	}
	for n, kind := range []string{"manifest", "zip", "mod", "info"} {
		object := mo
		if n > 0 {
			object = binding.Members[4+n].Object
		}
		r, err := httpState.get(ctx, kind, "HEAD", -1, 0)
		if err != nil {
			return collectionFailure(err)
		}
		r.Body.Close()
		if r.StatusCode != 200 || !collectionHeaders(r, object, *generation) || r.ContentLength != object.Size {
			return collectionFailure(errors.New("current serving access or snapshot changed before completion"))
		}
	}
	if err := httpState.checkCurrent(ctx, manifest, mo, event.Sequence); err != nil {
		return collectionFailure(err)
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return collectionFailure(err)
	}
	receipt := goCollectionReceipt{Binding: binding, CollectedGeneration: *generation, BytesVerified: true}
	expected := collectionJSON(receipt)
	saved, err := root.OpenFile("receipt.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		if _, err = saved.Write(expected); err == nil {
			err = saved.Sync()
		}
		ce := saved.Close()
		if err != nil {
			return err
		}
		if ce != nil {
			return ce
		}
		if err := dir.Sync(); err != nil {
			return err
		}
	} else {
		if !*resume || !os.IsExist(err) {
			return collectionFailure(err)
		}
		saved, err = openCollectionMember(root, "receipt.json")
		if err != nil {
			return err
		}
		defer saved.Close()
		previous, err := io.ReadAll(io.LimitReader(saved, (64<<10)+1))
		if err != nil {
			return err
		}
		var original goCollectionReceipt
		if len(previous) > 64<<10 || json.Unmarshal(previous, &original) != nil || !bytes.Equal(previous, collectionJSON(original)) || !reflect.DeepEqual(original.Binding, binding) || !original.BytesVerified || original.CollectedGeneration < 1 || original.CollectedGeneration > *generation || original.CurrentRegistryAdmission || original.ChecksumAuthority || original.DependencyClosure || original.DeliveryVerified {
			return errors.New("saved receipt differs from this verified historical collection")
		}
		if err := saved.Sync(); err != nil {
			return err
		}
		if err := dir.Sync(); err != nil {
			return err
		}
		expected = previous
	}
	n, err := out.Write(expected)
	if err == nil && n != len(expected) {
		err = io.ErrShortWrite
	}
	return err
}
func collectionFailure(cause error) error {
	return fmt.Errorf("collection incomplete: %w; private bytes retained without a new success receipt. Recheck current access/generation and rerun with --resume and the same original signed inputs", cause)
}
func collectionClient(path string) (*http.Client, string, string, func(), error) {
	var c configfile.Client
	if err := configfile.Read(path, &c); err != nil {
		return nil, "", "", nil, err
	}
	u, err := url.Parse(c.URL)
	if err != nil || len(c.URL) > 2048 || c.Version != 1 || c.TokenFile == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || strings.Trim(u.Path, "/") != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, "", "", nil, errors.New("client config requires a credential-free HTTPS authority and private token file")
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return nil, "", "", nil, errors.New("HTTP is restricted to a literal loopback address")
		}
	}
	token, err := configfile.ReadBytes(c.TokenFile, 257, true)
	if err != nil {
		return nil, "", "", nil, err
	}
	value := strings.TrimSpace(string(token))
	clear(token)
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return nil, "", "", nil, errors.New("invalid private token")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.MaxResponseHeaderBytes = 32 << 10
	transport.ResponseHeaderTimeout = 15 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.MaxConnsPerHost = 1
	transport.MaxIdleConnsPerHost = 1
	if c.CAFile != "" {
		pem, err := configfile.ReadBytes(c.CAFile, 1<<20, false)
		if err != nil {
			return nil, "", "", nil, err
		}
		transport.TLSClientConfig, err = crypt.TLSWithCA(pem)
		if err != nil {
			return nil, "", "", nil, err
		}
	}
	client := &http.Client{Transport: transport, Timeout: time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, strings.TrimRight(c.URL, "/"), value, transport.CloseIdleConnections, nil
}
