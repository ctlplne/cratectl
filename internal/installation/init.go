// SPDX-License-Identifier: BUSL-1.1
package installation

import (
	"context"
	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Options struct {
	Directory, Tenant, Actor, Listen, PublicURL, OwnerDSN, RuntimeDSN string
	Lifetime                                                          time.Duration
}
type Receipt struct {
	InstallationID string    `json:"installation_id"`
	Tenant         string    `json:"tenant"`
	RuntimeConfig  string    `json:"runtime_config"`
	ClientConfig   string    `json:"client_config"`
	CAFile         string    `json:"ca_file"`
	CAFingerprint  string    `json:"ca_sha256"`
	ExpiresAt      time.Time `json:"credentials_expire_at"`
}
type preparation struct {
	Version int                  `json:"version"`
	Input   store.BootstrapInput `json:"bootstrap"`
	Runtime configfile.Runtime   `json:"runtime"`
	TLS     crypt.LocalTLS       `json:"local_tls"`
}

func encode(v any) []byte { b, _ := json.MarshalIndent(v, "", "  "); return append(b, '\n') }
func syncDirectory(root *os.Root) error {
	f, e := root.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func publish(root *os.Root, name string, data []byte) error {
	before, e := root.Lstat(name)
	if e == nil {
		if !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 {
			return errors.New("prepared installation file is not a private regular file")
		}
		f, e := root.Open(name)
		if e != nil {
			return e
		}
		after, e := f.Stat()
		if e != nil || !os.SameFile(before, after) {
			f.Close()
			return errors.New("prepared installation file changed")
		}
		b, e := io.ReadAll(io.LimitReader(f, 65537))
		f.Close()
		defer clear(b)
		if e != nil || string(b) != string(data) {
			return errors.New("prepared installation file differs; preserve it and inspect configuration instead of overwriting")
		}
		return nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	token, e := crypt.Token()
	if e != nil {
		return e
	}
	tmp := ".prepare-" + token
	f, e := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer root.Remove(tmp)
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	closed := f.Close()
	if e == nil {
		e = closed
	}
	if e != nil {
		return e
	}
	if e = root.Rename(tmp, name); e != nil {
		return e
	}
	return syncDirectory(root)
}
func newPreparation(o Options) (preparation, error) {
	if !store.Name.MatchString(o.Tenant) || !store.Name.MatchString(o.Actor) || o.OwnerDSN == "" || o.RuntimeDSN == "" || o.Lifetime <= 0 {
		return preparation{}, errors.New("supply tenant, actor, positive credential lifetime and separate owner/runtime database configuration")
	}
	host, port, e := net.SplitHostPort(o.Listen)
	n, number := strconv.Atoi(port)
	if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || number != nil || n < 1 || n > 65535 {
		return preparation{}, errors.New("native initialization needs a literal loopback listener and valid port")
	}
	u, e := url.Parse(o.PublicURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Port() != port {
		return preparation{}, errors.New("public URL must be an HTTPS loopback authority on the listener port")
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	tls, e := crypt.LocalIdentity(u.Hostname(), now)
	if e != nil {
		return preparation{}, e
	}
	a, e := crypt.Token()
	if e != nil {
		return preparation{}, e
	}
	w, e := crypt.Token()
	if e != nil {
		return preparation{}, e
	}
	nonce, e := crypt.Token()
	if e != nil {
		return preparation{}, e
	}
	c := configfile.Runtime{Version: 1, DSN: o.RuntimeDSN, Listen: o.Listen, PublicURL: o.PublicURL, Objects: filepath.Join(o.Directory, "objects"), TLSCert: filepath.Join(o.Directory, "server.crt"), TLSKey: filepath.Join(o.Directory, "server.key"), WorkerIdentities: filepath.Join(o.Directory, "workers.json")}
	return preparation{Version: 1, Input: store.BootstrapInput{InstallationID: crypt.Digest([]byte(nonce)), Tenant: o.Tenant, Actor: o.Actor, AdminToken: a, WorkerToken: w, ExpiresAt: now.Add(o.Lifetime)}, Runtime: c, TLS: tls}, nil
}
func Initialize(ctx context.Context, o Options) (Receipt, error) {
	var receipt Receipt
	path, e := filepath.Abs(o.Directory)
	if e != nil || o.Directory == "" {
		return receipt, errors.New("installation directory required")
	}
	o.Directory = path
	if e = os.Mkdir(path, 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return receipt, e
	}
	parent, e := os.OpenRoot(filepath.Dir(path))
	if e != nil {
		return receipt, e
	}
	e = syncDirectory(parent)
	parent.Close()
	if e != nil {
		return receipt, e
	}
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return receipt, errors.New("installation directory must be private and must not be a link")
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		return receipt, e
	}
	defer root.Close()
	unlock, e := lock(root)
	if e != nil {
		return receipt, e
	}
	defer unlock()
	var p preparation
	if _, e = root.Lstat("prepare.json"); errors.Is(e, os.ErrNotExist) {
		if o.Actor == "" {
			o.Actor = "operator"
		}
		if o.Listen == "" {
			o.Listen = "127.0.0.1:38443"
		}
		if o.PublicURL == "" {
			o.PublicURL = "https://localhost:38443"
		}
		if o.Lifetime == 0 {
			o.Lifetime = 24 * time.Hour
		}
		p, e = newPreparation(o)
		if e != nil {
			return receipt, e
		}
		if e = publish(root, "prepare.json", encode(p)); e != nil {
			return receipt, e
		}
	} else if e != nil {
		return receipt, e
	} else if e = configfile.Read(filepath.Join(path, "prepare.json"), &p); e != nil {
		return receipt, e
	}
	if p.Version != 1 || p.Runtime.Validate() != nil || p.Runtime.Objects != filepath.Join(path, "objects") || len(p.Input.AdminToken) != 43 || len(p.Input.WorkerToken) != 43 {
		return receipt, errors.New("invalid prepared installation")
	}
	if o.Tenant != "" && o.Tenant != p.Input.Tenant || o.Actor != "" && o.Actor != p.Input.Actor || o.Listen != "" && o.Listen != p.Runtime.Listen || o.PublicURL != "" && o.PublicURL != p.Runtime.PublicURL || o.RuntimeDSN != "" && o.RuntimeDSN != p.Runtime.DSN {
		return receipt, errors.New("initialization parameters differ from the durable preparation; use its original configuration")
	}
	files := map[string][]byte{"ca.crt": []byte(p.TLS.CA), "server.crt": []byte(p.TLS.Certificate), "server.key": []byte(p.TLS.Key), "admin.token": []byte(p.Input.AdminToken + "\n"), "worker.token": []byte(p.Input.WorkerToken + "\n"), "workers.json": encode(map[string]any{"token_files": []string{filepath.Join(path, "worker.token")}}), "client.json": encode(configfile.Client{Version: 1, URL: p.Runtime.PublicURL, TokenFile: filepath.Join(path, "admin.token"), CAFile: filepath.Join(path, "ca.crt")})}
	for name, data := range files {
		if e = publish(root, name, data); e != nil {
			return receipt, e
		}
	}
	if e = root.Mkdir("objects", 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return receipt, e
	}
	objectInfo, e := root.Lstat("objects")
	if e != nil || !objectInfo.IsDir() || objectInfo.Mode()&os.ModeSymlink != 0 || objectInfo.Mode().Perm()&0077 != 0 {
		return receipt, errors.New("object directory must remain private and must not be a link")
	}
	if o.OwnerDSN == "" {
		return receipt, errors.New("CRATECTL_OWNER_DSN is required to complete or verify initialization")
	}
	if e = store.CheckBootstrapDatabase(ctx, o.OwnerDSN, p.Input); e != nil {
		return receipt, e
	}
	if e = store.Migrate(ctx, o.OwnerDSN); e != nil {
		return receipt, errors.New("database migration failed; check owner authority and retry the same directory")
	}
	db, e := store.Open(ctx, p.Runtime.DSN)
	if e != nil {
		return receipt, e
	}
	defer db.Pool.Close()
	var permitted bool
	if e = db.Pool.QueryRow(ctx, `SELECT has_function_privilege(current_user,'cratectl.authenticate(text)','EXECUTE') AND has_table_privilege(current_user,'cratectl.bootstrap_receipts','SELECT')`).Scan(&permitted); e != nil || !permitted {
		return receipt, errors.New("runtime login needs cratectl_app permissions; configure the restricted login and retry")
	}
	if e = store.Bootstrap(ctx, o.OwnerDSN, p.Input); e != nil {
		return receipt, e
	}
	admin, e := db.Authenticate(ctx, p.Input.AdminToken)
	if e != nil || admin.Tenant != p.Input.Tenant || admin.Role != "admin" {
		return receipt, errors.New("administrator credential is expired, revoked or unavailable; use owner provisioning for rotation")
	}
	worker, e := db.AuthenticateWorker(ctx, p.Input.WorkerToken)
	if e != nil || worker.Tenant != p.Input.Tenant {
		return receipt, errors.New("worker credential is expired, revoked or unavailable; use owner provisioning for rotation")
	}
	if e = publish(root, "runtime.json", encode(p.Runtime)); e != nil {
		return receipt, e
	}
	if e = syncDirectory(root); e != nil {
		return receipt, e
	}
	receipt = Receipt{InstallationID: p.Input.InstallationID, Tenant: p.Input.Tenant, RuntimeConfig: filepath.Join(path, "runtime.json"), ClientConfig: filepath.Join(path, "client.json"), CAFile: filepath.Join(path, "ca.crt"), CAFingerprint: p.TLS.Fingerprint, ExpiresAt: p.Input.ExpiresAt}
	return receipt, nil
}
