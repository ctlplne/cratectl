// SPDX-License-Identifier: BUSL-1.1
package configfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type Runtime struct {
	Version          int    `json:"version"`
	DSN              string `json:"database_dsn"`
	Listen           string `json:"listen"`
	PublicURL        string `json:"public_url"`
	Objects          string `json:"objects"`
	TLSCert          string `json:"tls_cert"`
	TLSKey           string `json:"tls_key"`
	WorkerIdentities string `json:"worker_identities"`
}

func (c Runtime) Validate() error {
	if c.Version != 1 || c.DSN == "" || c.Listen == "" || c.PublicURL == "" {
		return errors.New("invalid runtime configuration version or required fields")
	}
	for _, p := range []string{c.Objects, c.TLSCert, c.TLSKey, c.WorkerIdentities} {
		if !filepath.IsAbs(p) {
			return errors.New("runtime configuration paths must be absolute")
		}
	}
	return nil
}

type Client struct {
	Version   int    `json:"version"`
	URL       string `json:"url"`
	TokenFile string `json:"token_file"`
	CAFile    string `json:"ca_file"`
}

func Read(path string, value any) error {
	b, e := ReadBytes(path, 64<<10, true)
	if e != nil {
		return e
	}
	defer clear(b)
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil {
		return errors.New("invalid configuration JSON or unknown field")
	}
	var rest any
	if d.Decode(&rest) != io.EOF {
		return errors.New("configuration must contain one JSON object")
	}
	return nil
}
func ReadBytes(path string, limit int64, private bool) ([]byte, error) {
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() || private && before.Mode().Perm()&0077 != 0 {
		return nil, errors.New("configuration must be a regular file with appropriate private permissions")
	}
	f, e := os.OpenFile(path, os.O_RDONLY|readFlags(), 0)
	if e != nil {
		return nil, errors.New("cannot open configuration file")
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() > limit || private && after.Mode().Perm()&0077 != 0 {
		return nil, errors.New("configuration changed, is not private or exceeds its byte budget")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		clear(b)
		return nil, errors.New("cannot read bounded configuration")
	}
	return b, nil
}
