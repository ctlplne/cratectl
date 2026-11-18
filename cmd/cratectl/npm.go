// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"ctlplne.dev/cratectl/internal/configfile"
)

func runNPMConfig(args []string) error {
	f := flag.NewFlagSet("npm-config", flag.ContinueOnError)
	input := f.String("config", "", "private cratectl client configuration")
	repo := f.String("repository", "", "npm repository name")
	output := f.String("output", "", "new private npm configuration file; never overwritten")
	if e := f.Parse(args); e != nil {
		return e
	}
	if *output == "" || !regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`).MatchString(*repo) {
		return errors.New("supply a repository name and new output path")
	}
	var c configfile.Client
	if e := configfile.Read(*input, &c); e != nil {
		return e
	}
	u, e := url.Parse(c.URL)
	if e != nil || c.Version != 1 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" || strings.ContainsAny(c.CAFile, "\r\n\x00") {
		return errors.New("npm configuration requires an HTTPS authority and valid CA path")
	}
	token, e := configfile.ReadBytes(c.TokenFile, 257, true)
	if e != nil {
		return e
	}
	defer clear(token)
	value := bytes.TrimSpace(token)
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`).Match(value) {
		return errors.New("credential is not a valid native npm token")
	}
	registry := strings.TrimRight(c.URL, "/") + "/npm/" + *repo + "/"
	text := "registry=" + registry + "\nstrict-ssl=true\n"
	if c.CAFile != "" {
		ca, e := filepath.Abs(c.CAFile)
		if e != nil {
			return e
		}
		if _, e = configfile.ReadBytes(ca, 1<<20, false); e != nil {
			return e
		}
		text += "cafile=" + strconv.Quote(ca) + "\n"
	}
	text += "//" + u.Host + "/npm/" + *repo + "/:_authToken="
	contents := make([]byte, 0, len(text)+len(value)+1)
	contents = append(contents, text...)
	contents = append(contents, value...)
	contents = append(contents, '\n')
	defer clear(contents)
	if e := configfile.WriteNewPrivate(*output, contents); e != nil {
		return errors.New("npm output must be a new file in an existing private directory")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"path": *output, "registry": registry, "tls_verification": true})
}
