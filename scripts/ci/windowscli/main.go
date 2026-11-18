// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

var sourcePaths = []string{
	"go.mod", "go.sum", "cmd/cratectl/main.go",
	"internal/configfile/config.go", "internal/configfile/config_test.go",
	"internal/configfile/read_unix.go", "internal/configfile/read_other.go",
	"internal/configfile/private_acl.go", "internal/configfile/private_acl_test.go",
	"internal/configfile/read_windows.go", "internal/configfile/read_windows_test.go",
	"scripts/ci/windowscli/main.go", "scripts/ci/windowscli/events.go", "scripts/ci/windowscli/events_test.go",
	"scripts/ci/windowscli/process.go", "scripts/ci/windowscli/process_windows.go",
	"scripts/ci/windowscli/process_other.go", "scripts/ci/windowscli/process_windows_test.go",
}

func digestFile(path string, maximum int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return "", errors.New("qualification file is outside its regular-file/byte bound")
	}
	hash := crypt.SHA256()
	n, err := io.Copy(hash, io.LimitReader(f, maximum+1))
	if err != nil || n != info.Size() || n > maximum {
		return "", errors.New("qualification file changed or exceeded its byte bound")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func binaryIdentity(path, candidate, packagePath string) (map[string]string, error) {
	info, err := buildinfo.ReadFile(path)
	if err != nil || info.GoVersion != "go1.27.3" || info.Path != packagePath {
		return nil, errors.New("qualification binary is not the pinned native candidate")
	}
	settings := map[string]string{}
	for _, value := range info.Settings {
		settings[value.Key] = value.Value
	}
	want := map[string]string{"vcs.revision": candidate, "vcs.modified": "false", "GOOS": "windows", "GOARCH": runtime.GOARCH}
	for key, value := range want {
		if settings[key] != value {
			return nil, errors.New("qualification binary source/platform identity differs")
		}
	}
	return want, nil
}

func selectedPattern(names []string) string { return "^(" + strings.Join(names, "|") + ")$" }

func retainFailure(root string, output []byte) {
	// Only encrypted bounded raw output may leave the disposable runner. A
	// failed encryption preserves a hash/absence result, never plaintext upload.
	private := filepath.Join(root, ".cache", "ci-windows-command-private.jsonl")
	sealed := filepath.Join(root, ".cache", "ci-windows-diagnostics.cms")
	if _, err := os.Lstat(private); !os.IsNotExist(err) {
		return // Preserve the first command failure and its ciphertext unchanged.
	}
	encrypted := false
	if writePrivateDiagnostic(private, output) == nil {
		openssl, err := exec.LookPath("openssl.exe")
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			result, err := runCommand(ctx, []string{openssl, "cms", "-encrypt", "-binary", "-aes-256-gcm", "-outform", "DER", "-recip",
				filepath.Join(root, "docs", "qualification", "ci-diagnostics-recipient.pem"), "-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256", "-in", private, "-out", sealed}, root, os.Environ(), 64<<10)
			cancel()
			encrypted = err == nil && result.Exit == 0 && result.Cleaned
		}
	}
	metadata := map[string]any{"schema": 1, "candidate": os.Getenv("GITHUB_SHA"), "run_id": os.Getenv("GITHUB_RUN_ID"),
		"raw_output_sha256": crypt.Digest(output), "raw_output_bytes": len(output), "encrypted": encrypted}
	if encrypted {
		if hash, err := digestFile(sealed, 9<<20); err == nil {
			metadata["ciphertext_sha256"] = hash
		}
	} else {
		os.Remove(sealed) // Never upload an incomplete ciphertext as an observation.
	}
	raw, _ := json.Marshal(metadata)
	os.WriteFile(filepath.Join(root, ".cache", "ci-windows-diagnostics.json"), append(raw, '\n'), 0600)
}

func qualify() error {
	candidate, run := os.Getenv("GITHUB_SHA"), os.Getenv("GITHUB_RUN_ID")
	arch := map[string]string{"X64": "amd64", "ARM64": "arm64"}[os.Getenv("RUNNER_ARCH")]
	if runtime.GOOS != "windows" || arch == "" || runtime.GOARCH != arch || os.Getenv("RUNNER_OS") != "Windows" ||
		os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" ||
		os.Getenv("GITHUB_REPOSITORY") != "ctlplne/cratectl" || os.Getenv("GITHUB_REF") != "refs/heads/main" ||
		len(candidate) != 40 || strings.Trim(candidate, "0123456789abcdef") != "" || run == "" || len(run) > 20 || strings.Trim(run, "0123456789") != "" || run[0] == '0' {
		return errors.New("actual native owner main-branch GitHub Windows runner required")
	}
	root, err := filepath.Abs(".")
	if err != nil {
		return err
	}
	cli := filepath.Join(root, ".cache", "ci-windows", "cratectl.exe")
	self, err := os.Executable()
	if err != nil {
		return err
	}
	identities := map[string]map[string]string{}
	for label, item := range map[string]struct{ path, pkg string }{
		"cli":    {cli, "ctlplne.dev/cratectl/cmd/cratectl"},
		"driver": {self, "ctlplne.dev/cratectl/scripts/ci/windowscli"},
	} {
		identity, err := binaryIdentity(item.path, candidate, item.pkg)
		if err != nil {
			return err
		}
		identities[label] = identity
	}
	env := []string{}
	for _, value := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(value), "CRATECTL_WINDOWS_CLI=") {
			env = append(env, value)
		}
	}
	env = append(env, "CRATECTL_WINDOWS_CLI="+cli)
	commands := 0
	command := func(argv []string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()
		result, err := runCommand(ctx, argv, root, env, 8<<20)
		if err != nil || result.Exit != 0 || !result.Cleaned || result.TotalProcesses < 1 {
			retainFailure(root, result.Output)
			return nil, errors.New("owned native qualification command failed or did not retire its job")
		}
		commands++
		return result.Output, nil
	}
	git, err := exec.LookPath("git.exe")
	if err != nil {
		return err
	}
	head, err := command([]string{git, "rev-parse", "HEAD"})
	if err != nil || strings.TrimSpace(string(head)) != candidate {
		return errors.New("qualification checkout differs from candidate")
	}
	dirty, err := command([]string{git, "status", "--porcelain", "--untracked-files=all"})
	if err != nil || len(dirty) != 0 {
		return errors.New("qualification source must be clean before execution")
	}
	goexe, err := exec.LookPath("go.exe")
	if err != nil {
		return err
	}
	goInfo, err := buildinfo.ReadFile(goexe)
	if err != nil || goInfo.GoVersion != "go1.27.3" || goInfo.Path != "cmd/go" {
		return errors.New("actual pinned Go SDK required")
	}
	platform, err := command([]string{goexe, "env", "GOHOSTOS", "GOHOSTARCH", "GOOS", "GOARCH"})
	if err != nil || strings.Join(strings.Fields(string(platform)), "/") != "windows/"+arch+"/windows/"+arch {
		return errors.New("SDK host or target differs from actual native Windows runner")
	}
	hashes := map[string]string{}
	for label, path := range map[string]string{"cli": cli, "driver": self, "go": goexe} {
		hash, err := digestFile(path, 128<<20)
		if err != nil {
			return err
		}
		hashes[label] = hash
	}
	sources := map[string]string{}
	for _, path := range sourcePaths {
		hash, err := digestFile(filepath.Join(root, filepath.FromSlash(path)), 1<<20)
		if err != nil {
			return err
		}
		sources[path] = hash
	}
	observations := map[string][]string{}
	events := map[string]string{}
	for _, suite := range []struct {
		key, pkg string
		names    []string
	}{{"driver", "scripts/ci/windowscli", driverTests}, {"configuration", "internal/configfile", configurationTests}} {
		raw, err := command([]string{goexe, "test", "-json", "-count=1", "-timeout=180s", "-run", selectedPattern(suite.names), "./" + suite.pkg})
		if err != nil {
			return err
		}
		passed, err := verifyEvents(raw, "ctlplne.dev/cratectl/"+suite.pkg, suite.names)
		if err != nil {
			retainFailure(root, raw)
			return err
		}
		observations[suite.key], events[suite.key] = passed, crypt.Digest(raw)
	}
	if commands != 5 {
		return errors.New("native qualification command inventory incomplete")
	}
	report := map[string]any{"schema": 1, "profile": "cratectl.windows.private-configuration.v1", "candidate": candidate,
		"run_id": run, "runner_os": "Windows", "runner_arch": os.Getenv("RUNNER_ARCH"), "status": "passed", "go_version": "1.27.3",
		"binary_sha256": hashes, "build_identity": identities, "source_sha256": sources, "tests": observations, "events_sha256": events,
		"managed_commands": commands, "all_owned_jobs_empty": true, "management_response_standin": true,
		"windows_server_qualified": false, "offline_collection_qualified": false, "goal_complete": false, "broad_readiness": false}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil || len(raw) > 64<<10 {
		return errors.New("native safe report exceeds its bound")
	}
	path := filepath.Join(root, ".cache", "ci-windows-cli-summary.json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(raw, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	fmt.Println("Native Windows private configuration and owned-job controls passed (14 functions,5 managed commands)")
	return nil
}

func main() {
	if err := qualify(); err != nil {
		if root, e := filepath.Abs("."); e == nil {
			retainFailure(root, []byte(err.Error()))
		}
		// Failure detail must not include private paths, descriptors or test output.
		fmt.Fprintln(os.Stderr, "Native Windows qualification failed; no successful report was written. Inspect bounded encrypted diagnostics when available.")
		os.Exit(1)
	}
}
