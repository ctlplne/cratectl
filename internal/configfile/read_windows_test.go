//go:build windows

// SPDX-License-Identifier: BUSL-1.1
package configfile

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsCLIOutput struct{ bytes.Buffer }

func (b *windowsCLIOutput) Write(raw []byte) (int, error) {
	if len(raw) > 64<<10-b.Len() {
		return 0, errors.New("owned Windows CLI output exceeds its capture budget")
	}
	return b.Buffer.Write(raw)
}

func windowsFixtureUser(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		t.Fatal("native effective Windows user required", err)
	}
	return user.User.Sid.String()
}

func windowsFixtureFile(t *testing.T, path string, raw []byte, broad, unprotected bool) {
	t.Helper()
	user := windowsFixtureUser(t)
	protection := "P"
	if unprotected {
		protection = ""
	}
	text := "O:" + user + "D:" + protection + "(A;;FA;;;" + user + ")"
	if broad {
		text += "(A;;FR;;;WD)"
	}
	descriptor, err := windows.SecurityDescriptorFromString(text)
	if err != nil {
		t.Fatal("owned fixture security descriptor", err)
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal("create owned Windows fixture", err)
	}
	f := os.NewFile(uintptr(handle), path)
	if f == nil {
		windows.CloseHandle(handle)
		t.Fatal("retain owned Windows fixture handle")
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsPrivateConfigurationUsesActualProtectedOwnerACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cratectl-private.json")
	raw := []byte(`{"version":1,"url":"https://127.0.0.1:38443"}`)
	windowsFixtureFile(t, path, raw, false, false)
	got, err := ReadBytes(path, int64(len(raw)), true)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("protected native owner-only file refused", err)
	}
	var value Client
	if err := Read(path, &value); err != nil || value.Version != 1 || value.URL != "https://127.0.0.1:38443" {
		t.Fatal("native configuration decoding changed", err)
	}
	if _, err := ReadBytes(path, int64(len(raw)-1), true); err == nil {
		t.Fatal("native file byte budget not enforced")
	}
	if _, err := ReadBytes(strings.Repeat("x", (128<<10)+1), 128, true); err == nil {
		t.Fatal("native path byte budget not enforced")
	}
	user := windowsFixtureUser(t)
	descriptor, err := windows.SecurityDescriptorFromString("O:" + user + "D:P(A;;FA;;;" + user + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		t.Fatal("install owned owner/SYSTEM/Administrators profile", err)
	}
	if got, err := ReadBytes(path, int64(len(raw)), true); err != nil || !bytes.Equal(got, raw) {
		t.Fatal("native protected owner/OS-administrator profile refused", err)
	}
}

func TestWindowsPrivateConfigurationRejectsBroadInheritedAndNullACLs(t *testing.T) {
	for _, scenario := range []string{"everyone", "inheritance", "null"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cratectl-unsafe.token")
			windowsFixtureFile(t, path, []byte("owned synthetic credential"), scenario == "everyone", scenario == "inheritance")
			if scenario == "null" {
				if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
					windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
					t.Fatal("install owned null-DACL refusal fixture", err)
				}
			}
			if _, err := ReadBytes(path, 128, true); err == nil {
				t.Fatal("unsafe native ACL supplied private bytes", scenario)
			}
			if raw, err := ReadBytes(path, 128, false); err != nil || string(raw) != "owned synthetic credential" {
				t.Fatal("refusal fixture is not otherwise readable", err)
			}
		})
	}
}

func TestWindowsPrivateConfigurationRejectsHardLinkAliasesAndAlternateStreams(t *testing.T) {
	directory := t.TempDir()
	path, alias := filepath.Join(directory, "cratectl-owned.token"), filepath.Join(directory, "cratectl-alias.token")
	windowsFixtureFile(t, path, []byte("owned original"), false, false)
	if err := os.Link(path, alias); err != nil {
		t.Fatal("native NTFS hard-link fixture required", err)
	}
	for _, candidate := range []string{path, alias} {
		if _, err := ReadBytes(candidate, 128, true); err == nil {
			t.Fatal("shared private file accepted")
		}
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBytes(path, 128, true); err != nil {
		t.Fatal("owned single-link file failed after removing owned alias", err)
	}
	stream := path + ":owned-stream"
	if err := os.WriteFile(stream, []byte("owned stream"), 0600); err != nil {
		t.Fatal("native NTFS alternate stream fixture required", err)
	}
	for _, private := range []bool{false, true} {
		if _, err := ReadBytes(stream, 128, private); err == nil {
			t.Fatal("alternate representation accepted as named configuration")
		}
	}
}

func TestWindowsConfigurationRejectsActualReparsePoint(t *testing.T) {
	directory := t.TempDir()
	path, alias := filepath.Join(directory, "cratectl-owned.token"), filepath.Join(directory, "cratectl-reparse.token")
	windowsFixtureFile(t, path, []byte("owned original"), false, false)
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal("native Windows symlink fixture required; no skip counts as a pass", err)
	}
	for _, private := range []bool{false, true} {
		if _, err := ReadBytes(alias, 128, private); err == nil {
			t.Fatal("reparse point accepted as configuration")
		}
	}
}

func TestWindowsConfigurationHandleDeniesConcurrentWriteAndRename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cratectl-stable.token")
	windowsFixtureFile(t, path, []byte("owned original"), false, false)
	f, err := OpenBounded(path, 128, true)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if other, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		other.Close()
		t.Fatal("concurrent writer acquired an open private configuration")
	}
	if err := os.Rename(path, path+".moved"); err == nil {
		t.Fatal("open configuration was renamed despite its sharing contract")
	}
	raw, err := io.ReadAll(f)
	if err != nil || string(raw) != "owned original" {
		t.Fatal("stable handle changed its bytes", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("owned updated"), 0600); err != nil {
		t.Fatal("owned reader did not release its sharing lock", err)
	}
}

// Run the actual native candidate executable, never a CLI response stand-in.
// The trusted TLS server is an explicitly owned management-response stand-in;
// this test makes no PostgreSQL/registry/stock-client or offline-export claim.
func TestWindowsNativeCLIUsesPrivateConfigurationAndRefusesBroadCredentialsBeforeHTTP(t *testing.T) {
	cli := os.Getenv("CRATECTL_WINDOWS_CLI")
	if cli == "" || !filepath.IsAbs(cli) {
		t.Fatal("absolute actual Windows candidate CLI required")
	}
	identity, err := buildinfo.ReadFile(cli)
	if err != nil || identity.GoVersion != "go1.27.3" || identity.Path != "ctlplne.dev/cratectl/cmd/cratectl" {
		t.Fatal("actual pinned Windows candidate CLI build identity required", err)
	}
	settings := map[string]string{}
	for _, setting := range identity.Settings {
		settings[setting.Key] = setting.Value
	}
	candidate := os.Getenv("GITHUB_SHA")
	if len(candidate) != 40 || strings.Trim(candidate, "0123456789abcdef") != "" || settings["vcs.revision"] != candidate ||
		settings["vcs.modified"] != "false" || settings["GOOS"] != "windows" || settings["GOARCH"] != runtime.GOARCH {
		t.Fatal("native Windows CLI differs from the exact clean candidate or runner architecture")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:38443")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	const token = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" // Owned inert credential only.
	var requests atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+token || r.URL.Path != "/api/v1/repositories" || r.Method != "GET" {
			t.Error("actual CLI changed its scoped credential or management request")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"repositories":[],"owned_standin":true}`)
	}))
	server.Listener.Close()
	server.Listener = listener
	server.StartTLS()
	defer server.Close()
	credential, broadCredential := filepath.Join(directory, "cratectl.token"), filepath.Join(directory, "cratectl-broad.token")
	windowsFixtureFile(t, credential, []byte(token), false, false)
	windowsFixtureFile(t, broadCredential, []byte(token), true, false)
	ca := filepath.Join(directory, "cratectl-ca.pem")
	windowsFixtureFile(t, ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), false, false)
	for _, scenario := range []string{"private", "broad-config", "broad-token", "unknown-field"} {
		config := filepath.Join(directory, "cratectl-"+scenario+".json")
		selectedToken := credential
		if scenario == "broad-token" {
			selectedToken = broadCredential
		}
		raw, err := json.Marshal(Client{Version: 1, URL: server.URL, TokenFile: selectedToken, CAFile: ca})
		if err != nil {
			t.Fatal(err)
		}
		if scenario == "unknown-field" {
			raw = append(bytes.TrimSuffix(raw, []byte("}")), []byte(`,"owned_unknown":true}`)...)
		}
		windowsFixtureFile(t, config, raw, scenario == "broad-config", false)
		before := requests.Load()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, cli, "--config", config, "--path", "/api/v1/repositories", "--raw-response", "--timeout", "10s")
		var stdout, stderr windowsCLIOutput
		cmd.Stdout, cmd.Stderr, cmd.WaitDelay = &stdout, &stderr, 2*time.Second
		err = cmd.Run()
		cancel()
		if scenario == "private" {
			if err != nil || requests.Load() != before+1 || strings.TrimSpace(stdout.String()) != `{"repositories":[],"owned_standin":true}` {
				t.Fatal("actual Windows CLI did not complete the trusted TLS stand-in request", err)
			}
		} else if err == nil || requests.Load() != before || stdout.Len() != 0 {
			t.Fatal("unsafe native CLI input reached HTTP or emitted a success body", scenario, err)
		}
	}
}
