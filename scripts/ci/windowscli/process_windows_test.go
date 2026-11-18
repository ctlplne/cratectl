//go:build windows

// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func fixtureEnvironment(mode, marker string) []string {
	result := []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(entry), "CRATECTL_OWNED_FIXTURE=") && !strings.HasPrefix(strings.ToUpper(entry), "CRATECTL_CHILD_MARKER=") {
			result = append(result, entry)
		}
	}
	return append(result, "CRATECTL_OWNED_FIXTURE="+mode, "CRATECTL_CHILD_MARKER="+marker)
}

// Invoked only as the declared fixture command, not counted as profile proof.
func TestOwnedProcessFixture(t *testing.T) {
	mode := os.Getenv("CRATECTL_OWNED_FIXTURE")
	if mode == "" {
		return
	}
	switch mode {
	case "emit":
		fmt.Print("cratectl-owned-output")
		os.Exit(0)
	case "overflow":
		for {
			if _, err := os.Stdout.Write([]byte(strings.Repeat("x", 64<<10))); err != nil {
				os.Exit(0)
			}
		}
	case "tree":
		exe, err := os.Executable()
		if err != nil {
			os.Exit(2)
		}
		child := exec.Command(exe, "-test.run=^TestOwnedProcessFixture$")
		child.Env, child.Stdout, child.Stderr = fixtureEnvironment("wait", os.Getenv("CRATECTL_CHILD_MARKER")), os.Stdout, os.Stderr
		if child.Start() != nil {
			os.Exit(3)
		}
		child.Wait()
		os.Exit(4)
	case "wait":
		marker := os.Getenv("CRATECTL_CHILD_MARKER")
		fmt.Print("cratectl-owned-descendant")
		if !filepath.IsAbs(marker) || !strings.HasPrefix(filepath.Base(marker), "cratectl-child-") || os.WriteFile(marker, []byte(strconv.Itoa(os.Getpid())), 0600) != nil {
			os.Exit(5)
		}
		for {
			time.Sleep(time.Second)
		}
	default:
		os.Exit(6)
	}
}

func TestWindowsOwnedProcessCapturesExactOutput(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := runCommand(ctx, []string{exe, "-test.run=^TestOwnedProcessFixture$"}, t.TempDir(), fixtureEnvironment("emit", ""), 4096)
	if err != nil || result.Exit != 0 || string(result.Output) != "cratectl-owned-output" || !result.Cleaned || result.TotalProcesses < 1 {
		t.Fatal("native job did not capture exact output and retire owned processes", err)
	}
}

func TestWindowsOwnedProcessBoundsOutput(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := runCommand(ctx, []string{exe, "-test.run=^TestOwnedProcessFixture$"}, t.TempDir(), fixtureEnvironment("overflow", ""), 4096)
	if !errors.Is(err, errCommandOutput) || len(result.Output) != 4096 || !result.Cleaned || result.TotalProcesses < 1 {
		t.Fatal("native output exceeded its bound or owned group survived", err)
	}
}

func TestWindowsOwnedProcessTimeoutKillsOwnedDescendant(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	marker := filepath.Join(directory, "cratectl-child-observed.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	observed := make(chan windows.Handle, 1)
	go func() {
		for ctx.Err() == nil {
			raw, e := os.ReadFile(marker)
			if e == nil && len(raw) <= 16 {
				pid, e := strconv.ParseUint(string(raw), 10, 32)
				if e == nil && pid > 0 {
					handle, e := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
					if e == nil {
						observed <- handle
						cancel() // Retire only after observing the actual owned descendant.
						return
					}
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	result, err := runCommand(ctx, []string{exe, "-test.run=^TestOwnedProcessFixture$"}, directory, fixtureEnvironment("tree", marker), 4096)
	if !errors.Is(err, context.Canceled) || !result.Cleaned || result.TotalProcesses < 2 || !strings.Contains(string(result.Output), "cratectl-owned-descendant") {
		t.Fatal("native owned-tree cancellation lacked observation or cleanup", err)
	}
	select {
	case child := <-observed:
		defer windows.CloseHandle(child)
		state, e := windows.WaitForSingleObject(child, 0)
		if e != nil || state != windows.WAIT_OBJECT_0 {
			t.Fatal("observed owned descendant survived job termination", e)
		}
	default:
		t.Fatal("owned descendant was never observed")
	}
}
