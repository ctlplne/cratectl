// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

var configurationTests = []string{
	"TestPrivateWindowsACLRejectsBroadComplexUnprotectedAndUnboundedMetadata",
	"TestPrivateWindowsACLRestrictsEveryEffectiveGrantToOwnerAndOSAdministrators",
	"TestReadBytesRejectsOverflowingSentinelBudget",
	"TestWindowsConfigurationHandleDeniesConcurrentWriteAndRename",
	"TestWindowsConfigurationRejectsActualReparsePoint",
	"TestWindowsNativeCLIUsesPrivateConfigurationAndRefusesBroadCredentialsBeforeHTTP",
	"TestWindowsPrivateConfigurationRejectsBroadInheritedAndNullACLs",
	"TestWindowsPrivateConfigurationRejectsHardLinkAliasesAndAlternateStreams",
	"TestWindowsPrivateConfigurationUsesActualProtectedOwnerACL",
	"TestWriteNewPrivateKeepsExactBytesAndRefusesConcurrentOverwrite",
}

var driverTests = []string{
	"TestWindowsEventsEnforceExactTopLevelCoverageAndOrder",
	"TestWindowsEventsRejectSkippedFailedMalformedAndUnboundedInput",
	"TestWindowsOwnedProcessBoundsOutput",
	"TestWindowsOwnedProcessCapturesExactOutput",
	"TestWindowsOwnedProcessTimeoutKillsOwnedDescendant",
}

// Go emits package and subtest events as well as top-level tests. Require one
// run/pass per exact selected function and one final successful package event;
// any failed/skipped subtest also invalidates the whole observation.
func verifyEvents(raw []byte, pkg string, expected []string) ([]string, error) {
	if len(raw) == 0 || len(raw) > 8<<20 || len(expected) < 1 || len(expected) > 64 {
		return nil, errors.New("native test event budget")
	}
	states := map[string]int{}
	for _, name := range expected {
		if name == "" || states[name] != 0 {
			return nil, errors.New("native test inventory")
		}
		states[name] = 1
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	packagePass, lines := false, 0
	for scanner.Scan() {
		lines++
		if lines > 10000 || packagePass {
			return nil, errors.New("native test stream has extra or trailing events")
		}
		var event struct{ Action, Package, Test string }
		if json.Unmarshal(scanner.Bytes(), &event) != nil || event.Package != pkg || event.Action == "fail" || event.Action == "skip" {
			return nil, errors.New("native test event malformed, failed or skipped")
		}
		switch event.Action {
		case "start", "run", "pass", "output", "pause", "cont":
		default:
			return nil, errors.New("unreviewed native test event action")
		}
		if event.Test == "" {
			if event.Action == "pass" {
				packagePass = true
			}
			continue
		}
		name, subtest, _ := strings.Cut(event.Test, "/")
		state, exists := states[name]
		if !exists {
			return nil, errors.New("unreviewed native test function")
		}
		if subtest != "" {
			if state != 2 {
				return nil, errors.New("native subtest outside its running parent")
			}
			continue
		}
		switch event.Action {
		case "run":
			if state != 1 {
				return nil, errors.New("duplicate native test run")
			}
			states[name] = 2
		case "pass":
			if state != 2 {
				return nil, errors.New("native test passed without one observed run")
			}
			states[name] = 3
		case "output", "pause", "cont":
			if state != 2 {
				return nil, errors.New("native test output outside observed run")
			}
		default:
			return nil, errors.New("unreviewed native test action")
		}
	}
	if scanner.Err() != nil || !packagePass {
		return nil, errors.New("native test stream truncated or oversized")
	}
	result := []string{}
	for name, state := range states {
		if state != 3 {
			return nil, errors.New("native test coverage incomplete")
		}
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}
