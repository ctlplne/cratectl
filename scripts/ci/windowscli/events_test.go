// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func eventFixture(action, test string) string {
	raw, _ := json.Marshal(map[string]string{"Action": action, "Package": "owned/package", "Test": test})
	return string(raw) + "\n"
}

func TestWindowsEventsEnforceExactTopLevelCoverageAndOrder(t *testing.T) {
	raw := eventFixture("start", "") + eventFixture("run", "TestOwned") + eventFixture("run", "TestOwned/sub") +
		eventFixture("pass", "TestOwned/sub") + eventFixture("output", "TestOwned") + eventFixture("pass", "TestOwned") + eventFixture("pass", "")
	got, err := verifyEvents([]byte(raw), "owned/package", []string{"TestOwned"})
	if err != nil || len(got) != 1 || got[0] != "TestOwned" {
		t.Fatal("complete native event stream refused", got, err)
	}
	for _, changed := range []string{
		strings.Replace(raw, eventFixture("run", "TestOwned"), "", 1),
		strings.Replace(raw, eventFixture("pass", "TestOwned"), "", 1),
		strings.Replace(raw, eventFixture("run", "TestOwned"), eventFixture("run", "TestOwned")+eventFixture("run", "TestOwned"), 1),
		strings.Replace(raw, "TestOwned", "TestOther", -1),
		raw + eventFixture("output", ""),
	} {
		if _, err := verifyEvents([]byte(changed), "owned/package", []string{"TestOwned"}); err == nil {
			t.Fatal("incomplete, duplicate, unknown or trailing event stream accepted")
		}
	}
}

func TestWindowsEventsRejectSkippedFailedMalformedAndUnboundedInput(t *testing.T) {
	for _, raw := range []string{"", "not JSON", eventFixture("run", "TestOwned") + eventFixture("skip", "TestOwned/sub"),
		eventFixture("run", "TestOwned") + eventFixture("fail", "TestOwned"),
		strings.Repeat("x", (64<<10)+1), strings.Repeat(eventFixture("output", ""), 10001),
		strings.Repeat(" ", (8<<20)+1)} {
		if _, err := verifyEvents([]byte(raw), "owned/package", []string{"TestOwned"}); err == nil {
			t.Fatal("failed/skipped/malformed/unbounded native events accepted")
		}
	}
}
