// SPDX-License-Identifier: BUSL-1.1
package configfile

import (
	"slices"
	"strings"
	"testing"
)

func TestPrivateWindowsACLRestrictsEveryEffectiveGrantToOwnerAndOSAdministrators(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1001"
	for _, aces := range [][]privateACE{
		{{kind: 0, mask: 1, principal: user}},
		{{kind: 0, mask: 1, principal: user}, {kind: 0, mask: 1, principal: "S-1-5-18"}, {kind: 0, mask: 1, principal: "S-1-5-32-544"}},
		{{kind: 1, mask: 2, principal: "S-1-1-0"}, {kind: 0, mask: 1, principal: user}},
		{{kind: 0, mask: 1, principal: user}, {kind: 0, mask: 1, principal: "S-1-1-0", inheritOnly: true}},
		{{kind: 0, mask: 1, principal: user}, {kind: 0, mask: 0, principal: "S-1-1-0"}},
	} {
		if !privateWindowsACL(user, user, true, aces) {
			t.Fatal("documented protected owner/OS-administrator ACL refused", aces)
		}
	}
}

func TestPrivateWindowsACLRejectsBroadComplexUnprotectedAndUnboundedMetadata(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1001"
	for _, scenario := range []string{"wrong-owner", "missing-owner", "missing-user", "long-owner", "unprotected", "null", "empty", "other-user", "everyone", "users-group", "authenticated-users", "callback", "object-ace", "missing-sid", "long-sid", "deny-only", "zero-only", "inherit-only", "masked-broad-grant", "too-many"} {
		t.Run(scenario, func(t *testing.T) {
			owner, effective, protected := user, user, true
			aces := []privateACE{{kind: 0, mask: 1, principal: user}}
			switch scenario {
			case "wrong-owner":
				owner += "-other"
			case "missing-owner":
				owner = ""
			case "missing-user":
				effective = ""
			case "long-owner":
				owner, effective = strings.Repeat("a", 185), strings.Repeat("a", 185)
			case "unprotected":
				protected = false
			case "null":
				aces = nil
			case "empty":
				aces = []privateACE{}
			case "other-user", "everyone", "users-group", "authenticated-users":
				principal := map[string]string{"other-user": "S-1-5-21-1-2-3-1002", "everyone": "S-1-1-0", "users-group": "S-1-5-32-545", "authenticated-users": "S-1-5-11"}[scenario]
				aces = append(aces, privateACE{kind: 0, mask: 1, principal: principal})
			case "callback", "object-ace":
				aces[0].kind = 9
				if scenario == "object-ace" {
					aces[0].kind = 5
				}
			case "missing-sid":
				aces[0].principal = ""
			case "long-sid":
				aces[0].principal = strings.Repeat("a", 185)
			case "deny-only":
				aces[0].kind = 1
			case "zero-only":
				aces[0].mask = 0
			case "inherit-only":
				aces[0].inheritOnly = true
			case "masked-broad-grant":
				aces = append(aces, privateACE{kind: 1, mask: 1, principal: "S-1-1-0"}, privateACE{kind: 0, mask: 1, principal: "S-1-1-0"})
			case "too-many":
				aces = slices.Repeat(aces, maxPrivateACEs+1)
			}
			if privateWindowsACL(owner, effective, protected, aces) {
				t.Fatal("unsafe ACL metadata accepted", scenario)
			}
		})
	}
}
