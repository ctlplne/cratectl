// SPDX-License-Identifier: BUSL-1.1
package configfile

// These bounded records describe the OS-returned Windows DACL. Keeping the
// decision separate permits hostile metadata stand-ins on every source host;
// only native Windows handle tests qualify extraction/enforcement by the OS.
type privateACE struct {
	kind        uint8
	mask        uint32
	principal   string
	inheritOnly bool
}

const maxPrivateACEs = 64

func privateWindowsACL(owner, user string, protected bool, aces []privateACE) bool {
	if owner == "" || user == "" || len(owner) > 184 || len(user) > 184 || owner != user || !protected || len(aces) == 0 || len(aces) > maxPrivateACEs {
		return false
	}
	grants := 0
	for _, ace := range aces {
		if ace.kind > 1 || ace.principal == "" || len(ace.principal) > 184 {
			return false
		}
		if ace.kind == 1 || ace.inheritOnly || ace.mask == 0 {
			continue // Denies and inherit-only entries cannot grant this file access.
		}
		// Local SYSTEM and Administrators are the OS administrators, equivalent
		// to trusted root access on Unix. Ordinary groups/other users refuse even
		// when a more complicated deny/conditional ACL might mask their grant.
		if ace.principal != user && ace.principal != "S-1-5-18" && ace.principal != "S-1-5-32-544" {
			return false
		}
		grants++
	}
	return grants > 0
}
