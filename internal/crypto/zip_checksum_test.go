// SPDX-License-Identifier: BUSL-1.1
package crypto

import "testing"

func TestZIPCRC32CompatibilityVector(t *testing.T) {
	checksum := ZIPCRC32()
	if checksum.Sum32() != 0 {
		t.Fatal("empty ZIP checksum differs")
	}
	checksum.Write([]byte("1234"))
	checksum.Write([]byte("56789"))
	if checksum.Sum32() != 0xcbf43926 {
		t.Fatal("ZIP IEEE checksum compatibility vector differs")
	}
}
