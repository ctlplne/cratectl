// SPDX-License-Identifier: BUSL-1.1
package testnet

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

type brokenTCPReader struct{}

func (brokenTCPReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestTCPStateCountsAreBoundedAndExcludeRawEndpointContext(t *testing.T) {
	header := "sl local_address rem_address st tx_queue\n"
	row := func(address, state string) string {
		return fmt.Sprintf("0: %s:%04X private-synthetic-endpoint %s private-synthetic-process-data\n", address, 38443, state)
	}
	raw := header + row("0100007F", "0A") + row(strings.Repeat("0", 32), "01") + row("0100007F", "06") + row("0100007F", "04") + "1: 0100007F:0001 ignored 01 ignored\n"
	counts, err := countTCPStates(strings.NewReader(raw))
	if err != nil || counts != (tcpStates{1, 1, 1, 1}) || strings.Contains(fmt.Sprint(counts), "private-synthetic") {
		t.Fatal("bounded owned-port state counts changed or leaked endpoint context", err)
	}
	for _, raw := range []string{"", "missing header\n", header + "0: missing\n", header + "0: 0100007F:ZZZZ remote 01\n", header + row("0100007F", "invalid"), header + strings.Repeat("x", 4097), strings.Repeat("x", maxTCPTable+1)} {
		counts, err := countTCPStates(strings.NewReader(raw))
		if err == nil || counts != (tcpStates{}) {
			t.Fatal("invalid/oversized table produced partial counts")
		}
	}
	if counts, err := countTCPStates(brokenTCPReader{}); err == nil || counts != (tcpStates{}) {
		t.Fatal("failed table read returned counts")
	}
}
