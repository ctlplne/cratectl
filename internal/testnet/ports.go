// SPDX-License-Identifier: BUSL-1.1
// Package testnet holds bounded diagnostics for owned native test listeners.
package testnet

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
)

const maxTCPTable = 2 << 20

type tcpStates struct{ listen, established, timeWait, other int }

// ListenOwned never retries, kills a process or chooses a different port.
// On failure it exposes counts only, without addresses, inodes or process data.
func ListenOwned() (net.Listener, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:38443")
	if err != nil {
		return nil, fmt.Errorf("owned native listener: %w; TCP state counts: %s", err, ownedTCPStates())
	}
	return listener, nil
}

func countTCPStates(input io.Reader) (tcpStates, error) {
	var counts tcpStates
	raw, err := io.ReadAll(io.LimitReader(input, maxTCPTable+1))
	if err != nil || len(raw) > maxTCPTable {
		return tcpStates{}, errors.New("TCP table unavailable or exceeds diagnostic budget")
	}
	lines := bytes.Split(raw, []byte{'\n'})
	if len(lines) == 0 || !bytes.Contains(lines[0], []byte("local_address")) {
		return tcpStates{}, errors.New("TCP table header unavailable")
	}
	for _, line := range lines[1:] {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		fields := strings.Fields(string(line))
		if len(line) > 4096 || len(fields) < 4 {
			return tcpStates{}, errors.New("TCP table row unavailable")
		}
		colon := strings.LastIndexByte(fields[1], ':')
		if colon < 0 || len(fields[1])-colon-1 != 4 {
			return tcpStates{}, errors.New("TCP port unavailable")
		}
		port, err := strconv.ParseUint(fields[1][colon+1:], 16, 16)
		if err != nil {
			return tcpStates{}, errors.New("TCP port unavailable")
		}
		if port != 38443 {
			continue
		}
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil || len(fields[3]) != 2 {
			return tcpStates{}, errors.New("TCP state unavailable")
		}
		switch state {
		case 0x0a:
			counts.listen++
		case 0x01:
			counts.established++
		case 0x06:
			counts.timeWait++
		default:
			counts.other++
		}
	}
	return counts, nil
}

func ownedTCPStates() string {
	if runtime.GOOS != "linux" {
		return "unavailable on this platform"
	}
	var total tcpStates
	for _, name := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		input, err := os.Open(name)
		if err != nil {
			return "unavailable"
		}
		counts, err := countTCPStates(input)
		input.Close()
		if err != nil {
			return "unavailable"
		}
		total.listen += counts.listen
		total.established += counts.established
		total.timeWait += counts.timeWait
		total.other += counts.other
	}
	return fmt.Sprintf("listen=%d established=%d time_wait=%d other=%d", total.listen, total.established, total.timeWait, total.other)
}
