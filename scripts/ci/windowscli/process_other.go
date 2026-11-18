//go:build !windows

// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"errors"
)

func runPlatformCommand(context.Context, []string, string, []string, int) (commandResult, error) {
	return commandResult{}, errors.New("owned Windows job execution requires actual Windows")
}

func writePrivateDiagnostic(string, []byte) error {
	return errors.New("private Windows diagnostic creation requires actual Windows")
}
