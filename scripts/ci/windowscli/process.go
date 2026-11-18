// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"
)

var errCommandOutput = errors.New("owned command output budget exceeded")

type commandResult struct {
	Output         []byte
	Exit           uint32
	TotalProcesses uint32
	Cleaned        bool
}

func runCommand(ctx context.Context, argv []string, directory string, env []string, maximum int) (commandResult, error) {
	if ctx == nil || len(argv) == 0 || len(argv) > 128 || len(env) > 1024 || !filepath.IsAbs(argv[0]) || !filepath.IsAbs(directory) || maximum < 1 || maximum > 8<<20 {
		return commandResult{}, errors.New("invalid owned command bounds")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 5*time.Minute {
		return commandResult{}, errors.New("owned command needs a deadline through five minutes")
	}
	if err := ctx.Err(); err != nil {
		return commandResult{}, err
	}
	total := 0
	for _, arg := range append(append([]string{}, argv...), env...) {
		if strings.ContainsRune(arg, 0) || len(arg) > 128<<10 || len(arg) > (256<<10)-total {
			return commandResult{}, errors.New("owned command argument/environment budget exceeded")
		}
		total += len(arg)
	}
	return runPlatformCommand(ctx, argv, directory, env, maximum)
}
