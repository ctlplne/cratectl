//go:build !darwin && !linux

// SPDX-License-Identifier: BUSL-1.1
package configfile

func readFlags() int { return 0 }
