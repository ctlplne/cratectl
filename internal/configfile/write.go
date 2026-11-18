// SPDX-License-Identifier: BUSL-1.1
package configfile

import "errors"

// WriteNewPrivate writes and syncs a new file in a caller-controlled directory.
// It refuses an existing name. On Windows the protected owner DACL is applied
// at creation, before any caller bytes can reach the file.
func WriteNewPrivate(path string, raw []byte) error {
	return WriteNewPrivateThen(path, raw, nil)
}

// WriteNewPrivateThen runs afterSync only after syncing the new file. A
// callback failure discards the file before closing the creation handle.
func WriteNewPrivateThen(path string, raw []byte, afterSync func() error) (err error) {
	file, discard, err := createPrivateOutput(path)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			err = errors.Join(err, discard())
		}
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	if err == nil && afterSync != nil {
		err = afterSync()
	}
	keep = err == nil
	return err
}
