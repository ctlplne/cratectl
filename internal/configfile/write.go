// SPDX-License-Identifier: BUSL-1.1
package configfile

import "errors"

// WriteNewPrivate writes and syncs a new file in a caller-controlled directory.
// It refuses an existing name. On Windows the protected owner DACL is applied
// at creation, before any caller bytes can reach the file.
func WriteNewPrivate(path string, raw []byte) error {
	file, discard, err := createPrivateOutput(path)
	if err != nil {
		return err
	}
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	if err != nil {
		return errors.Join(err, discard(), file.Close())
	}
	return file.Close()
}
