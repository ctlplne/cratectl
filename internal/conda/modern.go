// SPDX-License-Identifier: BUSL-1.1
package conda

import (
	"archive/zip"
	"context"
	"encoding/json/v2"
	"io"

	"ctlplne.dev/cratectl/internal/ziparchive"
	"ctlplne.dev/cratectl/third_party/go-zstd"
)

const modernMetadata = "metadata.json"
const modernMetadataLimit = 4096

func inspectModern(ctx context.Context, input io.ReaderAt, size int64, coordinate Coordinate) ([]byte, error) {
	infoName := "info-" + coordinate.stem() + ".tar.zst"
	payloadName := "pkg-" + coordinate.stem() + ".tar.zst"
	limits := ziparchive.Limits{CompressedBytes: MaxArchiveBytes, ExpandedBytes: MaxArchiveBytes, Files: 3,
		DirectoryBytes: 16 << 10, AllowSizedLocalZIP64: true}
	inventory, err := ziparchive.Inspect(ctx, input, size, limits, func(name string, directory bool, expanded int64) (io.Writer, error) {
		if directory || expanded < 1 || (name != infoName && name != payloadName && name != modernMetadata) ||
			(name == modernMetadata && expanded > modernMetadataLimit) {
			return nil, ErrPackage
		}
		return nil, nil
	})
	if err != nil || inventory.Files != 3 {
		return nil, ErrPackage
	}
	outer, err := zip.NewReader(input, size)
	if err != nil || len(outer.File) != 3 {
		return nil, ErrPackage
	}
	parts := make(map[string]*zip.File, 3)
	for _, member := range outer.File {
		if member.Method != zip.Store {
			return nil, ErrPackage
		}
		parts[member.Name] = member
	}
	meta, info, payload := parts[modernMetadata], parts[infoName], parts[payloadName]
	if meta == nil || info == nil || payload == nil || !validModernMetadata(ctx, meta) {
		return nil, ErrPackage
	}
	declared, err := inspectModernPart(ctx, info, infoTar, maxExpandedBytes, maxTarMembers)
	if err != nil {
		return nil, err
	}
	if _, err := inspectModernPart(ctx, payload, payloadTar, maxExpandedBytes-declared.bytes, maxTarMembers-declared.members); err != nil {
		return nil, err
	}
	return declared.index, nil
}

func validModernMetadata(ctx context.Context, file *zip.File) bool {
	reader, err := file.Open()
	if err != nil {
		return false
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(checkedReader{ctx, reader}, modernMetadataLimit+1))
	var metadata struct {
		Version int `json:"conda_pkg_format_version"`
	}
	return err == nil && len(data) <= modernMetadataLimit && json.Unmarshal(data, &metadata) == nil && metadata.Version == 2
}

func inspectModernPart(ctx context.Context, file *zip.File, component tarComponent, byteLimit int64, memberLimit int) (packageTar, error) {
	reader, err := file.Open()
	if err != nil {
		return packageTar{}, ErrPackage
	}
	defer reader.Close()
	return inspectPackageTar(ctx, zstd.NewReader(checkedReader{ctx, reader}), component, byteLimit, memberLimit)
}
