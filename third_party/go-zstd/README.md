# Go Zstandard decoder

These are the unmodified production Go files from `src/internal/zstd` in the
Go 1.27.4 toolchain. Conda package inspection uses the decoder as a streaming
reader with cratectl's archive size, member count and cancellation limits.
The decoder does not use external dictionaries.

The BSD 3-Clause license in this directory is from the same Go source tree.

[Go 1.27.4 source](https://github.com/golang/go/tree/go1.27.4/src/internal/zstd)
