#!/bin/sh
# SPDX-License-Identifier: BUSL-1.1
# Start the original interpreter from the private copy of its runtime tree.
set -eu
cratectl_r_tree=$(CDPATH='' cd "$(dirname "$0")/.." && pwd -P)
cratectl_r_support="$cratectl_r_tree"
if [ ! -d "$cratectl_r_support/share" ]; then
    cratectl_r_support=$(CDPATH='' cd "$cratectl_r_tree/../../share/R" && pwd -P)
fi
export R_HOME="$cratectl_r_tree"
export R_SHARE_DIR="$cratectl_r_support/share"
export R_INCLUDE_DIR="$cratectl_r_support/include"
export R_DOC_DIR="$cratectl_r_support/doc"
export DYLD_LIBRARY_PATH="$cratectl_r_tree/lib"
export LD_LIBRARY_PATH="$cratectl_r_tree/lib"
exec "$cratectl_r_tree/bin/exec/R" "$@"
