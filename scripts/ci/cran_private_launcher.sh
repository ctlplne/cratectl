#!/bin/sh
# SPDX-License-Identifier: BUSL-1.1
# Start the original interpreter from the private copy of its runtime tree.
set -eu
cratectl_r_tree=$(CDPATH='' cd "$(dirname "$0")/.." && pwd -P)
export R_HOME="$cratectl_r_tree"
export DYLD_LIBRARY_PATH="$cratectl_r_tree/lib"
export LD_LIBRARY_PATH="$cratectl_r_tree/lib"
exec "$cratectl_r_tree/bin/exec/R" "$@"
