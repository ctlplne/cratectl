#!/bin/sh
set -eu
# Filled out alongside the server; a missing binary is an observed failure.
test -x bin/cratectld || { echo 'FAIL: cratectld is not built; no npm workflow exists'; exit 1; }
exec python3 scripts/conformance.py npm
