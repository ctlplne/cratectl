# SPDX-License-Identifier: BUSL-1.1
"""Explicit schema target shared by native upgrade qualification fixtures.

Advance this only with an appended migration and frozen-receipt evidence. Never
derive the expected version from the database under test.
"""

CURRENT_SCHEMA = 11
