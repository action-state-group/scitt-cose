# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Action State Group, Inc.
"""Put the standalone package on sys.path so its tests collect from an outer
directory too (e.g. `pytest path/to/this/package`), not only from inside it.
When installed (`pip install -e .`) this bootstrap is unnecessary."""
from __future__ import annotations

import sys
from pathlib import Path

_PKG_ROOT = str(Path(__file__).resolve().parent)
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)
