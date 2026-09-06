#!/usr/bin/env python3
"""大爱仙尊技能别名 → 本库专卡。"""
from __future__ import annotations

import sys
from pathlib import Path

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from se_skill_route import MAP, ALIASES, resolve, main  # noqa: E402

__all__ = ("MAP", "ALIASES", "resolve", "main")

if __name__ == "__main__":
    raise SystemExit(main())
