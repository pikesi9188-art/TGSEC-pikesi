#!/usr/bin/env python3
"""掩码 JWT / 会话查找票：服务端不验签，只按截断串查 session。"""
from __future__ import annotations

import re

# 前缀+字面 ... +短后缀（711 族：eyJhbG...XXXX）
MASKED_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{2,16}\.\.\.[A-Za-z0-9_-]{2,16}")
REAL_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def is_masked_session_token(tok: str) -> bool:
    t = (tok or "").strip().strip('"').strip("'")
    if not t or "..." not in t:
        return False
    if REAL_JWT_RE.fullmatch(t):
        return False
    return t.startswith("eyJ") or bool(MASKED_JWT_RE.search(t))


def extract_masked_tokens(text: str) -> list[str]:
    if not text:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for m in MASKED_JWT_RE.finditer(text):
        tok = m.group(0)
        if tok not in seen and is_masked_session_token(tok):
            seen.add(tok)
            out.append(tok)
    return out
