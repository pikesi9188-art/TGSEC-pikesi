#!/usr/bin/env python3
"""大爱仙尊证据闸：口头结论必须在案卷文件里逐字符出现。

只读，不打点。近成功：sink / 表单 / DIFF 还在、或矩阵「未测」，禁止结案。

  python3 炼蛊房/evidence_gate.py --case <案卷> --claim 'L2' --claim 'actuator'
  python3 炼蛊房/evidence_gate.py --case <案卷> --from-status
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ENGINE = Path(__file__).resolve().parents[1]
RECOVERY = ENGINE / "案卷"
SKIP_DIR = {".git", "__pycache__", "node_modules"}
EVIDENCE_TOP = {"测绘", "接管", "支付", "证据"}
TEXT_SUF = {".md", ".txt", ".json", ".log", ".csv", ".html", ".xml", ".yml", ".yaml"}
STATUS_CLAIM = re.compile(
    r"(?m)^(?:[-*]|\d+\.)\s+.{0,80}(?:命中|已验证|未授权读|L[123]\b).{0,80}$"
)
TOKEN_CLAIM = re.compile(r"\b(?:L[123]|CVE-\d{4}-\d+|flag\{[^}]+\})\b")
PATH_CLAIM = re.compile(r"/(?:actuator|admin|api|file|nacos|gateway)[/\w.-]*", re.I)
EXTRA_CLAIM = re.compile(
    r"\b(?:heapdump|unserialize|highlight_file|php://filter|gateway/routes)\b",
    re.I,
)
SINK_SIGNAL = re.compile(
    r"(unserialize|eval\s*\(|highlight_file|php://filter|/actuator)",
    re.I,
)


def resolve_case(raw: str) -> Path:
    p = Path(raw)
    if p.is_dir():
        return p.resolve()
    cand = RECOVERY / raw
    if cand.is_dir():
        return cand.resolve()
    return p.resolve()


def _iter_text(case: Path) -> list[tuple[Path, str]]:
    out: list[tuple[Path, str]] = []
    for p in case.rglob("*"):
        if not p.is_file() or any(x in SKIP_DIR for x in p.parts):
            continue
        if p.suffix.lower() not in TEXT_SUF and p.name not in {"STATUS.md", "TRIAGE.md"}:
            continue
        if p.name.startswith("STATUS"):
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if txt.strip():
            out.append((p, txt))
    return out


def _claims_from_status(status: str) -> list[str]:
    """只抽可对证记号。整行回灌会自证；也不把整句当 claim（测绘里几乎对不上）。"""
    claims: list[str] = []
    claims.extend(TOKEN_CLAIM.findall(status))
    for m in STATUS_CLAIM.finditer(status):
        line = m.group(0)
        claims.extend(PATH_CLAIM.findall(line))
        claims.extend(EXTRA_CLAIM.findall(line))
    seen: set[str] = set()
    uniq: list[str] = []
    for c in claims:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq[:40]


def _in_evidence_tree(case: Path, p: Path) -> bool:
    try:
        rel = p.relative_to(case)
    except ValueError:
        return False
    return rel.parts and rel.parts[0] in EVIDENCE_TOP


def check(case: Path, claims: list[str]) -> dict[str, Any]:
    files = _iter_text(case)
    status_p = case / "STATUS.md"
    status = status_p.read_text(encoding="utf-8", errors="replace") if status_p.is_file() else ""
    closing = bool(re.search(r"结案|无路|NO_PATH|复工结案", status, re.I))
    hits: list[dict[str, Any]] = []
    misses: list[str] = []
    for claim in claims:
        if not claim.strip():
            continue
        found = [str(p.relative_to(case)) for p, t in files if claim in t]
        if found:
            hits.append({"claim": claim, "files": found[:8]})
        else:
            misses.append(claim)
    leftover = []
    for p, t in files:
        if not _in_evidence_tree(case, p):
            continue
        for m in SINK_SIGNAL.finditer(t):
            tok = m.group(0)
            if tok.lower() not in status.lower():
                leftover.append({"token": tok[:80], "file": str(p.relative_to(case))})
        rel_parts = p.relative_to(case).parts
        blob: dict[str, Any] | None = None
        if p.suffix.lower() == ".json":
            try:
                parsed = json.loads(t)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict):
                blob = parsed
        if blob and ("http_batch" in rel_parts or p.name == "batch.json"):
            uniq = blob.get("unique_idx") or []
            if uniq and not re.search(r"对照|DIFF", status, re.I):
                leftover.append({"token": f"http_batch DIFF idx={uniq}", "file": str(p.relative_to(case))})
        if blob and ("source_extract" in rel_parts or p.name == "source.json"):
            forms = blob.get("forms") or []
            if forms and not re.search(r"表单|form|对照", status, re.I):
                leftover.append({"token": f"source_extract forms={len(forms)}", "file": str(p.relative_to(case))})
    seen: set[str] = set()
    uniq_left = []
    for row in leftover:
        k = row["token"]
        if k not in seen:
            seen.add(k)
            uniq_left.append(row)
        if len(uniq_left) >= 20:
            break
    matrix = case / "测绘" / "object_matrix.md"
    matrix_untested = False
    if matrix.is_file() and "未测" in matrix.read_text(encoding="utf-8", errors="replace"):
        matrix_untested = closing
    elif closing and re.search(r"(登录|票|token|session|身份|账号)", status, re.I) and not matrix.is_file():
        matrix_untested = True
    near_blocked = bool(uniq_left) and closing
    ok = not misses and not near_blocked and not matrix_untested
    return {
        "ok": ok,
        "case": str(case),
        "files_scanned": len(files),
        "hits": hits,
        "misses": misses,
        "high_signal_unspent": uniq_left,
        "near_success_blocked": near_blocked,
        "matrix_blocked": matrix_untested,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="案卷证据闸（只读）")
    ap.add_argument("--case", required=True)
    ap.add_argument("--claim", action="append", default=[], help="必须出现在案卷文件里的字面量")
    ap.add_argument("--from-status", action="store_true", help="从 STATUS 列表行抽 claim")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    case = resolve_case(args.case)
    if not case.is_dir():
        print(f"[!] 案卷不存在: {case}", file=sys.stderr)
        return 2
    claims = list(args.claim)
    if args.from_status:
        status = (case / "STATUS.md").read_text(encoding="utf-8", errors="replace") if (case / "STATUS.md").is_file() else ""
        claims.extend(_claims_from_status(status))
    if not claims and not args.from_status:
        print("[!] 需要 --claim 或 --from-status", file=sys.stderr)
        return 2
    data = check(case, claims)
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(("PASS" if data["ok"] else "FAIL") + f"  {case.name}")
        for h in data["hits"]:
            print(f"  + {h['claim'][:80]}  ← {', '.join(h['files'][:3])}")
        for m in data["misses"]:
            print(f"  E 口头无证据: {m[:80]}")
        for row in data["high_signal_unspent"][:8]:
            print(f"  W 高信号未写 STATUS: {row['token']}  ({row['file']})")
        if data.get("near_success_blocked"):
            print("  E 结案被近成功闸拦住：先耗尽 sink/表单/对照 DIFF")
        if data.get("matrix_blocked"):
            print("  E 有身份或矩阵「未测」不能结案：先填 案卷/object_matrix.md")
    return 0 if data["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
