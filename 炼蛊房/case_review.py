#!/usr/bin/env python3
"""只读复核大爱仙尊案卷：STATUS / 对象矩阵 / 证据目录是否可交差。不碰目标。"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def _utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if reconf:
            try:
                reconf(encoding="utf-8")
            except Exception:
                pass

_utf8_stdio()

ENGINE = Path(__file__).resolve().parents[1]
RECOVERY = ENGINE / "案卷"

NEED_FILES = ("STATUS.md",)
NEED_ANY_DIR = ("测绘", "接管", "支付", "证据")
MATRIX_HINT = re.compile(r"(登录|票|token|session|身份|账号)", re.I)


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(ENGINE))
    except ValueError:
        return str(p)


def review(case: Path) -> dict:
    errors: list[str] = []
    warns: list[str] = []
    notes: list[str] = []
    if not case.is_dir():
        return {"ok": False, "case": _rel(case), "errors": [f"案卷目录不存在: {case}"], "warns": [], "notes": []}

    for name in NEED_FILES:
        if not (case / name).is_file():
            errors.append(f"缺 {name}")

    status = case / "STATUS.md"
    status_txt = status.read_text(encoding="utf-8", errors="replace") if status.is_file() else ""
    if status_txt and len(status_txt.strip()) < 40:
        warns.append("STATUS.md 过短，不像可交差结论")

    present_dirs = [d for d in NEED_ANY_DIR if (case / d).is_dir()]
    if not present_dirs:
        warns.append("没有 案卷/ 接管/ 支付/ 证据/ 任一目录")
    else:
        notes.append("证据目录: " + ", ".join(present_dirs))

    matrix = case / "测绘" / "object_matrix.md"
    if MATRIX_HINT.search(status_txt) and not matrix.is_file():
        errors.append("STATUS 已出现身份线索，但缺 案卷/object_matrix.md（对象矩阵闸）")
    elif matrix.is_file():
        notes.append("已有 object_matrix.md")
        mx = matrix.read_text(encoding="utf-8", errors="replace")
        if "未测" in mx:
            warns.append("对象矩阵仍有「未测」格，专卡阴性不能结案")

    triage = case / "TRIAGE.md"
    if triage.is_file():
        notes.append("已有 TRIAGE.md")
    else:
        warns.append("无 TRIAGE.md（可用 case-triage 补）")

    ledger = case / "证据" / "ledger.jsonl"
    if ledger.is_file() and ledger.stat().st_size > 0:
        script = ENGINE / "炼蛊房" / "case_ledger.py"
        run = subprocess.run(
            [sys.executable, str(script), "verify", "--report", str(case)],
            capture_output=True,
            text=True,
        )
        if run.returncode != 0:
            err = (run.stderr or run.stdout or "verify failed").strip().splitlines()
            errors.append("ledger verify --report 失败: " + (err[-1] if err else "unknown"))
        else:
            notes.append("ledger verify --report PASS")

    if re.search(r"结案|无路|NO_PATH", status_txt, re.I):
        warns.append("STATUS 写了结案/无路：再跑 evidence_gate.py --from-status + object_matrix check")

    return {
        "ok": not errors,
        "case": _rel(case),
        "errors": errors,
        "warns": warns,
        "notes": notes,
    }


def resolve_case(raw: str) -> Path:
    p = Path(raw)
    if p.is_dir():
        return p.resolve()
    cand = RECOVERY / raw
    if cand.is_dir():
        return cand.resolve()
    return p.resolve()


def main() -> int:
    ap = argparse.ArgumentParser(description="只读复核案卷证据链")
    ap.add_argument("--case", required=True, help="案卷目录或 案卷/<名>")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="警告也当失败")
    args = ap.parse_args()
    data = review(resolve_case(args.case))
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(("PASS" if data["ok"] else "FAIL") + f"  {data.get('case', '')}")
        for e in data["errors"]:
            print(f"  E {e}")
        for w in data["warns"]:
            print(f"  W {w}")
        for n in data["notes"]:
            print(f"  - {n}")
        print("下一步: 缺矩阵先填 案卷/object_matrix.md；缺结论补 STATUS.md")
    failed = (not data["ok"]) or (args.strict and data["warns"])
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
