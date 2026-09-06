#!/usr/bin/env python3
"""对象矩阵闸：开案落模板，结案前按表格格子计数（空格=未测）。

专卡阴性不是结案条件。矩阵还有未测格子时，下一步是换对象/换他人，不是换同类锤子。

  python3 炼蛊房/object_matrix.py init --case <案卷>
  python3 炼蛊房/object_matrix.py check --case <案卷>
  python3 炼蛊房/object_matrix.py check --case <案卷> --strict
  python3 炼蛊房/object_matrix.py next --case <案卷>
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
CASES = ENGINE / "案卷"
TEMPLATE = CASES / "_templates" / "OBJECT_MATRIX.md"

_UNTESTED_TOKENS = frozenset({"", "未测", "待测", "todo", "TODO", "?"})


def case_dir(case: str, *, cases_root: Path | None = None) -> Path:
    return (cases_root or CASES) / case


def matrix_path(case: str, *, cases_root: Path | None = None) -> Path:
    return case_dir(case, cases_root=cases_root) / "测绘" / "object_matrix.md"


def _is_sep_cell(cell: str) -> bool:
    t = cell.replace(":", "").replace(" ", "")
    return bool(t) and set(t) <= {"-"}


def _cell_untested(val: str) -> bool:
    return (val or "").strip() in _UNTESTED_TOKENS


def parse_matrix(text: str) -> dict:
    """只数数据行的「自己/他人」两列。空单元格算未测；正文里的「未测」不算。"""
    untested: list[dict] = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw.startswith("|"):
            continue
        cols = [c.strip() for c in raw.strip("|").split("|")]
        if len(cols) < 4:
            continue
        if cols[0] == "对象" or _is_sep_cell(cols[0]):
            continue
        obj, verb = cols[0], cols[1]
        self_v, other_v = cols[2], cols[3]
        for who, val in (("自己", self_v), ("他人", other_v)):
            if _cell_untested(val):
                untested.append({"object": obj, "verb": verb, "who": who})
    bans_open = len(re.findall(r"^- \[ \] ", text, re.M))
    bans_done = len(re.findall(r"^- \[[xX]\] ", text, re.M))
    nxt = dict(untested[0]) if untested else None
    return {
        "untested": untested,
        "untested_count": len(untested),
        "bans_open": bans_open,
        "bans_done": bans_done,
        "next": nxt,
        "blocking": bool(untested) or bans_open > 0,
    }


def count_untested(text: str) -> int:
    return int(parse_matrix(text)["untested_count"])


def write_matrix(
    case: str,
    *,
    force: bool = False,
    cases_root: Path | None = None,
    template: Path | None = None,
) -> Path:
    d = case_dir(case, cases_root=cases_root)
    if not d.is_dir():
        raise FileNotFoundError(d)
    (d / "测绘").mkdir(exist_ok=True)
    dst = matrix_path(case, cases_root=cases_root)
    if dst.exists() and not force:
        return dst
    tpl = template or TEMPLATE
    if not tpl.is_file():
        raise FileNotFoundError(tpl)
    text = tpl.read_text(encoding="utf-8").replace("`<案卷>`", case)
    dst.write_text(text, encoding="utf-8")
    return dst


def summarize_case(case: str, *, cases_root: Path | None = None) -> dict:
    p = matrix_path(case, cases_root=cases_root)
    if not p.is_file():
        return {
            "present": False,
            "untested_count": None,
            "bans_open": None,
            "next": None,
            "blocking": True,
            "path": str(p),
        }
    parsed = parse_matrix(p.read_text(encoding="utf-8"))
    parsed["present"] = True
    parsed["path"] = str(p)
    return parsed


_NEXT_HINTS = (
    ("钱包", "fund-edge-ops · fund_edge_ops_probe.py wallet-swap"),
    ("地址", "fund-edge-ops · display-addr / cors"),
    ("流水", "fund-edge-ops · saga-read"),
    ("消息", "fund-edge-ops · message-oracle"),
    ("config", "fund-edge-ops · harvest"),
    ("turnwater", "fund-edge-ops · harvest"),
    ("info", "idor-bola-chain / authz-probe"),
)


def format_next(item: dict | None) -> str:
    if not item:
        return ""
    base = f"{item.get('object')} · {item.get('who')}（{item.get('verb')}）"
    blob = f"{item.get('object') or ''} {item.get('verb') or ''}".lower()
    for needle, hint in _NEXT_HINTS:
        if needle in blob:
            return f"{base} → {hint}"
    return base


def cmd_init(args: argparse.Namespace) -> int:
    d = case_dir(args.case)
    if not d.is_dir():
        print(f"[!] 案卷不存在: {d}（先 case_triage.py init）", file=sys.stderr)
        return 2
    dst = write_matrix(args.case, force=args.force)
    print(f"[+] {dst}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    info = summarize_case(args.case)
    if not info.get("present"):
        print(f"[!] 缺少 {info['path']}（先 object_matrix.py init）", file=sys.stderr)
        return 2
    n = info["untested_count"]
    bans = info["bans_open"]
    nxt = format_next(info.get("next"))
    payload = {
        "case": args.case,
        "untested_cells": n,
        "unchecked_bans": bans,
        "next": nxt or None,
        "blocking": info["blocking"],
        "path": info["path"],
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(
            f"case={args.case} untested_cells={n} unchecked_bans={bans}"
            + (f" next={nxt}" if nxt else "")
        )
        print(f"path={info['path']}")
        if info["blocking"]:
            print("[*] 下一步：测一个「他人」或换一个对象，不要换同类专卡")
        else:
            print("[*] 矩阵格子已填且三禁已勾；专卡可作细链，阴性仍须换对象而不是结案")
    if args.strict and info["blocking"]:
        print("[!] 矩阵未闭合，禁止专卡阴性结案", file=sys.stderr)
        return 1
    return 0


def cmd_next(args: argparse.Namespace) -> int:
    info = summarize_case(args.case)
    if not info.get("present"):
        print(f"[!] 缺少 {info['path']}（先 object_matrix.py init）", file=sys.stderr)
        return 2
    nxt = format_next(info.get("next"))
    if nxt:
        print(nxt)
        return 0
    if info["bans_open"]:
        print("格子已填，先勾结案前三禁")
        return 0
    print("矩阵已闭合")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="对象矩阵闸")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="写入 案卷/object_matrix.md")
    p.add_argument("--case", required=True)
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)
    p = sub.add_parser("check", help="数未测格子")
    p.add_argument("--case", required=True)
    p.add_argument("--strict", action="store_true", help="未闭合则 exit 1")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_check)
    p = sub.add_parser("next", help="打印下一格")
    p.add_argument("--case", required=True)
    p.set_defaults(func=cmd_next)
    args = ap.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
