#!/usr/bin/env python3
"""发现本地源码/备份解压目录后自动跑 DeepAudit sast + pay-hint。

可被 main.py assess/recover/backup-fetch 调用，也可独立:
  python3 炼蛊房/deepaudit_auto.py --case ilikeu831_20260804 --source ./www
  python3 炼蛊房/deepaudit_auto.py --case X --scan-dir 案卷/X
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

ENGINE = Path(__file__).resolve().parents[1]
DA = ENGINE / "tools" / "deepaudit" / "bin" / "da_pipeline.py"

SOURCE_MARKERS = (
    "composer.json",
    "package.json",
    "pom.xml",
    "go.mod",
    "requirements.txt",
    "manage.py",
    "Gemfile",
    "Cargo.toml",
    ".git",
    "wp-config.php",
    "application/config",
    "config/database.php",
    "app/Controller",
    "app/Models",
)

BACKUP_NAME_HINT = re.compile(
    r"(backup|www|web|site|html|dist|src|source|dump|\.git)",
    re.I,
)


def looks_like_source(path: Path) -> bool:
    if not path.is_dir():
        return False
    # 直接标记
    for m in SOURCE_MARKERS:
        if (path / m).exists():
            return True
    # 浅层扫描
    try:
        children = list(path.iterdir())
    except OSError:
        return False
    names = {c.name.lower() for c in children}
    if {"app", "application", "vendor", "src", "public", "config"} & names:
        return True
    php = sum(1 for c in children if c.suffix == ".php")
    if php >= 5:
        return True
    return False


def discover_sources(roots: list[Path], *, max_depth: int = 3) -> list[Path]:
    found: list[Path] = []
    seen: set[Path] = set()

    def walk(p: Path, depth: int) -> None:
        if depth > max_depth or p in seen:
            return
        seen.add(p)
        if looks_like_source(p):
            found.append(p)
            return  # 不钻入已识别源码树
        if not p.is_dir():
            return
        try:
            kids = list(p.iterdir())
        except OSError:
            return
        for c in kids:
            if c.name in {".git", "node_modules", "vendor", "__pycache__", ".tools"}:
                # .git 本身可作为源码根
                if c.name == ".git" and looks_like_source(p):
                    found.append(p)
                continue
            if c.is_dir() and (BACKUP_NAME_HINT.search(c.name) or depth < 2):
                walk(c, depth + 1)

    for r in roots:
        r = r.expanduser().resolve()
        if r.is_file():
            # zip/sql 旁若有同名目录
            if r.suffix.lower() in {".zip", ".tar", ".gz", ".tgz"}:
                sibling = r.with_suffix("")
                if sibling.is_dir():
                    walk(sibling, 0)
            continue
        if r.is_dir():
            walk(r, 0)
    # 去重
    uniq: list[Path] = []
    for p in found:
        if p not in uniq:
            uniq.append(p)
    return uniq


def run_sast_and_hint(source: Path, case: str, *, timeout: int = 600) -> dict[str, Any]:
    if not DA.is_file():
        return {"ok": False, "error": f"missing {DA}"}
    cmd = [
        sys.executable,
        str(DA),
        "sast",
        "--source",
        str(source),
        "--case",
        case,
        "--timeout",
        str(timeout),
        "--skip-trufflehog",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60)
    hint = subprocess.run(
        [sys.executable, str(DA), "pay-hint", "--case", case],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return {
        "ok": r.returncode == 0,
        "source": str(source),
        "sast_exit": r.returncode,
        "sast_tail": ((r.stdout or "") + (r.stderr or ""))[-1500:],
        "pay_hint_exit": hint.returncode,
        "pay_hint_tail": ((hint.stdout or "") + (hint.stderr or ""))[-800:],
    }


def auto_deepaudit(
    *,
    case: str,
    sources: list[str | Path] | None = None,
    scan_dirs: list[str | Path] | None = None,
    timeout: int = 600,
) -> dict[str, Any]:
    roots = [Path(p) for p in (scan_dirs or [])]
    explicit = [Path(p) for p in (sources or [])]
    discovered = discover_sources(roots) if roots else []
    all_srcs = []
    for p in explicit + discovered:
        p = p.expanduser().resolve()
        if p.is_dir() and p not in all_srcs:
            all_srcs.append(p)

    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "case": case,
        "discovered": [str(p) for p in discovered],
        "ran": [],
        "skipped": False,
    }
    if not all_srcs:
        report["skipped"] = True
        report["reason"] = "no source trees found"
        return report

    for src in all_srcs[:3]:  # 单次最多 3 棵树，防炸
        print(f"[*] DeepAudit sast ← {src}")
        one = run_sast_and_hint(src, case, timeout=timeout)
        report["ran"].append(one)

    # 落盘
    out = ENGINE / "案卷" / case / "测绘" / "deepaudit"
    out.mkdir(parents=True, exist_ok=True)
    path = out / "auto_trigger.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report["log"] = str(path)
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="自动 DeepAudit sast + pay-hint")
    ap.add_argument("--case", required=True)
    ap.add_argument("--source", action="append", default=[], help="显式源码目录，可重复")
    ap.add_argument("--scan-dir", action="append", default=[], help="在此目录下发现源码树")
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args()
    rep = auto_deepaudit(
        case=args.case,
        sources=args.source,
        scan_dirs=args.scan_dir,
        timeout=args.timeout,
    )
    print(json.dumps(rep, ensure_ascii=False, indent=2)[:3000])
    if rep.get("skipped"):
        return 0
    return 0 if all(x.get("ok") for x in rep.get("ran") or []) else 1


if __name__ == "__main__":
    sys.exit(main())
