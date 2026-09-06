#!/usr/bin/env python3
"""案卷归档工具：识别并压缩可归档的案卷及大二进制文件。

用法:
  python3 炼蛊房/archive_cases.py scan              # 扫描可归档候选
  python3 炼蛊房/archive_cases.py scan --before 30   # 30天前的案卷
  python3 炼蛊房/archive_cases.py binaries           # 列出大二进制（>50MB）
  python3 炼蛊房/archive_cases.py archive --before 30 --dest /Volumes/NAS/cases/
  python3 炼蛊房/archive_cases.py clean-binaries --dry-run  # 清理已分析的大二进制

不传 --dest 时只分析不操作。归档不删除原件（用 tar.gz 压缩后需手动确认删除）。
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

ENGINE_ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = ENGINE_ROOT / "案卷"

BINARY_EXTS = {".apk", ".dmg", ".exe", ".7z", ".ipa", ".tar.gz", ".hprof", ".asar"}
BIG_THRESHOLD = 50 * 1024 * 1024  # 50 MB


def _size_human(size_bytes: int) -> str:
    if size_bytes >= 1_073_741_824:
        return f"{size_bytes / 1_073_741_824:.1f} GB"
    if size_bytes >= 1_048_576:
        return f"{size_bytes / 1_048_576:.0f} MB"
    return f"{size_bytes / 1024:.0f} KB"


def _dir_size(path: Path) -> int:
    total = 0
    for f in path.rglob("*"):
        if f.is_file():
            total += f.stat().st_size
    return total


def _parse_date_from_name(name: str) -> datetime | None:
    """从案卷名提取日期（格式 xxx_20260815）。"""
    import re
    m = re.search(r"(\d{8})$", name.rstrip("/"))
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y%m%d")
        except ValueError:
            pass
    m = re.search(r"(\d{4}-\d{2}-\d{2})", name)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%d")
        except ValueError:
            pass
    return None


def cmd_scan(args) -> int:
    cutoff = datetime.now() - timedelta(days=args.before) if args.before else None
    total_size = 0
    candidates = []

    for d in sorted(CASES_DIR.iterdir()):
        if not d.is_dir() or d.name.startswith(("_", ".")):
            continue
        case_date = _parse_date_from_name(d.name)
        if cutoff and case_date and case_date > cutoff:
            continue
        size = _dir_size(d)
        total_size += size
        age_str = f"({case_date.strftime('%Y-%m-%d')})" if case_date else "(未知日期)"
        candidates.append((d.name, size, age_str))

    if not candidates:
        print("没有符合条件的可归档案卷。")
        return 0

    print(f"{'案卷名':<45} {'体积':>10} {'日期'}")
    print("-" * 70)
    for name, size, age in candidates:
        print(f"{name:<45} {_size_human(size):>10} {age}")
    print("-" * 70)
    print(f"共 {len(candidates)} 个案卷，总计 {_size_human(total_size)}")

    if cutoff:
        print(f"\n筛选条件：{args.before} 天前（{cutoff.strftime('%Y-%m-%d')} 之前）")
    return 0


def cmd_binaries(args) -> int:
    big_files: list[tuple[Path, int]] = []
    for f in CASES_DIR.rglob("*"):
        if not f.is_file():
            continue
        if f.stat().st_size < BIG_THRESHOLD:
            continue
        if f.suffix.lower() in BINARY_EXTS or any(
            f.name.endswith(ext) for ext in (".tar.gz",)
        ):
            big_files.append((f, f.stat().st_size))

    if not big_files:
        print("没有超过 50MB 的二进制文件。")
        return 0

    big_files.sort(key=lambda x: -x[1])
    total = sum(s for _, s in big_files)

    print(f"{'体积':>10} {'文件路径'}")
    print("-" * 80)
    for f, size in big_files:
        rel = f.relative_to(ENGINE_ROOT)
        print(f"{_size_human(size):>10} {rel}")
    print("-" * 80)
    print(f"共 {len(big_files)} 个大二进制文件，总计 {_size_human(total)}")
    print("\n提示：已完成分析的 APK/DMG/EXE 可安全删除原件（逆向产物在对应子目录）")
    return 0


def cmd_archive(args) -> int:
    if not args.dest:
        print("需要指定 --dest 归档目录（如 /Volumes/NAS/cases/）")
        return 1

    dest = Path(args.dest)
    if not dest.exists():
        print(f"目标目录不存在: {dest}")
        return 1

    cutoff = datetime.now() - timedelta(days=args.before) if args.before else None
    archived = 0

    for d in sorted(CASES_DIR.iterdir()):
        if not d.is_dir() or d.name.startswith(("_", ".")):
            continue
        case_date = _parse_date_from_name(d.name)
        if cutoff and case_date and case_date > cutoff:
            continue

        archive_path = dest / f"{d.name}.tar.gz"
        if archive_path.exists():
            print(f"  跳过（已存在）: {d.name}")
            continue

        size = _dir_size(d)
        print(f"  归档 {d.name} ({_size_human(size)})...")

        if not args.dry_run:
            subprocess.run(
                ["tar", "czf", str(archive_path), "-C", str(CASES_DIR), d.name],
                check=True,
            )
        archived += 1

    print(f"\n{'[DRY RUN] ' if args.dry_run else ''}归档 {archived} 个案卷到 {dest}")
    if not args.dry_run and archived > 0:
        print("确认归档完整后，可手动删除原始目录以释放空间。")
    return 0


def cmd_clean_binaries(args) -> int:
    to_clean: list[tuple[Path, int]] = []

    for f in CASES_DIR.rglob("*"):
        if not f.is_file() or f.stat().st_size < BIG_THRESHOLD:
            continue
        if f.suffix.lower() not in BINARY_EXTS and not f.name.endswith(".tar.gz"):
            continue
        parent_name = f.parent.name
        if parent_name in ("apk", "client", "exe", "backup_client"):
            to_clean.append((f, f.stat().st_size))

    if not to_clean:
        print("没有可安全清理的大二进制文件。")
        return 0

    total = sum(s for _, s in to_clean)
    for f, size in to_clean:
        rel = f.relative_to(ENGINE_ROOT)
        action = "[DRY] 将删除" if args.dry_run else "删除"
        print(f"  {action}: {rel} ({_size_human(size)})")
        if not args.dry_run:
            f.unlink()

    print(f"\n{'[DRY RUN] ' if args.dry_run else ''}清理 {len(to_clean)} 个文件，"
          f"释放 {_size_human(total)}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="案卷归档工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="扫描可归档候选")
    p_scan.add_argument("--before", type=int, default=0,
                        help="仅列出 N 天前的案卷（0=全部）")

    sub.add_parser("binaries", help="列出大二进制文件（>50MB）")

    p_archive = sub.add_parser("archive", help="归档案卷到外部目录")
    p_archive.add_argument("--before", type=int, default=30)
    p_archive.add_argument("--dest", help="归档目标目录")
    p_archive.add_argument("--dry-run", action="store_true")

    p_clean = sub.add_parser("clean-binaries", help="清理已分析的大二进制")
    p_clean.add_argument("--dry-run", action="store_true", default=True)

    args = ap.parse_args()

    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "binaries":
        return cmd_binaries(args)
    if args.cmd == "archive":
        return cmd_archive(args)
    if args.cmd == "clean-binaries":
        return cmd_clean_binaries(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
