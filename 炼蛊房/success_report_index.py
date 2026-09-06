#!/usr/bin/env python3
"""重建呈文柜技术链索引（开源不带这棵树）。"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "呈文柜"
RESULTS = REPORTS / "按闭环结果"
TECHNIQUES = REPORTS / "按技术链"
BUSINESSES = REPORTS / "按业务线"
META = REPORTS / "_meta"
DETAILS = ROOT / "站点详情"
BUSINESS_OVERRIDES = META / "业务覆盖映射.json"
BUSINESS_CATEGORIES = ("发卡网", "赌博台", "商城", "盘口站", "TG与账号平台", "基础设施与工具")


def link(link_path: Path, target: Path) -> None:
    if link_path.exists() or link_path.is_symlink():
        link_path.unlink()
    link_path.symlink_to(Path(os.path.relpath(target, link_path.parent)))


def report_dirs() -> list[tuple[str, str, Path]]:
    rows: list[tuple[str, str, Path]] = []
    for outcome in sorted(path for path in RESULTS.iterdir() if path.is_dir()):
        for technique in sorted(path for path in outcome.iterdir() if path.is_dir()):
            for site in sorted(path for path in technique.iterdir() if path.is_dir()):
                if (site / "报告.md").is_file() or (site / "原始报告.md").is_file():
                    rows.append((outcome.name, technique.name, site))
    return rows


def business_aliases() -> dict[str, str]:
    aliases: dict[str, str] = {}
    for category in BUSINESS_CATEGORIES:
        folder = DETAILS / category
        if not folder.is_dir():
            continue
        for site in folder.iterdir():
            if not site.is_dir():
                continue
            aliases[site.name.lower()] = category
            overview = site / "站点概览.md"
            if overview.is_file():
                text = overview.read_text(encoding="utf-8", errors="replace")
                match = re.search(r"^- 入口：(.+)$", text, re.M)
                if match:
                    host = urlparse(match.group(1).strip()).hostname
                    if host:
                        aliases[host.lower()] = category
    if BUSINESS_OVERRIDES.is_file():
        try:
            data = json.loads(BUSINESS_OVERRIDES.read_text(encoding="utf-8"))
            for key, value in data.items():
                if value in BUSINESS_CATEGORIES:
                    aliases[str(key).lower()] = value
        except (OSError, json.JSONDecodeError, TypeError):
            pass
    return aliases


def normalize_name(value: str) -> str:
    value = value.lower().strip()
    for prefix in ("www.", "h5.", "shop.", "admin.", "api."):
        if value.startswith(prefix):
            return value[len(prefix) :]
    return value


def business_for_report(site: str, outcome: str, technique: str, aliases: dict[str, str]) -> str:
    candidates = [site.lower(), normalize_name(site)]
    for candidate in candidates:
        if candidate in aliases:
            return aliases[candidate]
    fuzzy = {
        category
        for alias, category in aliases.items()
        if len(alias) >= 5 and (alias in candidates[-1] or candidates[-1] in alias)
    }
    if len(fuzzy) == 1:
        return fuzzy.pop()
    if outcome in {"成功出卡", "未出卡"}:
        return "发卡网"
    text = f"{site} {technique}".lower()
    if any(word in text for word in ("tg", "telegram", "session", "云控", "账号")):
        return "TG与账号平台"
    if any(word in text for word in ("赌场", "娱乐城", "博彩", "体育", "交易所", "股票", "盘口")):
        return "赌博台"
    if any(word in text for word in ("actuator", "oss", "minio", "sql", "cloud", "服务端")):
        return "基础设施与工具"
    return "未匹配"


def reset_indexes() -> None:
    for root in (TECHNIQUES, BUSINESSES):
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_symlink():
                path.unlink()


def prune_empty_index_dirs() -> None:
    for root in (TECHNIQUES, BUSINESSES):
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*"), reverse=True):
            if path.is_dir() and not any(path.iterdir()):
                path.rmdir()


def main() -> int:
    parser = argparse.ArgumentParser(description="重建成功报告交叉索引（只建软链接）")
    parser.add_argument("--reset", action="store_true", help="删除旧索引软链接后重建")
    args = parser.parse_args()
    if not RESULTS.is_dir():
        parser.error(f"缺少报告真源：{RESULTS}")

    TECHNIQUES.mkdir(exist_ok=True)
    BUSINESSES.mkdir(exist_ok=True)
    META.mkdir(exist_ok=True)
    if args.reset:
        reset_indexes()

    aliases = business_aliases()
    entries: list[dict[str, str]] = []
    for outcome, technique, site in report_dirs():
        tech_folder = TECHNIQUES / technique
        tech_folder.mkdir(exist_ok=True)
        link(tech_folder / f"{outcome}·{site.name}", site)

        business = business_for_report(site.name, outcome, technique, aliases)
        business_folder = BUSINESSES / business
        business_folder.mkdir(exist_ok=True)
        link(business_folder / f"{outcome}·{technique}·{site.name}", site)

        entries.append(
            {
                "site": site.name,
                "outcome": outcome,
                "technique": technique,
                "business": business,
                "report": str(site.relative_to(REPORTS)),
            }
        )

    (META / "INDEX.json").write_text(
        json.dumps(entries, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    prune_empty_index_dirs()
    print(f"已建立 {len(entries)} 条报告索引；业务未匹配 {sum(item['business'] == '未匹配' for item in entries)} 条")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
