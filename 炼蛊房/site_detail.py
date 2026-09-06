#!/usr/bin/env python3
"""创建「站点详情/<中文名>/」的人类浏览入口，不移动案卷真源。"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, UTC
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
DETAILS = ROOT / "站点详情"
CASES = ROOT / "案卷"
TEMPLATE = DETAILS / "_模板" / "站点概览.md"
NAME_MAP = DETAILS / "_站点名称映射.json"
CATEGORY_MAP = DETAILS / "_站点分类映射.json"
SKIP_CASE_DIRS = {
    "reports",
    "cards",
    "exports",
    "恢复报告",
    "_board",
    "_archive",
    "_templates",
    "_kb",
}
CATEGORIES = (
    "发卡网",
    "赌博台",
    "商城",
    "盘口站",
    "TG与账号平台",
    "基础设施与工具",
    "待分类",
)
SITE_SKIP_DIRS = {"分类", *CATEGORIES}


def _safe_name(value: str) -> str:
    name = value.strip()
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ValueError("站点中文名不能为空，且不能包含路径分隔符")
    return name


def _link(link: Path, target: Path, force: bool) -> None:
    if link.exists() or link.is_symlink():
        if link.is_symlink() and link.resolve() == target.resolve():
            return
        if not force:
            raise FileExistsError(f"已存在：{link}（需要覆盖请加 --force）")
        link.unlink()
    link.symlink_to(Path(os.path.relpath(target, link.parent)))


def _write_overview(
    destination: Path,
    *,
    site: str,
    case: str,
    url: str,
    business: str,
    scope: str,
    force: bool,
) -> None:
    if destination.exists() and not force:
        raise FileExistsError(f"已存在：{destination}（需要覆盖请加 --force）")
    text = TEMPLATE.read_text(encoding="utf-8")
    text = text.replace("<中文站点名>", site)
    text = text.replace("- 案卷 ID：", f"- 案卷 ID：`{case}`")
    text = text.replace("- 入口：", f"- 入口：{url or '—'}")
    text = text.replace("- 业务类型：", f"- 业务类型：{business or '—'}")
    text = text.replace(
        "- 授权：`授权范围` / 单站授权：",
        f"- 授权：`授权范围` / 单站授权：`{scope or '—'}`",
    )
    text = text.replace("- 最后更新：", f"- 最后更新：{datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}")
    destination.write_text(text, encoding="utf-8")


def _report_paths(case_dir: Path) -> list[str]:
    """仅关联案卷根的报告 Markdown，不扫描原始证据子树。"""
    reports = [
        path.relative_to(ROOT).as_posix()
        for path in sorted(case_dir.glob("*.md"))
        if "报告" in path.name or path.name in {"DRAFT_REPORT.md", "REPORT.md"}
    ]
    return reports


def _case_meta(case: str) -> dict:
    path = CASES / case / "triage.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _name_map() -> dict[str, str]:
    if not NAME_MAP.is_file():
        return {}
    try:
        data = json.loads(NAME_MAP.read_text(encoding="utf-8"))
        return {str(key): _safe_name(str(value)) for key, value in data.items()}
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


def _category_map() -> dict[str, str]:
    if not CATEGORY_MAP.is_file():
        return {}
    try:
        data = json.loads(CATEGORY_MAP.read_text(encoding="utf-8"))
        return {
            str(key): str(value)
            for key, value in data.items()
            if str(value) in CATEGORIES
        }
    except (OSError, json.JSONDecodeError):
        return {}


def _display_name(case: str, meta: dict, names: dict[str, str]) -> str:
    if case in names:
        return names[case]
    url = str(meta.get("url") or "")
    host = (urlparse(url).hostname or "").strip()
    return host or re.sub(r"_20\d{6}$", "", case) or case


def _category_for(site_name: str, case_names: list[str], overrides: dict[str, str]) -> str:
    if site_name in overrides:
        return overrides[site_name]
    text = " ".join([site_name.lower(), *(name.lower() for name in case_names)])
    rules = (
        ("发卡网", ("faka", "card", "kami", "appleid", "accreg", "epay", "tokenpay", "dujiaoshuka")),
        ("盘口站", ("odds", "sportsbook", "盘口", "japan_stock")),
        ("赌博台", ("casino", ".bet", "_bet", "slot", "博彩", "gambling")),
        ("商城", ("mall", "shop", "market", "store", "4399")),
        ("TG与账号平台", ("telegram", "tg", "bot", "line", "band")),
        ("基础设施与工具", ("cdn", "proxy", "cloak", "scan", "api", "cloud", "fanghong")),
    )
    for category, keywords in rules:
        if any(keyword.lower() in text for keyword in keywords):
            return category
    return "待分类"


def _site_category(site: Path, overrides: dict[str, str]) -> str:
    case_names = [link.name for link in (site / "案卷").glob("*") if link.is_symlink()]
    return _category_for(site.name, case_names, overrides)


def _existing_site_dir(site: str) -> Path | None:
    for category in CATEGORIES:
        candidate = DETAILS / category / site
        if candidate.is_dir():
            return candidate
    candidate = DETAILS / site
    return candidate if candidate.is_dir() else None


def _repair_case_links() -> tuple[int, int]:
    """分类移动后重写案卷软链接，保证相对路径仍指向英文真源。"""
    repaired = missing = 0
    for category in CATEGORIES:
        folder = DETAILS / category
        if not folder.is_dir():
            continue
        for site in folder.iterdir():
            if not site.is_dir():
                continue
            for link in (site / "案卷").glob("*"):
                target = CASES / link.name
                if not target.is_dir():
                    missing += 1
                    continue
                _link(link, target, force=True)
                repaired += 1
    return repaired, missing


def cmd_init(args: argparse.Namespace) -> int:
    try:
        site = _safe_name(args.site)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    case = args.case.strip()
    case_dir = CASES / case
    if not case or not case_dir.is_dir():
        print(f"[!] 案卷不存在：{case_dir}", file=sys.stderr)
        return 2
    if not TEMPLATE.is_file():
        print(f"[!] 缺少模板：{TEMPLATE}", file=sys.stderr)
        return 2

    overrides = _category_map()
    detail = _existing_site_dir(site)
    if detail is None:
        category = _category_for(site, [case], overrides)
        detail = DETAILS / category / site
    detail.mkdir(parents=True, exist_ok=True)
    case_links = detail / "案卷"
    if case_links.is_symlink():
        if not args.force:
            print(f"[!] 旧案卷软链接存在：{case_links}（加 --force 迁移为目录）", file=sys.stderr)
            return 1
        case_links.unlink()
    case_links.mkdir(exist_ok=True)
    reports = detail / "报告"
    reports.mkdir(exist_ok=True)
    try:
        overview = detail / "站点概览.md"
        if not overview.exists() or args.force:
            _write_overview(
                overview,
                site=site,
                case=case,
                url=args.url,
                business=args.business,
                scope=args.scope,
                force=args.force,
            )
        _link(case_links / case, case_dir, args.force)
        _link(detail / "AI作业说明.md", DETAILS / "AI作业规范.md", args.force)
        authorization = detail / "授权引用.md"
        if not authorization.exists() or args.force:
            authorization.write_text(
                f"# {site} — 授权引用\n\n"
                f"- 总表：`授权范围`\n"
                f"- 单站授权：`{args.scope or '未指定'}`\n"
                f"- 首个关联案卷：`案卷/{case}/`\n"
                f"- 注意：本文件仅引用授权与案卷，不复制敏感信息。\n",
                encoding="utf-8",
            )
        for report in args.report:
            report_path = (ROOT / report).resolve()
            if not report_path.is_file() or ROOT not in report_path.parents:
                raise ValueError(f"报告路径无效或不在工程内：{report}")
            _link(reports / report_path.name, report_path, args.force)
    except (FileExistsError, OSError, ValueError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    print(f"[+] {detail}")
    print(f"    案卷 -> {case_dir.relative_to(ROOT)}")
    return 0


def cmd_seed(args: argparse.Namespace) -> int:
    """为历史案卷批量建立人类入口；不迁移任何真源数据。"""
    names = _name_map()
    created = skipped = failed = 0
    for case_dir in sorted(CASES.iterdir()):
        if (
            not case_dir.is_dir()
            or case_dir.name.startswith("_")
            or case_dir.name in SKIP_CASE_DIRS
        ):
            continue
        case = case_dir.name
        meta = _case_meta(case)
        site = _display_name(case, meta, names)
        detail = _existing_site_dir(site)
        if detail is None:
            detail = DETAILS / _category_for(site, [case], names) / site
        if detail.exists() and not args.force:
            skipped += 1
            print(f"[*] 跳过已存在：{site} <- {case}")
            continue
        init_args = argparse.Namespace(
            site=site,
            case=case,
            url=str(meta.get("url") or ""),
            business="",
            scope="",
            report=_report_paths(case_dir),
            force=args.force,
        )
        result = cmd_init(init_args)
        if result == 0:
            created += 1
        else:
            failed += 1
    print(f"\nDone: created={created} skipped={skipped} failed={failed}")
    return 1 if failed else 0


def cmd_classify(args: argparse.Namespace) -> int:
    """把站点详情入口归入根目录分类文件夹，不移动案卷真源。"""
    overrides = _category_map()
    sites: list[Path] = []
    for item in DETAILS.iterdir():
        if not item.is_dir() or item.name.startswith("_"):
            continue
        if item.name in CATEGORIES:
            sites.extend(site for site in item.iterdir() if site.is_dir())
        elif item.name not in SITE_SKIP_DIRS:
            sites.append(item)

    moved = skipped = 0
    for site in sorted(sites):
        category = _site_category(site, overrides)
        target = DETAILS / category / site.name
        if site == target:
            continue
        target.parent.mkdir(exist_ok=True)
        if target.exists():
            print(f"[*] 跳过已存在：{target}")
            skipped += 1
            continue
        site.rename(target)
        moved += 1
    repaired, missing = _repair_case_links()
    counts = {
        category: len([site for site in (DETAILS / category).iterdir() if site.is_dir()])
        if (DETAILS / category).is_dir()
        else 0
        for category in CATEGORIES
    }
    print(
        "分类完成："
        + " · ".join(f"{key}={value}" for key, value in counts.items())
        + f" · 移动={moved} · 跳过={skipped} · 链接修复={repaired} · 缺失案卷={missing}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="新建站点详情入口（不移动案卷）")
    sub = parser.add_subparsers(dest="cmd", required=True)
    init = sub.add_parser("init", help="创建中文站点名目录、概览与案卷软链接")
    init.add_argument("--site", required=True, help="中文业务名，例如 UU科技")
    init.add_argument("--case", required=True, help="案卷 下的案卷 ID")
    init.add_argument("--url", default="")
    init.add_argument("--business", default="")
    init.add_argument("--scope", default="")
    init.add_argument("--report", action="append", default=[], help="工程内正式报告相对路径，可重复")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_init)

    seed = sub.add_parser("seed", help="为全部历史案卷建立站点详情入口")
    seed.add_argument("--force", action="store_true", help="覆盖同名入口的概览和软链接")
    seed.set_defaults(func=cmd_seed)

    classify = sub.add_parser("classify", help="把站点详情入口移动至根目录分类文件夹")
    classify.set_defaults(func=cmd_classify)
    args = parser.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
