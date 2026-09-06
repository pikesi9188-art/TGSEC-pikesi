#!/usr/bin/env python3
"""H1 案例库检索 — 来自 72stack-sec（2887 条 High/Critical 公开报告）

用法：
  python3 炼蛊房/h1_search.py --keyword "idor"
  python3 炼蛊房/h1_search.py --keyword "sql injection" --severity critical
  python3 炼蛊房/h1_search.py --cwe "SQL Injection" --limit 20
  python3 炼蛊房/h1_search.py --program kubernetes --limit 10
  python3 炼蛊房/h1_search.py --cve CVE-2021-44228
  python3 炼蛊房/h1_search.py --list-cwe
  python3 炼蛊房/h1_search.py --list-programs
  python3 炼蛊房/h1_search.py --stats
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

SKILL_BASE = Path(__file__).resolve().parents[1] / "杀招" / "七十二层防"
INDEX_FILE = SKILL_BASE / "references" / "h1-reports" / "raw" / "index.json"
WEAKNESS_DIR = SKILL_BASE / "references" / "h1-reports" / "by-weakness"


def load_index() -> list[dict]:
    if not INDEX_FILE.exists():
        sys.exit(f"[h1_search] 找不到索引文件：{INDEX_FILE}\n请确认 72stack-sec 已克隆到 杀招/")
    data = json.loads(INDEX_FILE.read_text(encoding="utf-8"))
    return data["nodes"]


def fmt_row(n: dict, i: int) -> str:
    report = n.get("report", {})
    title = report.get("title", "—")[:72]
    sev = n.get("severity_rating", "?").upper()[:8]
    cwe = (n.get("cwe") or "—")[:35]
    team = (n.get("team") or {}).get("handle", "?")[:20]
    url = report.get("url", "")
    votes = n.get("votes", 0)
    award = n.get("total_awarded_amount")
    award_str = f"${award:.0f}" if award else "—"
    return (
        f"  [{i:4d}] [{sev:<8}] [{team:<20}] votes={votes:3d} bounty={award_str:<8}\n"
        f"         {title}\n"
        f"         CWE: {cwe}\n"
        f"         {url}\n"
    )


def cmd_search(args: argparse.Namespace) -> None:
    nodes = load_index()
    results = nodes

    if args.keyword:
        kw = args.keyword.lower()
        results = [
            n for n in results
            if kw in (n.get("report", {}).get("title", "") or "").lower()
            or kw in (n.get("cwe") or "").lower()
            or any(kw in c.lower() for c in n.get("cve_ids", []))
        ]

    if args.cwe:
        cwe_q = args.cwe.lower()
        results = [n for n in results if cwe_q in (n.get("cwe") or "").lower()]

    if args.severity:
        sev = args.severity.lower()
        results = [n for n in results if (n.get("severity_rating") or "").lower() == sev]

    if args.program:
        prog = args.program.lower()
        results = [
            n for n in results
            if prog in (n.get("team", {}) or {}).get("handle", "").lower()
        ]

    if args.cve:
        cve = args.cve.upper()
        results = [n for n in results if cve in [c.upper() for c in n.get("cve_ids", [])]]

    # 按 votes 降序排列
    results = sorted(results, key=lambda n: n.get("votes", 0), reverse=True)
    total = len(results)
    shown = results[: args.limit]

    print(f"\n[h1_search] 命中 {total} 条（显示前 {len(shown)} 条，按 votes 排序）\n")
    for i, n in enumerate(shown, 1):
        print(fmt_row(n, i))

    if total > args.limit:
        print(f"  … 还有 {total - args.limit} 条，加 --limit 参数查看更多")


def cmd_stats(nodes: list[dict]) -> None:
    sev_cnt: Counter = Counter()
    cwe_cnt: Counter = Counter()
    team_cnt: Counter = Counter()

    for n in nodes:
        sev_cnt[n.get("severity_rating", "unknown")] += 1
        cwe_cnt[(n.get("cwe") or "unknown")] += 1
        team_cnt[(n.get("team") or {}).get("handle", "unknown")] += 1

    print(f"\n[h1_search] 数据库统计（共 {len(nodes)} 条）\n")

    print("── 严重程度分布 ──")
    for sev, cnt in sorted(sev_cnt.items(), key=lambda x: -x[1]):
        print(f"  {sev:<12}: {cnt:4d}")

    print("\n── Top 20 CWE 类型 ──")
    for cwe, cnt in cwe_cnt.most_common(20):
        print(f"  {cnt:4d}  {cwe}")

    print("\n── Top 20 项目（按报告数）──")
    for team, cnt in team_cnt.most_common(20):
        print(f"  {cnt:4d}  {team}")


def cmd_list_cwe(nodes: list[dict]) -> None:
    cwe_cnt: Counter = Counter()
    for n in nodes:
        cwe_cnt[(n.get("cwe") or "unknown")] += 1
    print(f"\n[h1_search] 所有 CWE 类型（共 {len(cwe_cnt)} 种）\n")
    for cwe, cnt in cwe_cnt.most_common():
        print(f"  {cnt:4d}  {cwe}")


def cmd_list_programs(nodes: list[dict]) -> None:
    team_cnt: Counter = Counter()
    for n in nodes:
        h = (n.get("team") or {}).get("handle", "unknown")
        team_cnt[h] += 1
    print(f"\n[h1_search] 所有项目（共 {len(team_cnt)} 个）\n")
    for team, cnt in team_cnt.most_common():
        print(f"  {cnt:4d}  {team}")


def cmd_weakness_files() -> None:
    """列出 by-weakness/ 下可直接 Read 的 md 文件。"""
    files = sorted(WEAKNESS_DIR.glob("*.md"))
    print(f"\n[h1_search] by-weakness/ 分类文件（共 {len(files)} 个）\n")
    for f in files:
        size = f.stat().st_size
        print(f"  {size:7d}B  {f.name}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="H1 案例库检索（72stack-sec · 2887 条 High/Critical）"
    )
    ap.add_argument("--keyword", "-k", help="标题/CWE 关键词（模糊匹配）")
    ap.add_argument("--cwe", help="按 CWE 类型筛选（部分匹配）")
    ap.add_argument("--severity", choices=["critical", "high"], help="严重级别")
    ap.add_argument("--program", help="按 H1 项目 handle 筛选（部分匹配）")
    ap.add_argument("--cve", help="按 CVE 编号精确匹配（如 CVE-2021-44228）")
    ap.add_argument("--limit", type=int, default=15, help="显示条数（默认 15）")
    ap.add_argument("--stats", action="store_true", help="显示数据库整体统计")
    ap.add_argument("--list-cwe", action="store_true", help="列出所有 CWE 类型及数量")
    ap.add_argument("--list-programs", action="store_true", help="列出所有 H1 项目")
    ap.add_argument("--list-weakness-files", action="store_true", help="列出 by-weakness/ 分类 md 文件")
    args = ap.parse_args()

    if args.list_weakness_files:
        cmd_weakness_files()
        return

    nodes = load_index()

    if args.stats:
        cmd_stats(nodes)
        return
    if args.list_cwe:
        cmd_list_cwe(nodes)
        return
    if args.list_programs:
        cmd_list_programs(nodes)
        return

    if not any([args.keyword, args.cwe, args.severity, args.program, args.cve]):
        ap.print_help()
        print("\n提示：不带筛选条件时请用 --stats 看总览")
        return

    cmd_search(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n中断")
    except Exception as exc:
        print(f"[!] {exc}")
        raise SystemExit(1)
