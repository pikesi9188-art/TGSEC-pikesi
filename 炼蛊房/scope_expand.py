#!/usr/bin/env python3
"""从已授权主站发现的中转/支付域 → 静默并入 scope（不询问）。

示例:
  python3 炼蛊房/scope_expand.py --grant web.example.com --case example_20260818 --note "用户授权"
  python3 炼蛊房/scope_expand.py --compact
  python3 炼蛊房/scope_expand.py \\
    --parent 授权站 \\
    --add api.授权站 \\
    --site-scope 授权范围/scope.tghaopf.json \\
    --case <案卷> \\
    --note "TokenPay 跳转"
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_OPS = Path(__file__).resolve().parent
if str(_OPS) not in sys.path:
    sys.path.insert(0, str(_OPS))

from scope_lib import ENGINE, compact_company, grant, silent_expand  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="授权写入 / 静默扩权 / 压缩总表")
    ap.add_argument("--compact", action="store_true", help="压缩 scope.company.json（去 https/www 重复）")
    ap.add_argument("--grant", default="", help="新目标写入单站 JSON 并并入 company（不要手改总表）")
    ap.add_argument("--parent", default="", help="已授权主站域名或 URL")
    ap.add_argument("--add", action="append", default=[], help="发现的域名/URL，可重复")
    ap.add_argument("--add-file", help="每行一个域名/URL")
    ap.add_argument("--site-scope", default="", help="单站 scope JSON，同步写入")
    ap.add_argument("--site-id", default="", help="--grant 时的单站文件名")
    ap.add_argument("--case", default="", help="案卷名，写入案卷/scope_expand.json")
    ap.add_argument("--note", default="")
    args = ap.parse_args()

    if args.compact:
        report = compact_company()
        print(json.dumps(report, ensure_ascii=False, indent=2))
        print(f"[+] targets {report['before']} → {report['after']}")
        return 0

    if args.grant:
        report = grant(host=args.grant, case=args.case, note=args.note, site_id=args.site_id)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        print(f"[+] grant {report['host']} → {report['site']}")
        return 0

    if not args.parent:
        print("[!] 需要 --parent --add，或 --grant，或 --compact", file=sys.stderr)
        return 2

    discovered = list(args.add)
    if args.add_file:
        for line in Path(args.add_file).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                discovered.append(line)
    if not discovered:
        print("[!] 需要 --add 或 --add-file", file=sys.stderr)
        return 2

    site = Path(args.site_scope) if args.site_scope else None
    if site and not site.is_file():
        alt = ENGINE / args.site_scope
        if alt.is_file():
            site = alt

    try:
        report = silent_expand(
            parent=args.parent,
            discovered=discovered,
            site_scope=site if site and site.is_file() else None,
            case=args.case,
            note=args.note,
        )
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report.get("skipped_denied"):
        print(f"[*] 跳过基础设施域: {report['skipped_denied']}")
    if report.get("changed"):
        print(f"[+] 已静默扩权 {len(report.get('added_company') or [])} 条 → company")
    else:
        print("[*] 无变更（已在 scope 或全部被拒绝）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
