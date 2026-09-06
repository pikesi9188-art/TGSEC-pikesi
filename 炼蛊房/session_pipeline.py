#!/usr/bin/env python3
"""会话流水线：Cookie 校验导入 → Playwright storage → 会员 API 探针。

示例:
  python3 炼蛊房/session_pipeline.py \\
    --domain 授权站 \\
    --input cookies.json \\
    --case <案卷> \\
    --require-session --require-cf
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, UTC
from pathlib import Path

_OPS = Path(__file__).resolve().parent
if str(_OPS) not in sys.path:
    sys.path.insert(0, str(_OPS))

from scope_lib import ENGINE, host_of, in_scope  # noqa: E402

# 默认会员/个人中心探针（ACG + 通用）
DEFAULT_PATHS = [
    "/user/dashboard/index",
    "/user/recharge/index",
    "/user/purchase/record",
    "/user/user/index",
    "/user/personal/index",
    "/user/business/index",
    "/user/api/user/info",
    "/user/api/authentication/status",
    "/user/api/index/data",
]


def run_import(args: argparse.Namespace, out_dir: Path) -> int:
    import session_import as si

    # 组装等价 CLI
    argv = [
        "--domain",
        args.domain,
        "--out",
        str(out_dir),
        "--scheme",
        args.scheme,
    ]
    if args.input:
        argv += ["--input", args.input]
    if args.stdin:
        argv += ["--stdin"]
    if args.require_session:
        argv += ["--require-session"]
    if args.require_cf:
        argv += ["--require-cf"]
    if args.session_names:
        argv += ["--session-names", args.session_names]

    old = sys.argv
    try:
        sys.argv = ["session_import.py"] + argv
        return int(si.main() or 0)
    finally:
        sys.argv = old


def probe_with_playwright(
    *,
    base: str,
    storage: Path,
    paths: list[str],
    timeout_ms: int = 60000,
) -> list[dict]:
    from playwright.sync_api import sync_playwright

    results: list[dict] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            storage_state=str(storage),
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ),
            locale="zh-CN",
        )
        page = context.new_page()
        page.goto(base.rstrip("/") + "/", wait_until="domcontentloaded", timeout=timeout_ms)
        time.sleep(2)
        for path in paths:
            r = page.evaluate(
                """async (path) => {
                try {
                  const resp = await fetch(path, {credentials:'include', redirect:'follow'});
                  const t = await resp.text();
                  const title = (t.match(/<title[^>]*>([^<]+)/i) || [,''])[1].trim();
                  const looksLogin = /登录会话过期|请重新登录|请先登录|Just a moment|请稍候/i.test(t)
                    || /登录会话过期|请重新登录|请先登录/.test(title);
                  return {
                    status: resp.status,
                    title,
                    len: t.length,
                    looksLogin,
                    head: t.slice(0, 240).replace(/\\s+/g, ' '),
                  };
                } catch (e) {
                  return {error: String(e)};
                }
            }""",
                path,
            )
            results.append({"path": path, **r})
        browser.close()
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description="会话导入 + 会员 API 探针")
    ap.add_argument("--domain", required=True)
    ap.add_argument("--input", "-i")
    ap.add_argument("--stdin", action="store_true")
    ap.add_argument("--case", required=True)
    ap.add_argument("--out", default="", help="默认 案卷/.../接管/session")
    ap.add_argument("--require-session", action="store_true")
    ap.add_argument("--require-cf", action="store_true")
    ap.add_argument("--session-names", default="")
    ap.add_argument("--scheme", default="https")
    ap.add_argument("--paths", default="", help="逗号分隔；默认 ACG/通用会员路径")
    ap.add_argument("--skip-probe", action="store_true")
    ap.add_argument("--skip-scope-check", action="store_true")
    args = ap.parse_args()

    if not args.skip_scope_check and not in_scope(args.domain):
        print(f"[!] {args.domain} 不在 scope.company.json", file=sys.stderr)
        return 1

    out = Path(args.out) if args.out else (
        ENGINE / "案卷" / args.case / "接管" / "session"
    )
    out.mkdir(parents=True, exist_ok=True)

    code = run_import(args, out)
    if code != 0:
        print("[!] session_import 失败，中止探针", file=sys.stderr)
        return code

    storage = out / "storage_state.json"
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "domain": host_of(args.domain),
        "case": args.case,
        "import_ok": True,
        "storage_state": str(storage),
        "probes": [],
    }

    if args.skip_probe:
        (out / "pipeline_report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"[+] import only → {out}")
        return 0

    paths = [p.strip() for p in args.paths.split(",") if p.strip()] or list(DEFAULT_PATHS)
    base = f"{args.scheme}://{host_of(args.domain)}"
    try:
        probes = probe_with_playwright(base=base, storage=storage, paths=paths)
    except Exception as e:
        print(f"[!] Playwright 探针失败: {e}", file=sys.stderr)
        report["probe_error"] = str(e)
        (out / "pipeline_report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return 2

    report["probes"] = probes
    authed = [p for p in probes if not p.get("looksLogin") and not p.get("error") and p.get("status") == 200]
    report["authed_paths"] = [p["path"] for p in authed]
    report["session_alive"] = len(authed) > 0

    (out / "member_probe.json").write_text(
        json.dumps(probes, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (out / "pipeline_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    md = [
        "# 会话流水线报告",
        "",
        f"- domain: `{report['domain']}`",
        f"- session_alive: **{report['session_alive']}**",
        f"- storage: `{storage}`",
        "",
        "| path | status | login墙 | title |",
        "|------|--------|---------|-------|",
    ]
    for p in probes:
        md.append(
            f"| `{p.get('path')}` | {p.get('status', p.get('error', ''))} | "
            f"{'Y' if p.get('looksLogin') else 'n'} | {p.get('title', '')[:40]} |"
        )
    (out / "PIPELINE_REPORT.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print(f"[{'OK' if report['session_alive'] else 'WEAK'}] session_alive={report['session_alive']} → {out}")
    for p in probes[:8]:
        flag = "AUTH" if (not p.get("looksLogin") and p.get("status") == 200) else "----"
        print(f"  [{flag}] {p.get('status')} {p.get('path')} :: {p.get('title', '')[:50]}")
    return 0 if report["session_alive"] else 3


if __name__ == "__main__":
    sys.exit(main())
