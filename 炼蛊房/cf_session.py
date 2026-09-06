#!/usr/bin/env python3
"""CF / Turnstile 人机分工：headed 过验证存 storage；headless 只消费会话。

capture（有头）:
  python3 炼蛊房/cf_session.py capture \\
    --url https://授权站/ --case <案卷>

consume（无头，只带已有 storage 打点）:
  python3 炼蛊房/cf_session.py consume \\
    --url https://授权站/ --case <案卷> --paths /user/dashboard/index
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, UTC
from pathlib import Path

_OPS = Path(__file__).resolve().parent
ENGINE = (_OPS.parent if (_OPS.parent / "杀招").is_dir() else (_OPS.parent if (_OPS.parent / "杀招").is_dir() else _OPS.parents[1]))
if str(_OPS) not in sys.path:
    sys.path.insert(0, str(_OPS))

from scope_lib import host_of, in_scope  # noqa: E402


def case_session_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "接管" / "session"
    d.mkdir(parents=True, exist_ok=True)
    return d


def cmd_capture(args: argparse.Namespace) -> int:
    from playwright.sync_api import sync_playwright

    host = host_of(args.url)
    if not args.skip_scope_check and not in_scope(host):
        print(f"[!] {host} 不在 scope", file=sys.stderr)
        return 1

    out = Path(args.out) if args.out else case_session_dir(args.case)
    out.mkdir(parents=True, exist_ok=True)
    storage = out / "storage_state.json"

    print("[*] 启动有头浏览器，请手动完成 Cloudflare / Turnstile / 登录…")
    print(f"    完成后回到终端按回车保存 → {storage}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context(
            locale="zh-CN",
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ),
        )
        page = context.new_page()
        page.goto(args.url, wait_until="domcontentloaded", timeout=args.timeout_ms)
        if args.auto_wait:
            # 等到标题不再是挑战页，或超时
            deadline = time.time() + args.auto_wait
            while time.time() < deadline:
                title = page.title()
                if title and "请稍候" not in title and "Just a moment" not in title:
                    print(f"[*] 页面标题已变化: {title}")
                    break
                time.sleep(1)
        if not args.no_prompt:
            try:
                input(">>> 验证/登录完成后按 Enter 保存 storage … ")
            except EOFError:
                print("[!] 非交互环境，等待 3s 后保存当前状态")
                time.sleep(3)
        context.storage_state(path=str(storage))
        cookies = context.cookies()
        (out / "cookies.json").write_text(
            json.dumps(cookies, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        meta = {
            "generated_at": datetime.now(UTC).isoformat(),
            "mode": "headed_capture",
            "url": args.url,
            "title": page.title(),
            "cookie_names": [c.get("name") for c in cookies],
            "storage_state": str(storage),
        }
        (out / "cf_capture.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        browser.close()

    print(f"[+] 已保存 {storage}")
    print("    无头消费: python3 炼蛊房/cf_session.py consume "
          f"--url {args.url} --case {args.case}")
    print("    或: python3 炼蛊房/session_pipeline.py --domain "
          f"{host} --case {args.case} --skip-probe  # 需先有 cookies；推荐用 consume")
    return 0


def cmd_consume(args: argparse.Namespace) -> int:
    from playwright.sync_api import sync_playwright

    host = host_of(args.url)
    if not args.skip_scope_check and not in_scope(host):
        print(f"[!] {host} 不在 scope", file=sys.stderr)
        return 1

    out = Path(args.out) if args.out else case_session_dir(args.case)
    storage = Path(args.storage) if args.storage else out / "storage_state.json"
    if not storage.is_file():
        print(f"[!] 缺少 storage: {storage}", file=sys.stderr)
        print("    先跑: cf_session.py capture …", file=sys.stderr)
        return 2

    paths = [p.strip() for p in (args.paths or "").split(",") if p.strip()]
    if not paths:
        paths = [
            "/",
            "/user/dashboard/index",
            "/user/api/index/data",
            "/user/api/index/pay",
        ]

    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(storage_state=str(storage), locale="zh-CN")
        page = context.new_page()
        page.goto(args.url, wait_until="domcontentloaded", timeout=args.timeout_ms)
        time.sleep(1.5)
        title0 = page.title()
        challenged = "请稍候" in title0 or "Just a moment" in title0
        for path in paths:
            r = page.evaluate(
                """async (path) => {
                  const resp = await fetch(path, {credentials:'include'});
                  const t = await resp.text();
                  const title = (t.match(/<title[^>]*>([^<]+)/i)||[,''])[1].trim();
                  const challenge = /请稍候|Just a moment/i.test(title)||/请稍候|Just a moment/i.test(t.slice(0,500));
                  const loginWall = /登录会话过期|请重新登录|请先登录/i.test(title+t.slice(0,800));
                  return {status: resp.status, title, challenge, loginWall, len: t.length};
                }""",
                path,
            )
            results.append({"path": path, **r})
            flag = "CF" if r.get("challenge") else ("LOGIN" if r.get("loginWall") else "OK")
            print(f"  [{flag}] {r.get('status')} {path} :: {r.get('title','')[:40]}")
        browser.close()

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "mode": "headless_consume",
        "storage_state": str(storage),
        "initial_challenge": challenged,
        "results": results,
        "usable": (not challenged)
        and any(not x.get("challenge") and not x.get("loginWall") for x in results),
    }
    (out / "cf_consume.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[{'OK' if report['usable'] else 'FAIL'}] usable={report['usable']} → {out / 'cf_consume.json'}")
    if challenged:
        print("[!] storage 已失效或未过 CF，请重新 capture（有头）")
        return 3
    return 0 if report["usable"] else 4


def main() -> int:
    ap = argparse.ArgumentParser(description="CF/Turnstile 人机分工")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("capture", help="有头过验证并保存 storage")
    p.add_argument("--url", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--out", default="")
    p.add_argument("--timeout-ms", type=int, default=120000)
    p.add_argument("--auto-wait", type=int, default=0, help="秒；等到非挑战页")
    p.add_argument("--no-prompt", action="store_true")
    p.add_argument("--skip-scope-check", action="store_true")
    p.set_defaults(func=cmd_capture)

    p = sub.add_parser("consume", help="无头只消费 storage")
    p.add_argument("--url", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--storage", default="")
    p.add_argument("--out", default="")
    p.add_argument("--paths", default="")
    p.add_argument("--timeout-ms", type=int, default=60000)
    p.add_argument("--skip-scope-check", action="store_true")
    p.set_defaults(func=cmd_consume)

    args = ap.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
