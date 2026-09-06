#!/usr/bin/env python3
"""
scrapling_fetch.py — scope 门控的 Scrapling 单页抓取工具
用法:
  python3 tools/scrapling/bin/scrapling_fetch.py <url> [options]
  python3 tools/scrapling/bin/scrapling_fetch.py https://target.com/admin --mode stealthy --css '#content' --out exports/...
"""
import argparse
import fnmatch
import json
import sys
from datetime import datetime
from pathlib import Path

def _kit_ops_dir(start: Path) -> Path:
    here = start.resolve()
    if here.is_file():
        here = here.parent
    for p in (here, *here.parents):
        fang = p / "炼蛊房"
        if (fang / "scope_lib.py").is_file():
            return fang
        ops = p / "tools" / "ops"
        if (ops / "scope_lib.py").is_file():
            return ops
    return here

WORKSPACE = Path(__file__).resolve().parents[3]
SCOPE_FILE = (WORKSPACE / "态度蛊.json" if (WORKSPACE / "态度蛊.json").is_file() else WORKSPACE / "config" / "scope.company.json")
SCOPE_SITES_DIR = WORKSPACE / "config" / "scope_sites"
EXPORTS_DIR = (WORKSPACE / "案卷" if (WORKSPACE / "案卷").is_dir() else WORKSPACE / "exports" / "bot-recovery")


def load_allowed_targets() -> list[str]:
    targets: list[str] = []
    if SCOPE_FILE.exists():
        targets.extend(json.loads(SCOPE_FILE.read_text()).get("targets", []))
    if SCOPE_SITES_DIR.exists():
        for f in SCOPE_SITES_DIR.glob("*.json"):
            try:
                targets.extend(json.loads(f.read_text()).get("targets", []))
            except Exception:
                pass
    return targets


def is_authorized(url: str, allowed: list[str]) -> bool:
    from urllib.parse import urlparse
    host = urlparse(url).hostname or url.split(":")[0]
    for pattern in allowed:
        if fnmatch.fnmatch(host, pattern) or host == pattern:
            return True
    return False


def fetch_page(url: str, mode: str, css: str | None, solve_cf: bool, proxy: str | None):
    try:
        from scrapling.fetchers import Fetcher, StealthyFetcher, DynamicFetcher
    except ImportError:
        print("[Scrapling] 未安装。请先运行: pip install 'scrapling[fetchers]' && scrapling install")
        sys.exit(1)

    kwargs: dict = {}
    if proxy:
        kwargs["proxy"] = proxy

    if mode == "http":
        page = Fetcher.get(url, stealthy_headers=True, **kwargs)
    elif mode == "stealthy":
        kwargs["headless"] = True
        kwargs["network_idle"] = True
        if solve_cf:
            kwargs["solve_cloudflare"] = True
        page = StealthyFetcher.fetch(url, **kwargs)
    elif mode == "browser":
        kwargs["headless"] = True
        kwargs["network_idle"] = True
        page = DynamicFetcher.fetch(url, **kwargs)
    else:
        print(f"[Scrapling] 未知模式: {mode}")
        sys.exit(1)

    if css:
        elements = page.css(css)
        content = "\n".join(e.clean_text for e in elements)
    else:
        content = page.get_all_text(separator="\n")

    return content, page.status


def main() -> None:
    parser = argparse.ArgumentParser(description="Scrapling scope-gated fetcher")
    parser.add_argument("url", help="目标 URL")
    parser.add_argument("--mode", choices=["http", "browser", "stealthy"], default="http",
                        help="http=快速HTTP | browser=JS渲染 | stealthy=反爬绕过（默认http）")
    parser.add_argument("--css", help="CSS 选择器，提取特定元素")
    parser.add_argument("--solve-cf", action="store_true", help="自动解 Cloudflare Turnstile（需 stealthy 模式）")
    parser.add_argument("--proxy", help="代理地址，如 http://127.0.0.1:8080")
    parser.add_argument("--out", help="输出文件路径（默认打印到 stdout）")
    parser.add_argument("--case", default="", help="案卷名，写入 案卷/<case>/scrapling/")
    parser.add_argument("--force", action="store_true", help="跳过 scope 检查（谨慎使用）")
    args = parser.parse_args()

    if not args.force:
        allowed = load_allowed_targets()
        if not is_authorized(args.url, allowed):
            print(f"[Scrapling] ❌ {args.url!r} 不在 scope，请先授权")
            sys.exit(1)
        print(f"[Scrapling] ✅ {args.url!r} 已授权")

    content, status = fetch_page(args.url, args.mode, args.css, args.solve_cf, args.proxy)
    print(f"[Scrapling] HTTP {status} | {len(content)} 字符")

    out_path = args.out
    if not out_path and args.case:
        from urllib.parse import urlparse
        host = (urlparse(args.url).hostname or "page").replace(":", "_")
        out_path = str(EXPORTS_DIR / args.case / "scrapling" / f"{host}.md")
    if out_path:
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content, encoding="utf-8")
        print(f"[Scrapling] 已写入: {out}")
    else:
        print(content[:5000])
        if len(content) > 5000:
            print(f"\n... [已截断，完整内容 {len(content)} 字符] ...")


if __name__ == "__main__":
    main()
