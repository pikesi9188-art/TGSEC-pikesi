#!/usr/bin/env python3
"""
scrapling_spider.py — scope 门控的 Scrapling 并发爬虫（用于资产测绘）
用法:
  python3 tools/scrapling/bin/scrapling_spider.py <target_domain> [--depth 2] [--out-dir exports/.../scrapling/]

爬取目标站所有页面，输出 links.json + pages.jsonl（含路径、标题、关键词）
常用于授权站点的全量路由发现、JS文件收集、API端点枚举。
"""
import argparse
import asyncio
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
from urllib.parse import urlparse

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


def is_authorized(host: str, allowed: list[str]) -> bool:
    for pattern in allowed:
        if fnmatch.fnmatch(host, pattern) or host == pattern:
            return True
    return False


def run_spider(start_url: str, depth: int, out_dir: Path, proxy: str | None) -> None:
    try:
        from scrapling.spiders import Spider, Request, Response
        from scrapling.fetchers import FetcherSession
    except ImportError:
        print("[Scrapling] 未安装 fetchers。请先: pip install 'scrapling[fetchers]' && scrapling install")
        sys.exit(1)

    out_dir.mkdir(parents=True, exist_ok=True)
    items_file = out_dir / "pages.jsonl"
    links_file = out_dir / "links.json"
    all_links: list[str] = []

    class ReconSpider(Spider):
        name = "recon"
        start_urls = [start_url]
        concurrent_requests = 8
        depth_limit = depth
        development_mode = False

        def configure_sessions(self, manager):  # type: ignore[override]
            session_kwargs = {}
            if proxy:
                session_kwargs["proxy"] = proxy
            manager.add("default", FetcherSession(impersonate="chrome", **session_kwargs))

        async def parse(self, response: Response):  # type: ignore[override]
            title = ""
            title_el = response.css("title::text")
            if title_el:
                title = title_el.get()

            js_urls = [a.attrib.get("src", "") for a in response.css("script[src]")]
            forms = [f.attrib.get("action", "") for f in response.css("form[action]")]

            item = {
                "url": response.url,
                "status": response.status,
                "title": title,
                "js_files": js_urls,
                "forms": forms,
                "links_count": 0,
            }

            links = []
            for a in response.css("a[href]"):
                href = a.attrib.get("href", "")
                if href and not href.startswith("#"):
                    links.append(href)
                    yield response.follow(href)

            item["links_count"] = len(links)
            all_links.extend(links)
            yield item

    result = ReconSpider().start()
    print(f"[Scrapling Spider] 爬取完成：{len(result.items)} 页面")

    with items_file.open("w", encoding="utf-8") as f:
        for item in result.items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    unique_links = sorted(set(all_links))
    links_file.write_text(json.dumps(unique_links, ensure_ascii=False, indent=2))

    print(f"[Scrapling Spider] 发现链接：{len(unique_links)} 个")
    print(f"[Scrapling Spider] 页面数据：{items_file}")
    print(f"[Scrapling Spider] 链接列表：{links_file}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Scrapling scope-gated spider")
    parser.add_argument("target", help="目标域名或起始 URL（如 https://target.com）")
    parser.add_argument("--depth", type=int, default=2, help="爬取深度（默认 2）")
    parser.add_argument("--proxy", help="代理，如 http://127.0.0.1:8080")
    parser.add_argument("--out-dir", help="输出目录（默认自动生成）")
    parser.add_argument("--force", action="store_true", help="跳过 scope 检查")
    args = parser.parse_args()

    start_url = args.target if args.target.startswith("http") else f"https://{args.target}"
    host = urlparse(start_url).hostname or args.target

    if not args.force:
        allowed = load_allowed_targets()
        if not is_authorized(host, allowed):
            print(f"[Scrapling] ❌ {host!r} 不在 scope，请先授权")
            sys.exit(1)
        print(f"[Scrapling] ✅ {host!r} 已授权")

    if args.out_dir:
        out_dir = Path(args.out_dir)
    else:
        slug = host.replace(".", "_")
        date_str = datetime.now().strftime("%Y%m%d")
        out_dir = EXPORTS_DIR / f"{slug}_{date_str}" / "scrapling"

    run_spider(start_url, args.depth, out_dir, args.proxy)


if __name__ == "__main__":
    main()
