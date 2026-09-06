#!/usr/bin/env python3
"""
非侵入式抓取网页中的 JS 文件引用，输出结构化结果，供 web-pentest skill 后续交给大模型筛选。

用法：
  python3 tools/extract_page_js.py https://target.tld/
  python3 tools/extract_page_js.py https://target.tld/ -o js_inventory.json
"""

from __future__ import annotations

import argparse
import json
import posixpath
import re
import ssl
import sys
from html.parser import HTMLParser
from typing import Dict, List, Set
from urllib.parse import parse_qs, unquote, urljoin, urlparse
from urllib.request import Request, urlopen

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Alma-web-pentest-js-crawler/1.1"
JS_EXT_RE = re.compile(r"\.[cm]?js$", re.I)
COMMON_JS_HINT_RE = re.compile(r"(app|main|index|vendor|chunk|bundle|runtime|loader|module)", re.I)


class AssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.assets: List[Dict[str, str]] = []
        self.inline_scripts = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()

        if tag == "script":
            src = attr.get("src", "").strip()
            if src:
                self.assets.append({
                    "tag": "script",
                    "src": src,
                    "rel": "",
                    "type": attr.get("type", ""),
                    "crossorigin": attr.get("crossorigin", ""),
                })
            else:
                self.inline_scripts += 1
            return

        if tag == "link":
            href = attr.get("href", "").strip()
            rel = attr.get("rel", "").strip().lower()
            as_attr = attr.get("as", "").strip().lower()
            type_attr = attr.get("type", "").strip().lower()
            if not href:
                return
            if rel in {"preload", "modulepreload", "prefetch"}:
                if as_attr == "script" or "javascript" in type_attr or looks_like_js_url(href):
                    self.assets.append({
                        "tag": "link",
                        "src": href,
                        "rel": rel,
                        "type": type_attr,
                        "crossorigin": attr.get("crossorigin", ""),
                    })


def looks_like_js_url(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path or ""
    if JS_EXT_RE.search(path):
        return True
    query = parsed.query.lower()
    if "file=" in query:
        for values in parse_qs(parsed.query).values():
            for value in values:
                if JS_EXT_RE.search(urlparse(value).path or value):
                    return True
    return any(x in (path + "?" + parsed.query).lower() for x in [".js", "javascript", "module", "chunk", "bundle"])


def filename_from_url(url: str) -> str:
    parsed = urlparse(url)
    name = posixpath.basename(parsed.path.rstrip("/"))
    if name:
        return unquote(name)
    if parsed.query:
        for values in parse_qs(parsed.query).values():
            for value in values:
                value_name = posixpath.basename(urlparse(value).path.rstrip("/"))
                if value_name:
                    return unquote(value_name)
    return "(inline-or-unknown)"


def classify_hint(filename: str, full_url: str) -> str:
    low = f"{filename} {full_url}".lower()
    if any(k in low for k in ["react", "vue", "angular", "element", "antd", "mui", "vendor", "runtime", "polyfill", "webpack", "chunk-vendors"]):
        return "likely-framework-or-vendor"
    if any(k in low for k in ["app", "main", "index", "pages", "router", "login", "user", "order", "admin", "dashboard", "report", "service", "api", "request", "utils"]):
        return "likely-business-or-entry"
    if COMMON_JS_HINT_RE.search(low):
        return "mixed-or-uncertain"
    return "uncertain"


def fetch_text(url: str, timeout: int) -> str:
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urlopen(req, timeout=timeout, context=ctx) as resp:
        # 处理重定向
        if resp.url != url:
            print(f"Redirected from {url} to {resp.url}", file=sys.stderr)
        raw = resp.read()
        charset = resp.headers.get_content_charset() or "utf-8"
    return raw.decode(charset, errors="replace")


def build_inventory(page_url: str, timeout: int) -> Dict:
    html = fetch_text(page_url, timeout)
    parser = AssetParser()
    parser.feed(html)

    seen: Set[str] = set()
    js_files: List[Dict[str, str]] = []
    for item in parser.assets:
        src = item.get("src", "").strip()
        if not src:
            continue
        full_url = urljoin(page_url, src)
        if full_url in seen:
            continue
        seen.add(full_url)
        filename = filename_from_url(full_url)
        js_files.append({
            "tag": item.get("tag", ""),
            "rel": item.get("rel", ""),
            "type": item.get("type", ""),
            "url": full_url,
            "path": urlparse(full_url).path,
            "filename": filename,
            "name_without_ext": re.sub(r"\.[cm]?js$", "", filename, flags=re.I),
            "classification_hint": classify_hint(filename, full_url),
        })

    return {
        "page_url": page_url,
        "inline_script_count": parser.inline_scripts,
        "js_file_count": len(js_files),
        "js_files": js_files,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract JS file references from a web page")
    ap.add_argument("url", help="Target page URL")
    ap.add_argument("-o", "--output", help="Write JSON result to file")
    ap.add_argument("--timeout", type=int, default=20, help="HTTP timeout in seconds")
    args = ap.parse_args()

    try:
        inventory = build_inventory(args.url, args.timeout)
    except Exception as e:
        print(json.dumps({"error": str(e), "page_url": args.url}, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1

    data = json.dumps(inventory, ensure_ascii=False, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(data)
            f.write("\n")
    print(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
