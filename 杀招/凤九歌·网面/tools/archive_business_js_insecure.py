#!/usr/bin/env python3
"""
根据已筛选的 JS 清单，下载并归档业务功能类 JS 到本地目录，方便后续 grep / 审计。

输入 JSON 兼容两种形式：
1. extract_page_js.py 的原始输出，但需要手工或大模型补充分类字段
2. 大模型整理后的分类结果，包含 business_js / vendor_js / review_js

推荐：
  python3 tools/archive_business_js.py js_inventory_classified.json -o audit_js
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlparse
from urllib.request import Request, urlopen

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Alma-web-pentest-js-archiver/1.0"


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def normalize_filename(name: str) -> str:
    keep = []
    for ch in name:
        if ch.isalnum() or ch in {"-", "_", "."}:
            keep.append(ch)
        else:
            keep.append("_")
    result = "".join(keep).strip("._")
    return result or "unnamed.js"


def unique_name(filename: str, url: str) -> str:
    digest = hashlib.sha1(url.encode("utf-8")).hexdigest()[:10]
    if "." in filename:
        stem, ext = filename.rsplit(".", 1)
        return f"{stem}__{digest}.{ext}"
    return f"{filename}__{digest}.js"


def fetch_bytes(url: str, timeout: int) -> bytes:
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read()


def extract_business_items(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        if isinstance(data.get("business_js"), list):
            return [x for x in data["business_js"] if isinstance(x, dict)]
        if isinstance(data.get("business_function_js"), list):
            return [x for x in data["business_function_js"] if isinstance(x, dict)]
        if isinstance(data.get("js_files"), list):
            result = []
            for item in data["js_files"]:
                if not isinstance(item, dict):
                    continue
                label = str(item.get("llm_category") or item.get("category") or item.get("final_category") or "").lower()
                if label in {"business", "business_js", "business-function", "business_function_js", "developer-written", "developer_written"}:
                    result.append(item)
            return result
    if isinstance(data, list):
        result = []
        for item in data:
            if not isinstance(item, dict):
                continue
            label = str(item.get("llm_category") or item.get("category") or item.get("final_category") or "").lower()
            if label in {"business", "business_js", "business-function", "business_function_js", "developer-written", "developer_written"}:
                result.append(item)
        return result
    return []


def item_url(item: Dict[str, Any]) -> str:
    return str(item.get("url") or item.get("src") or item.get("full_url") or "").strip()


def item_filename(item: Dict[str, Any]) -> str:
    raw = str(item.get("filename") or "").strip()
    if raw:
        return normalize_filename(raw)
    parsed = urlparse(item_url(item))
    name = os.path.basename(parsed.path) or "unnamed.js"
    return normalize_filename(name)


def archive(input_json: str, output_dir: str, timeout: int) -> Dict[str, Any]:
    data = load_json(input_json)
    items = extract_business_items(data)

    base = Path(output_dir)
    files_dir = base / "files"
    ensure_dir(files_dir)

    manifest_items: List[Dict[str, Any]] = []
    downloaded = 0
    failed = 0

    for idx, item in enumerate(items, start=1):
        url = item_url(item)
        if not url:
            failed += 1
            manifest_items.append({
                "index": idx,
                "status": "failed",
                "reason": "missing url",
                "source": item,
            })
            continue

        filename = unique_name(item_filename(item), url)
        target = files_dir / filename
        try:
            body = fetch_bytes(url, timeout)
            target.write_bytes(body)
            downloaded += 1
            manifest_items.append({
                "index": idx,
                "status": "downloaded",
                "url": url,
                "saved_to": str(target),
                "bytes": len(body),
                "filename": filename,
                "original": item,
            })
        except Exception as e:
            failed += 1
            manifest_items.append({
                "index": idx,
                "status": "failed",
                "url": url,
                "reason": str(e),
                "filename": filename,
                "original": item,
            })

    manifest = {
        "input_json": input_json,
        "output_dir": str(base),
        "business_js_count": len(items),
        "downloaded_count": downloaded,
        "failed_count": failed,
        "items": manifest_items,
    }

    manifest_path = base / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    ap = argparse.ArgumentParser(description="Download and archive business JS files for auditing")
    ap.add_argument("input_json", help="Classified JS inventory JSON")
    ap.add_argument("-o", "--output-dir", default="audit_js", help="Archive output directory")
    ap.add_argument("--timeout", type=int, default=20, help="HTTP timeout in seconds")
    args = ap.parse_args()

    try:
        manifest = archive(args.input_json, args.output_dir, args.timeout)
    except Exception as e:
        print(json.dumps({"error": str(e), "input_json": args.input_json}, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1

    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
