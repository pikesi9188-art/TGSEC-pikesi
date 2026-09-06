#!/usr/bin/env python3
"""大爱仙尊源码还原：highlight / 着色 HTML → 干净源码 + sink。

抽出 sink/表单是 L1。文件读/RCE 交接 lfi / 反序列化 / 命令注入。
URL 必须在 scope；本地文件不走授权闸。

  python3 炼蛊房/source_extract.py --url https://授权站 --case <案卷>
  python3 炼蛊房/source_extract.py --file page.html
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import require_in_scope, write_probe_json  # noqa: E402

SINK_RE = re.compile(
    r"(unserialize|eval\s*\(|assert\s*\(|system\s*\(|passthru\s*\(|"
    r"shell_exec|proc_open|popen\s*\(|include\s*\(|require\s*\(|"
    r"highlight_file|show_source|create_function|preg_replace\s*\(.*/e|"
    r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[)",
    re.I,
)
FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.I | re.S)
INPUT_RE = re.compile(r"<(?:input|textarea|select)\b[^>]*>", re.I)
ENDPOINT_RE = re.compile(
    r"""(?:href|src|action|url)\s*=\s*['"]([^'"]+)['"]""",
    re.I,
)
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
TAG_RE = re.compile(r"<[^>]+>")


def clean_source(html: str) -> str:
    # 真·highlight 输出有大量 color span；源码里出现 highlight_file() 或普通 <span> 不能当着色页。
    highlighted = "code-highlighted" in html or html.count('<span style="color:') >= 3
    text = TAG_RE.sub("", html) if highlighted else html
    text = (
        text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
    )
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def analyze(raw: str) -> dict[str, Any]:
    clean = clean_source(raw)
    comments = [c.strip()[:300] for c in COMMENT_RE.findall(raw) if c.strip()]
    sinks = sorted({m.group(0)[:80] for m in SINK_RE.finditer(clean + "\n" + raw)})
    forms = [re.sub(r"\s+", " ", f)[:240] for f in FORM_RE.findall(raw)]
    inputs = [re.sub(r"\s+", " ", i)[:160] for i in INPUT_RE.findall(raw)]
    endpoints = []
    seen: set[str] = set()
    for m in ENDPOINT_RE.finditer(raw):
        u = m.group(1)
        if u.startswith(("javascript:", "data:", "#", "mailto:")):
            continue
        if u not in seen:
            seen.add(u)
            endpoints.append(u)
            if len(endpoints) >= 40:
                break
    return {
        "clean": clean[:20000],
        "clean_len": len(clean),
        "raw_len": len(raw),
        "comments": comments[:20],
        "sinks": sinks,
        "forms": forms[:10],
        "inputs": inputs[:20],
        "endpoints": endpoints,
    }


def _load(args: argparse.Namespace) -> tuple[str, str]:
    if args.file:
        return Path(args.file).read_text(encoding="utf-8", errors="replace"), args.file
    if not args.url:
        print("[!] 需要 --url 或 --file", file=sys.stderr)
        sys.exit(2)
    require_in_scope(args.url)
    try:
        import requests

        requests.packages.urllib3.disable_warnings()  # type: ignore
    except ImportError:
        print("[!] pip install requests", file=sys.stderr)
        sys.exit(1)
    try:
        r = requests.get(args.url, timeout=15, verify=False)
    except requests.RequestException as e:
        print(f"[!] 拉取失败: {e}", file=sys.stderr)
        sys.exit(1)
    return r.text or "", args.url


def main() -> int:
    ap = argparse.ArgumentParser(description="HTML/highlight 源码还原")
    ap.add_argument("--url")
    ap.add_argument("--file")
    ap.add_argument("--case", default="")
    ap.add_argument("--out")
    args = ap.parse_args()
    raw, src = _load(args)
    info = analyze(raw)
    level = "L1" if (info["sinks"] or info["forms"]) else "L0"
    payload = {
        "ts": datetime.now(UTC).isoformat(),
        "source": src,
        "level": level,
        "note": "sink/表单=L1；升 L2 走 lfi-rfi-exploit / 反序列化 / command-injection",
        **info,
    }
    print(f"level={level} sinks={len(info['sinks'])} forms={len(info['forms'])} endpoints={len(info['endpoints'])} clean={info['clean_len']}")
    for s in info["sinks"][:8]:
        print(f"  sink {s}")
    if args.case:
        write_probe_json(payload, case=args.case, case_subdir="source_extract", filename="source.json")
    if args.out:
        write_probe_json(payload, out=Path(args.out))
    if not args.case and not args.out:
        print(json.dumps({k: v for k, v in payload.items() if k != "clean"}, ensure_ascii=False, indent=2))
        print("\n----- clean source -----\n")
        print(info["clean"][:4000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
