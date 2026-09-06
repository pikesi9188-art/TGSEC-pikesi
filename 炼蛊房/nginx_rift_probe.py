#!/usr/bin/env python3
"""
nginx_rift_probe.py — NGINX Rift (CVE-2026-42945) L1/L2 指纹与配置审计（授权范围内）

CVE-2026-42945：ngx_http_rewrite_module 堆缓冲区溢出
  CVSS 4.0 9.2 Critical | 野外已利用 | F5 K000161019

本脚本覆盖 L1/L2。授权内 L3 DoS / L4 RCE 走外置 PoC：
  见 传承/河门·裂.md §五
  git clone → poc-db/nginx-rift/Nginx-Rift → setup.sh + poc.py

能力：
  detect         — Server 头 / 版本区间 / 风险评级
  surface        — 常见路径上的 30x+query 改写面粗扫
  check-config   — 本地 nginx.conf 危险 rewrite 链静态审计
  scan           — detect + surface 一键

用法：
  python3 炼蛊房/nginx_rift_probe.py detect -u https://target
  python3 炼蛊房/nginx_rift_probe.py surface -u https://target --out 案卷/.../nginx_rift/
  python3 炼蛊房/nginx_rift_probe.py check-config -f /path/nginx.conf
  python3 炼蛊房/nginx_rift_probe.py scan -u https://target --out 案卷/.../nginx_rift/

依赖：pip install requests
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

CVE = "CVE-2026-42945"
FIXED_OSS = [(1, 30, 1), (1, 31, 0)]  # 任一达到即视为官方修复线
AFFECTED_MIN = (0, 6, 27)
AFFECTED_MAX_INCLUSIVE = (1, 30, 0)

SERVER_RE = re.compile(r"(?i)\b(nginx|openresty)(?:/([\d.]+))?")
PLUS_RE = re.compile(r"(?i)nginx[\s_-]?plus|r(\d{2,3})")

# rewrite 行：捕获替换串；后续找未命名 $n
REWRITE_RE = re.compile(
    r"^\s*rewrite\s+(\S+)\s+(\S+)(?:\s+\w+)?;",
    re.MULTILINE,
)
SET_OR_IF_RE = re.compile(
    r"^\s*(?:set\s+\$\w+\s+.*|if\s*\([^)]*\)|rewrite\s+\S+\s+\S+)",
    re.MULTILINE,
)
UNNAMED_CAPTURE_RE = re.compile(r"(?<!\{)\$([1-9][0-9]?)(?!\w)")
NAMED_CAPTURE_DECL = re.compile(r"\(\?P?[<']\w+[>']")

SURFACE_PATHS = [
    "/",
    "/index.html",
    "/old/test",
    "/api/",
    "/api/v1/",
    "/redirect",
    "/r/",
    "/.well-known/",
    "/nginx_status",
    "/status",
]


# ──────────────────────────── Scope ────────────────────────────

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import require_in_scope  # noqa: E402


# ──────────────────────────── HTTP ─────────────────────────────

def _sess() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; 大爱仙尊-NginxRift/1.0)",
        "Accept": "*/*",
    })
    return s


def _get(sess: requests.Session, url: str, **kw) -> requests.Response | None:
    try:
        kw.setdefault("timeout", 12)
        kw.setdefault("verify", False)
        kw.setdefault("allow_redirects", False)
        return sess.get(url, **kw)
    except Exception:
        return None


# ──────────────────────────── 版本逻辑 ─────────────────────────

def parse_version(ver: str) -> tuple[int, ...] | None:
    if not ver:
        return None
    parts = []
    for p in ver.strip().split("."):
        if not p.isdigit():
            break
        parts.append(int(p))
    return tuple(parts) if parts else None


def version_risk(ver_tuple: tuple[int, ...] | None) -> dict[str, Any]:
    """返回 risk: fixed|affected|unknown|below_min"""
    if ver_tuple is None:
        return {
            "risk": "unknown",
            "label": "无精确版本（Server 可能隐藏）",
            "in_affected_range": None,
        }
    v = ver_tuple
    # 官方修复：>= 1.30.1 或 >= 1.31.0（1.30.1 已覆盖 1.30 线）
    if v >= (1, 30, 1) or v >= (1, 31, 0):
        return {
            "risk": "fixed",
            "label": f"版本 {'.'.join(map(str, v))} ≥ 1.30.1 / 修复线",
            "in_affected_range": False,
        }
    if v < AFFECTED_MIN:
        return {
            "risk": "below_min",
            "label": f"版本过旧/异常: {'.'.join(map(str, v))}",
            "in_affected_range": False,
        }
    if v <= AFFECTED_MAX_INCLUSIVE:
        return {
            "risk": "affected",
            "label": (
                f"版本 {'.'.join(map(str, v))} 落在受影响区间 "
                f"{'.'.join(map(str, AFFECTED_MIN))}–"
                f"{'.'.join(map(str, AFFECTED_MAX_INCLUSIVE))}"
            ),
            "in_affected_range": True,
        }
    return {
        "risk": "unknown",
        "label": f"版本 {'.'.join(map(str, v))} 未映射到已知区间",
        "in_affected_range": None,
    }


def extract_server_meta(headers: dict) -> dict[str, Any]:
    # requests headers 大小写不敏感，但转普通 dict 后可能丢失；用原响应时传入 CaseInsensitive
    server = ""
    for k, v in headers.items():
        if k.lower() == "server":
            server = str(v)
            break
    product = None
    version = None
    m = SERVER_RE.search(server)
    if m:
        product = m.group(1).lower()
        version = m.group(2)
    plus = bool(PLUS_RE.search(server))
    return {
        "server_header": server,
        "product": product,
        "version": version,
        "version_tuple": list(parse_version(version)) if version else None,
        "looks_plus": plus,
    }


# ──────────────────────────── 配置审计 ─────────────────────────

def _strip_nginx_comments(text: str) -> str:
    out = []
    for line in text.splitlines():
        if "#" in line:
            line = line[: line.index("#")]
        out.append(line)
    return "\n".join(out)


def _location_blocks(text: str) -> list[tuple[str, str]]:
    """粗解析 location { ... } 块（不处理嵌套极深配置，够审计用）。"""
    blocks: list[tuple[str, str]] = []
    # location [=|~|~*|^~]? path {
    loc_re = re.compile(
        r"location\s*([=^~*]*\s*)?([^\s{]+)\s*\{",
        re.MULTILINE,
    )
    for m in loc_re.finditer(text):
        start = m.end()
        depth = 1
        i = start
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        body = text[start : i - 1]
        path = (m.group(2) or "").strip()
        blocks.append((path, body))
    return blocks


def audit_nginx_config(text: str, source: str = "") -> dict[str, Any]:
    clean = _strip_nginx_comments(text)
    findings: list[dict[str, Any]] = []
    blocks = _location_blocks(clean)
    # 无 location 时扫整文件；有 location 则只扫各块，避免 file-wide 重复命中
    if not blocks:
        blocks = [("(global)", clean)]

    for loc_path, body in blocks:
        rewrites = list(REWRITE_RE.finditer(body))
        for idx, rw in enumerate(rewrites):
            replacement = rw.group(2).rstrip(";")
            if "?" not in replacement:
                continue
            # 同块内，该 rewrite 之后的文本
            after = body[rw.end() :]
            # 后续是否有 set/if/rewrite 且含未命名捕获
            has_follow = bool(
                re.search(r"^\s*(set|if|rewrite)\b", after, re.MULTILINE)
            )
            unnamed = UNNAMED_CAPTURE_RE.findall(after)
            # 当前 rewrite 模式若声明了命名捕获，仍可能被后续 $1 引用旧捕获
            if has_follow and unnamed:
                findings.append({
                    "location": loc_path,
                    "rewrite_pattern": rw.group(1),
                    "rewrite_replacement": replacement,
                    "follow_unnamed_captures": sorted(set(unnamed)),
                    "severity": "high",
                    "reason": "rewrite 替换串含 '?' 且同块后续指令使用未命名捕获 $n",
                    "cve": CVE,
                })
            elif "?" in replacement and UNNAMED_CAPTURE_RE.search(rw.group(0) + after[:200]):
                # 弱信号：同行/邻近有 $1
                if UNNAMED_CAPTURE_RE.search(body):
                    findings.append({
                        "location": loc_path,
                        "rewrite_pattern": rw.group(1),
                        "rewrite_replacement": replacement,
                        "follow_unnamed_captures": sorted(set(UNNAMED_CAPTURE_RE.findall(body))),
                        "severity": "medium",
                        "reason": "含 '?' 的 rewrite 与未命名捕获同块共存（需人工确认指令顺序）",
                        "cve": CVE,
                    })

    # 去重
    seen = set()
    uniq = []
    for f in findings:
        key = (f["location"], f["rewrite_pattern"], f["rewrite_replacement"], f["severity"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)

    return {
        "cve": CVE,
        "source": source,
        "locations_scanned": len(blocks),
        "findings": uniq,
        "vulnerable_config_likely": any(f["severity"] == "high" for f in uniq),
        "mitigation_hint": (
            "将未命名捕获改为命名捕获，例如 "
            "rewrite ^/old/(?<path>.*)$ /new?upgrade=1; "
            "并升级到 NGINX 1.30.1+ / 1.31.0+"
        ),
    }


# ──────────────────────────── 命令实现 ─────────────────────────

def cmd_detect(url: str, out_dir: Path | None) -> dict[str, Any]:
    require_in_scope(url)
    sess = _sess()
    r = _get(sess, url, allow_redirects=True)
    meta = {
        "cve": CVE,
        "url": url,
        "ok": False,
        "status_code": None,
        "final_url": None,
        "server": {},
        "risk": {},
        "notes": [],
    }
    if not r:
        meta["notes"].append("HTTP 请求失败")
        _write(out_dir, "detect.json", meta)
        return meta

    meta["ok"] = True
    meta["status_code"] = r.status_code
    meta["final_url"] = str(r.url)
    meta["server"] = extract_server_meta(dict(r.headers))
    vt = parse_version(meta["server"].get("version") or "")
    meta["risk"] = version_risk(vt)

    if meta["server"].get("product") in ("nginx", "openresty"):
        meta["notes"].append("检测到 nginx/openresty Server 头")
    else:
        meta["notes"].append("未识别到 nginx Server 头（可能藏头或非 nginx）")

    if meta["risk"].get("risk") == "affected":
        meta["notes"].append(
            "版本落在受影响区间；远程利用仍依赖危险 rewrite 配置（见 Playbook）"
        )
    if meta["risk"].get("risk") == "unknown" and meta["server"].get("product"):
        meta["notes"].append("建议旁证：包版本、error 页、check-config、发行版 advisory")

    meta["references"] = [
        "https://my.f5.com/manage/s/article/K000161019",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-42945",
        "传承/河门·裂.md",
    ]
    _write(out_dir, "detect.json", meta)
    return meta


def cmd_surface(url: str, out_dir: Path | None) -> dict[str, Any]:
    require_in_scope(url)
    sess = _sess()
    base = url.rstrip("/") + "/"
    hits: list[dict[str, Any]] = []
    for p in SURFACE_PATHS:
        u = urljoin(base, p.lstrip("/"))
        r = _get(sess, u)
        if not r:
            continue
        loc = r.headers.get("Location") or r.headers.get("location") or ""
        server = r.headers.get("Server") or r.headers.get("server") or ""
        interesting = False
        reasons = []
        if r.status_code in (301, 302, 303, 307, 308) and loc:
            interesting = True
            reasons.append("redirect")
            if "?" in loc:
                reasons.append("redirect_with_query")
        if "nginx" in server.lower():
            reasons.append("nginx_server")
        if interesting or "nginx" in server.lower():
            hits.append({
                "url": u,
                "status": r.status_code,
                "location": loc[:300],
                "server": server,
                "reasons": reasons,
            })

    result = {
        "cve": CVE,
        "url": url,
        "paths_tested": len(SURFACE_PATHS),
        "hits": hits,
        "rewrite_surface_hint": any(
            "redirect_with_query" in h.get("reasons", []) for h in hits
        ),
        "note": "粗扫仅观察 30x/Server，不发送溢出 payload",
    }
    _write(out_dir, "surface.json", result)
    return result


def cmd_check_config(path: Path, out_dir: Path | None) -> dict[str, Any]:
    if not path.is_file():
        print(f"[!] 文件不存在: {path}", file=sys.stderr)
        sys.exit(2)
    text = path.read_text(encoding="utf-8", errors="replace")
    result = audit_nginx_config(text, source=str(path))
    _write(out_dir, "config_audit.json", result)
    return result


def cmd_scan(url: str, out_dir: Path | None) -> dict[str, Any]:
    det = cmd_detect(url, out_dir)
    surf = cmd_surface(url, out_dir)
    summary = {
        "cve": CVE,
        "url": url,
        "detect": det,
        "surface": {
            "rewrite_surface_hint": surf.get("rewrite_surface_hint"),
            "hit_count": len(surf.get("hits") or []),
        },
        "next": [
            "有 nginx.conf → check-config",
            "版本 affected → 推动 1.30.1+/1.31.0+ 或命名捕获缓解",
            "勿默认打堆溢出；DoS/RCE 须明确授权",
        ],
    }
    _write(out_dir, "SUMMARY.json", summary)
    return summary


def _write(out_dir: Path | None, name: str, data: dict) -> None:
    if not out_dir:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / name
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[+] wrote {p}")


def _print_brief(data: dict) -> None:
    risk = (data.get("risk") or {}) if "risk" in data else {}
    if not risk and "detect" in data:
        risk = (data["detect"] or {}).get("risk") or {}
    server = data.get("server") or (data.get("detect") or {}).get("server") or {}
    print("---")
    print(f"CVE: {CVE}")
    if server:
        print(f"Server: {server.get('server_header') or '-'}")
        print(f"Product/Ver: {server.get('product')}/{server.get('version') or '?'}")
    if risk:
        print(f"Risk: {risk.get('risk')} — {risk.get('label')}")
    if "findings" in data:
        print(f"Config findings: {len(data.get('findings') or [])} "
              f"(likely={data.get('vulnerable_config_likely')})")
        for f in (data.get("findings") or [])[:8]:
            print(f"  [{f.get('severity')}] loc={f.get('location')} "
                  f"rew={f.get('rewrite_replacement')} "
                  f"$={f.get('follow_unnamed_captures')}")


def main() -> None:
    ap = argparse.ArgumentParser(description=f"NGINX Rift {CVE} probe (detect/config only)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_det = sub.add_parser("detect", help="指纹 + 版本风险")
    p_det.add_argument("-u", "--url", required=True)
    p_det.add_argument("--out", type=Path, default=None)

    p_surf = sub.add_parser("surface", help="改写面粗扫")
    p_surf.add_argument("-u", "--url", required=True)
    p_surf.add_argument("--out", type=Path, default=None)

    p_cfg = sub.add_parser("check-config", help="审计本地 nginx.conf")
    p_cfg.add_argument("-f", "--file", type=Path, required=True)
    p_cfg.add_argument("--out", type=Path, default=None)

    p_scan = sub.add_parser("scan", help="detect + surface")
    p_scan.add_argument("-u", "--url", required=True)
    p_scan.add_argument("--out", type=Path, default=None)

    args = ap.parse_args()
    if args.cmd == "detect":
        data = cmd_detect(args.url, args.out)
    elif args.cmd == "surface":
        data = cmd_surface(args.url, args.out)
    elif args.cmd == "check-config":
        data = cmd_check_config(args.file, args.out)
    else:
        data = cmd_scan(args.url, args.out)
    _print_brief(data)


if __name__ == "__main__":
    main()
