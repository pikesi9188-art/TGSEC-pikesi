#!/usr/bin/env python3
"""授权范围内探测 Spring Boot Actuator 暴露面（非 Gateway 专用）。

用法:
  python3 炼蛊房/actuator_probe.py --base https://api.example.com --out 案卷/.../案卷/actuator/

产出:
  probe.json / PROBE.md — 端点可达性、heapdump Content-Length、env 摘要
"""
from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, UTC
from pathlib import Path

DEFAULT_PATHS = [
    "/actuator",
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/mappings",
    "/actuator/configprops",
    "/actuator/heapdump",
    "/actuator/threaddump",
    "/actuator/loggers",
    "/actuator/prometheus",
    "/actuator/gateway/routes",
    "/druid/index.html",
    "/v3/api-docs",
    "/swagger-ui/index.html",
    "/doc.html",
]


def fetch(url: str, timeout: float, method: str = "GET", range_header: str | None = None):
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "大爱仙尊-actuator-probe/1.0")
    if range_header:
        req.add_header("Range", range_header)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(65536)
            return {
                "ok": True,
                "status": resp.status,
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "body_prefix": body[:2000].decode("utf-8", "replace"),
                "body_len": len(body),
            }
    except urllib.error.HTTPError as e:
        body = e.read(4096) if e.fp else b""
        return {
            "ok": False,
            "status": e.code,
            "headers": {k.lower(): v for k, v in (e.headers.items() if e.headers else [])},
            "body_prefix": body[:800].decode("utf-8", "replace"),
            "error": f"HTTPError {e.code}",
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "status": None, "error": str(e)}


def scan(base: str, timeout: float = 12.0, extra_paths: str = "") -> dict:
    """打 DEFAULT_PATHS：health / heapdump Range / gateway/routes。不写盘。"""
    base = base.rstrip("/")
    paths = list(DEFAULT_PATHS)
    if extra_paths.strip():
        paths.extend(p.strip() for p in extra_paths.split(",") if p.strip())

    results = []
    for p in paths:
        url = base + (p if p.startswith("/") else "/" + p)
        if p.rstrip("/").endswith("heapdump"):
            head = fetch(url, timeout, method="HEAD")
            rng = fetch(url, timeout, method="GET", range_header="bytes=0-1023")
            cl = head.get("headers", {}).get("content-length") or rng.get("headers", {}).get(
                "content-range", ""
            )
            results.append(
                {
                    "path": p,
                    "url": url,
                    "head": head,
                    "range_1k": {k: rng.get(k) for k in ("ok", "status", "headers", "error")},
                    "size_hint": cl,
                }
            )
        else:
            r = fetch(url, timeout)
            results.append({"path": p, "url": url, **r})

    interesting = []
    for r in results:
        # heapdump 常 HEAD=405、Range=206；只看 head 会漏
        cands = [
            r.get("status"),
            (r.get("head") or {}).get("status"),
            (r.get("range_1k") or {}).get("status"),
        ]
        ok = False
        for st in cands:
            try:
                if st is not None and int(st) < 400:
                    ok = True
                    break
            except (TypeError, ValueError):
                continue
        if ok:
            interesting.append(r["path"])

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "base": base,
        "interesting_paths": interesting,
        "heapdump_exposed": any("heapdump" in p for p in interesting),
        "gateway_routes_exposed": any("gateway/routes" in p for p in interesting),
        "results": results,
        "next": (
            "若 heapdump 暴露：Range 分桶下载 → 炼蛊房/heap_cred_scan.py（正则+蓝鸟蜘蛛）；"
            "若仅 gateway/routes：改走 spring-gateway-killchain Playbook。"
        ),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Spring Boot Actuator 暴露面探测（授权目标）")
    ap.add_argument("--base", required=True, help="https://api.host 无尾斜杠")
    ap.add_argument("--out", required=True, help="输出目录")
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--paths", default="", help="逗号分隔额外路径")
    args = ap.parse_args()

    ops = Path(__file__).resolve().parent
    if str(ops) not in sys.path:
        sys.path.insert(0, str(ops))
    from scope_lib import host_of, in_scope  # noqa: E402
    host = host_of(args.base)
    if host and not in_scope(host):
        raise SystemExit(f"[scope] {host} 不在授权范围")

    report = scan(args.base, timeout=args.timeout, extra_paths=args.paths)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    interesting = report["interesting_paths"]
    (out / "probe.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        f"# Actuator Probe — `{report['base']}`",
        "",
        f"- 时间：{report['generated_at']}",
        f"- 可达（<400）：{', '.join(interesting) or '无'}",
        f"- heapdump：{'是' if report['heapdump_exposed'] else '否'}",
        f"- gateway/routes：{'是' if report['gateway_routes_exposed'] else '否'}",
        "",
        "## 下一步",
        "",
        report["next"],
        "",
    ]
    (out / "PROBE.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"out": str(out), "interesting": interesting}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
