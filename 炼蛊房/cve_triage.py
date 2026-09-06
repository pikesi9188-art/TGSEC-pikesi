#!/usr/bin/env python3
"""Banner / 产品版本 → NVD 检索。只出 L1 假设，不打目标。

Banner ≠ 已验证。命中后走 nday_route / 1day-nuclei-kit；入库走 cve-daily-intel。

  python3 炼蛊房/cve_triage.py --query 'Apache httpd 2.4.49'
  python3 炼蛊房/cve_triage.py --cve CVE-2021-41773
"""
from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "大爱仙尊-cve-triage/1.0"


def _ssl_ctx() -> ssl.SSLContext:
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        ctx = ssl.create_default_context()
        try:
            ctx.load_default_certs()
        except Exception:
            pass
        return ctx


def _get(url: str, timeout: int = 20) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except ssl.SSLError:
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))


def _cvss(metrics: dict[str, Any]) -> float:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if rows:
            data = rows[0].get("cvssData") or {}
            try:
                return float(data.get("baseScore") or 0)
            except (TypeError, ValueError):
                return 0.0
    return 0.0


def _row(item: dict[str, Any]) -> dict[str, Any]:
    cve = item.get("cve") or {}
    descs = cve.get("descriptions") or []
    en = next((d.get("value") for d in descs if d.get("lang") == "en"), "")
    zh = next((d.get("value") for d in descs if d.get("lang") == "zh"), "")
    return {
        "id": cve.get("id"),
        "cvss": _cvss(cve.get("metrics") or {}),
        "published": (cve.get("published") or "")[:10],
        "summary": (zh or en)[:280],
    }


def search(query: str, limit: int) -> dict[str, Any]:
    q = urllib.parse.urlencode({"keywordSearch": query, "resultsPerPage": min(limit, 20)})
    data = _get(f"{NVD}?{q}")
    rows = [_row(x) for x in data.get("vulnerabilities") or []]
    rows.sort(key=lambda r: r["cvss"], reverse=True)
    return {
        "query": query,
        "level": "L1",
        "note": "NVD 命中是假设，禁止写成 STATUS L2",
        "total": data.get("totalResults", len(rows)),
        "hits": rows[:limit],
        "ok": bool(rows),
    }


def detail(cve_id: str) -> dict[str, Any]:
    q = urllib.parse.urlencode({"cveId": cve_id})
    data = _get(f"{NVD}?{q}")
    items = data.get("vulnerabilities") or []
    if not items:
        return {"ok": False, "error": f"NVD 无 {cve_id}"}
    row = _row(items[0])
    row["ok"] = True
    row["level"] = "L1"
    row["note"] = "Banner/版本匹配只是假设；补丁回迁后同版本号也可能已修。验证走 nday_route。"
    return row


def main() -> int:
    ap = argparse.ArgumentParser(description="NVD CVE 分诊（只读情报）")
    ap.add_argument("--query", help="产品 + 版本，如 nginx 1.18.0")
    ap.add_argument("--cve", help="CVE-YYYY-NNNN")
    ap.add_argument("--limit", type=int, default=8)
    ap.add_argument("--case", default="", help="写入 案卷/cve_triage/nvd.json")
    ap.add_argument("--out")
    args = ap.parse_args()
    try:
        if args.cve:
            data = detail(args.cve.strip())
        elif args.query:
            data = search(args.query.strip(), args.limit)
        else:
            print("[!] 需要 --query 或 --cve", file=sys.stderr)
            return 2
    except urllib.error.HTTPError as e:
        print(f"[!] NVD HTTP {e.code}: {e.reason}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[!] NVD 请求失败: {e}", file=sys.stderr)
        return 1
    print(json.dumps(data, ensure_ascii=False, indent=2))
    if args.case or args.out:
        ops = Path(__file__).resolve().parent
        if str(ops) not in sys.path:
            sys.path.insert(0, str(ops))
        from scope_lib import write_probe_json  # noqa: E402

        if args.case:
            write_probe_json(data, case=args.case, case_subdir="cve_triage", filename="nvd.json")
        if args.out:
            write_probe_json(data, out=Path(args.out))
    if args.query:
        print("下一步: 高 CVSS 用 nday_route.py --url <授权站> --case <案卷>；不要把版本命中写成已验证。", file=sys.stderr)
    return 0 if data.get("hits") or data.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
