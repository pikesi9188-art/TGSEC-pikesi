#!/usr/bin/env python3
"""etcd 暴露面探针（授权范围内）。version / v2 keys / v3 健康；默认不破坏性 DoS。"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

try:
    import requests

    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-etcd"


def _normalize_base(url: str) -> str:
    """无 scheme 补 http://；无端口补 :2379。"""
    s = (url or "").strip()
    if "://" not in s:
        s = "http://" + s
    p = urlparse(s)
    host = p.hostname or ""
    port = p.port
    if port is None:
        # 用户写了 host 或 host/path 无端口
        netloc = f"{host}:2379"
    else:
        netloc = p.netloc
    return urlunparse((p.scheme or "http", netloc, "", "", "", "")).rstrip("/")


def _get(sess: requests.Session, url: str) -> requests.Response | None:
    try:
        return sess.get(url, timeout=8, verify=False, allow_redirects=True)
    except Exception:
        return None


def run(base_url: str, case: str, out: Path | None, deep: bool) -> dict[str, Any]:
    host = host_of(base_url)
    if host and not in_scope(host):
        print(f"[!] 不在 scope：{host}", file=sys.stderr)
        sys.exit(2)
    base = _normalize_base(base_url)
    sess = requests.Session()
    sess.headers["User-Agent"] = UA

    checks: list[tuple[str, tuple[str, ...]] | None] = [
        ("/version", ("etcdserver", "etcdcluster")),
        ("/health", ("true", "health")),
        ("/v2/keys/", ("node", "key", "dir")),
    ]
    if deep:
        checks.append(("/v2/keys/?recursive=true", ("node", "key")))

    hits: list[dict[str, Any]] = []
    for item in checks:
        if not item:
            continue
        path, needles = item
        r = _get(sess, base + path)
        if r is None:
            continue
        body = (r.text or "")[:4000]
        low = body.lower()
        matched = [n for n in needles if n.lower() in low]
        row = {
            "path": path,
            "status": r.status_code,
            "matched": matched,
            "snippet": body[:240],
        }
        if matched or (path == "/version" and r.status_code == 200 and "etcd" in low):
            hits.append(row)
            print(f"  [{r.status_code}] {path} matched={matched}")

    if deep:
        try:
            r = sess.post(
                base + "/v3/kv/range",
                json={"key": "AA==", "range_end": "AA=="},
                timeout=8,
                verify=False,
            )
            if r is not None and r.status_code < 500:
                hits.append(
                    {
                        "path": "/v3/kv/range",
                        "status": r.status_code,
                        "matched": ["v3"] if r.status_code == 200 else [],
                        "snippet": (r.text or "")[:240],
                    }
                )
        except Exception:
            pass

    report = {
        "target": base_url,
        "normalized": base,
        "ts": datetime.now(UTC).isoformat(),
        "hits": hits,
        "playbook": "传承/契柜·无门·2.md",
        "skill": "杀招/契柜无门",
        "cve": ["CVE-2026-73499", "CVE-2026-73500"],
        "note": "73500 为 TLS 握手 DoS，授权内默认不做破坏性复现",
        "next": [
            "能读 keys → 抽 K8s secret / 业务配置",
            "切 Skill k8s / linux-post-exploit",
        ],
    }
    out_path = write_probe_json(
        report, case=case, out=out, case_subdir="etcd", filename="probe.json"
    )
    print(json.dumps({"hits": len(hits), "normalized": base, "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="etcd 暴露面探针")
    ap.add_argument("-u", "--url", required=True, help="http://host:2379 或 host（自动补端口）")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--deep", action="store_true", help="recursive keys + v3 轻探测")
    args = ap.parse_args()
    run(args.url, args.case, args.out, args.deep)


if __name__ == "__main__":
    main()
