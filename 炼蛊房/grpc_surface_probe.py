#!/usr/bin/env python3
"""gRPC / grpc-web 猎面（授权范围内）。

L1：grpc-status 传输指纹。L2：Health 无票成功或反射/转码露出内部面。
禁止 Rapid Reset。不依赖 grpcurl。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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

UA = "Mozilla/5.0 大爱仙尊-grpc"
GRPC_PATHS = (
    "/grpc.health.v1.Health/Check",
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
)
HTTP_PATHS = (
    "/swagger.json",
    "/openapi.json",
    "/v1/admin/users",
    "/.well-known/grpc",
)


def _grpc_post(sess: requests.Session, url: str) -> dict[str, Any]:
    try:
        r = sess.post(
            url,
            timeout=10,
            verify=False,
            allow_redirects=False,
            headers={
                "Content-Type": "application/grpc",
                "TE": "trailers",
                "grpc-timeout": "5S",
            },
            data=b"\x00\x00\x00\x00\x00",
        )
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    hdrs = {k.lower(): v for k, v in r.headers.items()}
    text = r.text or ""
    # 只用 grpc-status；details-bin 是 protobuf，当真值会假 L1
    trailers = str(hdrs.get("grpc-status") or "").strip()
    if not trailers:
        m = re.search(r"(?:^|[\r\n])grpc-status[:\s]+(\d+)", text, re.I)
        trailers = m.group(1) if m else ""
    return {
        "url": url,
        "status": r.status_code,
        "grpc_status": str(trailers)[:40],
        "content_type": (hdrs.get("content-type") or "")[:80],
        "snip": re.sub(r"\s+", " ", text)[:160],
    }


def _get(sess: requests.Session, url: str) -> dict[str, Any]:
    try:
        r = sess.get(url, timeout=10, verify=False, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    return {
        "url": url,
        "status": r.status_code,
        "size": len(r.text or ""),
        "snip": re.sub(r"\s+", " ", r.text or "")[:160],
    }


def _bases(raw: str, extra_ports: bool) -> list[str]:
    s = (raw or "").strip()
    if "://" not in s:
        s = "https://" + s
    u = urlparse(s)
    host = u.hostname or ""
    out = [s.rstrip("/")]
    if extra_ports and host and u.port not in {50051, 9090}:
        out.append(f"http://{host}:50051")
        out.append(f"http://{host}:9090")
    seen: set[str] = set()
    uniq: list[str] = []
    for b in out:
        if b not in seen:
            seen.add(b)
            uniq.append(b)
    return uniq


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    findings: list[dict[str, Any]] = []
    for base in _bases(args.base, bool(args.extra_ports)):
        for p in GRPC_PATHS:
            row = _grpc_post(sess, base + p)
            gs = row.get("grpc_status") or ""
            ctype = (row.get("content_type") or "").lower()
            transport = bool(gs) or ctype.startswith("application/grpc")
            if not transport:
                continue
            findings.append({"level": "L1", "signal": "grpc-transport", **{k: v for k, v in row.items() if k != "error"}})
            print(f"  L1 grpc-status={gs or ctype} {p}")
            if "Health/Check" in p and gs in {"0", "OK", "ok"}:
                findings.append({"level": "L2", "signal": "grpc-health-unauth", "url": row.get("url")})
                print("  L2 Health Check OK unauth")
            if "Reflection" in p and (
                gs in {"0", "OK"} or "reflection" in (row.get("snip") or "").lower()
            ):
                findings.append({"level": "L2", "signal": "grpc-reflection", "url": row.get("url")})
                print("  L2 ServerReflection")
        for p in HTTP_PATHS:
            row = _get(sess, base + p)
            st = int(row.get("status") or 0)
            snip = row.get("snip") or ""
            if st == 200 and p in ("/swagger.json", "/openapi.json") and re.search(
                r'["\'](?:swagger|openapi)["\']', snip, re.I,
            ):
                findings.append({"level": "L1", "signal": "grpc-gateway-doc", "path": p, "status": st})
                print(f"  L1 gateway doc {p}")
            if st == 200 and p == "/.well-known/grpc" and re.search(r"grpc", snip, re.I):
                findings.append({"level": "L1", "signal": "grpc-well-known", "path": p, "status": st})
            if st == 200 and p.startswith("/v1/admin") and snip.lstrip()[:1] in "{[" and re.search(
                r'"(?:id|email|username|users|items)"', snip, re.I,
            ):
                findings.append({"level": "L2", "signal": "grpc-gateway-admin-json", "path": p})
                print("  L2 gateway admin JSON")

    levels = {f.get("level") for f in findings}
    level = "L2" if "L2" in levels else ("L1" if "L1" in levels else "none")
    report = {
        "target": args.base.rstrip("/"),
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "findings": findings,
        "playbook": "传承/沉声·猎面.md",
        "next": "Unimplemented(12) 只证明传输。禁止 Rapid Reset。",
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="grpc", filename="surface.json",
    )
    print(json.dumps({"level": level, "findings": len(findings), "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="gRPC 猎面探针（无 Rapid Reset）")
    ap.add_argument("-u", "--url", "--base", dest="base", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument(
        "--extra-ports",
        action="store_true",
        help="额外探同主机 :50051 / :9090（默认关，避免无 gRPC 站空转超时）",
    )
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
