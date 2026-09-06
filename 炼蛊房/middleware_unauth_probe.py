#!/usr/bin/env python3
"""中间件未授权探针：Mongo / Elasticsearch / Memcached（授权范围内）。

只做握手 + 只读列举。不写盘、不删索引、不 flush_all。
Redis 仍走 redis_unauth_probe.py。
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402


def _mongo_op_query_ismaster() -> bytes:
    doc = b"\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00"
    cname = b"admin.$cmd\x00"
    body = struct.pack("<i", 0) + cname + struct.pack("<ii", 0, -1) + doc
    header = struct.pack("<iiii", 16 + len(body), 1, 0, 2004)
    return header + body


def _mongo_op_msg_hello() -> bytes:
    doc = b"\x10\x00\x00\x00\x10hello\x00\x01\x00\x00\x00\x00"
    section = b"\x00" + doc
    body = struct.pack("<I", 0) + section
    header = struct.pack("<iiii", 16 + len(body), 2, 0, 2013)
    return header + body


def _tcp(host: str, port: int, payload: bytes, timeout: float = 3.0) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        if payload:
            sock.sendall(payload)
        chunks = b""
        while len(chunks) < 4096:
            try:
                part = sock.recv(1024)
            except TimeoutError:
                break
            if not part:
                break
            chunks += part
            if len(part) < 1024:
                break
        return chunks
    except OSError:
        return b""
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _http(url: str, timeout: float = 4.0) -> tuple[int, str]:
    req = Request(url, headers={"User-Agent": "大爱仙尊-middleware"})
    try:
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310 授权目标
            body = resp.read(8000).decode("utf-8", errors="replace")
            return int(getattr(resp, "status", 200) or 200), body
    except HTTPError as exc:
        try:
            body = exc.read(400).decode("utf-8", errors="replace")
        except Exception:
            body = str(exc)
        return int(exc.code), body
    except (URLError, OSError, TimeoutError, ValueError) as exc:
        return 0, str(exc)[:200]


def _looks_mongo(raw: bytes) -> bool:
    if not raw:
        return False
    low = raw.lower()
    return any(k in low for k in (b"ismaster", b"iswritableprimary", b"maxbson", b"hellook", b"mongodb"))


def probe_mongo(host: str, port: int) -> dict[str, Any] | None:
    raw = _tcp(host, port, _mongo_op_query_ismaster())
    if not _looks_mongo(raw):
        raw = _tcp(host, port, _mongo_op_msg_hello())
    if not _looks_mongo(raw):
        return None
    text = raw.decode("latin1", errors="replace")
    return {
        "family": "mongo",
        "level": "L1",
        "port": port,
        "signal": "mongo-hello",
        "banner": text[:180].replace("\x00", " "),
    }


def _looks_es(body: str) -> bool:
    return any(k in body for k in ("cluster_name", "tagline", "lucene_version", "You Know, for Search"))


def probe_es(host: str, port: int) -> dict[str, Any] | None:
    code, body = 0, ""
    for scheme in ("http", "https"):
        code, body = _http(f"{scheme}://{host}:{port}/")
        if code == 200 and _looks_es(body):
            item: dict[str, Any] = {
                "family": "elasticsearch",
                "level": "L1",
                "port": port,
                "signal": "es-root",
                "scheme": scheme,
                "banner": body[:240],
            }
            icode, ibody = _http(f"{scheme}://{host}:{port}/_cat/indices?v")
            if icode == 200 and ibody.strip() and not ibody.lstrip().startswith("<"):
                item["level"] = "L2"
                item["signal"] = "es-indices"
                item["indices_preview"] = ibody[:400]
            return item
        if code in (401, 403) and _looks_es(body):
            return {
                "family": "elasticsearch",
                "level": "L1",
                "port": port,
                "signal": "es-auth-required",
                "scheme": scheme,
                "note": "ES 在线但要账密，不算未授权",
            }
    return None


def probe_memcached(host: str, port: int) -> dict[str, Any] | None:
    raw = _tcp(host, port, b"stats\r\n")
    if not raw or b"STAT " not in raw:
        return None
    return {
        "family": "memcached",
        "level": "L1",
        "port": port,
        "signal": "memcached-stats",
        "banner": raw.decode("latin1", errors="replace")[:240],
    }


def run(host: str, case: str, out: Path | None, ports: dict[str, int]) -> dict[str, Any]:
    host = host_of(host) or host.strip()
    if host and not in_scope(host):
        print(f"[!] 不在 scope：{host}", file=sys.stderr)
        sys.exit(2)
    findings: list[dict[str, Any]] = []
    for fn, key in ((probe_mongo, "mongo"), (probe_es, "es"), (probe_memcached, "memcached")):
        hit = fn(host, ports[key])
        if hit:
            findings.append(hit)
    unauth = [f for f in findings if f.get("signal") != "es-auth-required"]
    report: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "host": host,
        "ports": ports,
        "findings": findings,
        "unauth_hits": len(unauth),
        "playbook": "传承/中门无门.md",
        "skill": "杀招/中门无门",
        "next": [
            "Mongo L1 → 只读 listDatabases；写盘/JS RCE 先问",
            "ES L2 → 抽样 _search size=1，禁止 _delete_by_query",
            "es-auth-required → 弱口另测，不算未授权",
            "Memcached L1 → 只 stats/get 抽样，禁止 flush_all",
            "6379 另走 redis_unauth_probe.py",
        ],
    }
    out_path = write_probe_json(
        report, case=case, out=out, case_subdir="middleware", filename="probe.json"
    )
    print(
        json.dumps(
            {"findings": [f.get("family") for f in findings], "unauth": len(unauth), "out": str(out_path)},
            ensure_ascii=False,
        )
    )
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Mongo/ES/Memcached 未授权探针")
    ap.add_argument("--host", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--mongo-port", type=int, default=27017)
    ap.add_argument("--es-port", type=int, default=9200)
    ap.add_argument("--memcached-port", type=int, default=11211)
    args = ap.parse_args()
    parsed = urlparse(args.host if "://" in args.host else f"//{args.host}")
    host = parsed.hostname or args.host
    run(
        host,
        args.case,
        args.out,
        {"mongo": args.mongo_port, "es": args.es_port, "memcached": args.memcached_port},
    )


if __name__ == "__main__":
    main()
