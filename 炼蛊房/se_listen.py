#!/usr/bin/env python3
"""大爱仙尊回连监听：案卷落盘，不用 nc 口头交差。

攻击机跑本进程，授权机执行 se_cb.sh / se_cb.py。
--once 收一条连接就退出（给自动化/验活）。交互模式把 stdin 转给对端。

示例:
  python3 炼蛊房/se_listen.py --lport 4444 --case <案>
  python3 炼蛊房/se_listen.py --lhost 0.0.0.0 --lport 4444 --once --case <案>
  python3 炼蛊房/se_listen.py --self-test
"""
from __future__ import annotations

import argparse
import json
import select
import socket
import sys
import threading
import time
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    from scope_lib import ENGINE  # noqa: WPS433

    d = ENGINE / "案卷" / case / "测绘" / "c2"
    d.mkdir(parents=True, exist_ok=True)
    return d


def log_event(case: str, row: dict[str, Any]) -> Path | None:
    if not case:
        return None
    p = case_dir(case) / "listen.jsonl"
    rec = {"ts": _now(), **row}
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return p


def recv_once(sock: socket.socket, *, timeout: float, limit: int = 65536) -> bytes:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    n = 0
    while n < limit:
        try:
            b = sock.recv(4096)
        except socket.timeout:
            break
        if not b:
            break
        chunks.append(b)
        n += len(b)
        if b.endswith(b"\n") and n > 0:
            break
    return b"".join(chunks)


def serve_once(bind: str, port: int, *, timeout: float, case: str) -> dict[str, Any]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port))
    srv.listen(1)
    srv.settimeout(timeout)
    actual = srv.getsockname()
    try:
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            rec = {"ok": False, "error": "timeout", "bind": list(actual)}
            log_event(case, rec)
            return rec
        with conn:
            data = recv_once(conn, timeout=min(timeout, 8.0))
            rec = {
                "ok": True,
                "peer": f"{addr[0]}:{addr[1]}",
                "bind": list(actual),
                "bytes": len(data),
                "preview": data[:200].decode("utf-8", errors="replace"),
            }
            log_event(case, rec)
            return rec
    finally:
        srv.close()


def serve_interactive(bind: str, port: int, *, case: str) -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port))
    srv.listen(1)
    actual = srv.getsockname()
    print(f"[listen] {actual[0]}:{actual[1]}  等回连", file=sys.stderr)
    log_event(case, {"ok": True, "phase": "wait", "bind": list(actual)})
    conn, addr = srv.accept()
    print(f"[listen] peer {addr[0]}:{addr[1]}", file=sys.stderr)
    log_event(case, {"ok": True, "phase": "accept", "peer": f"{addr[0]}:{addr[1]}"})
    conn.setblocking(False)
    try:
        while True:
            r, _, _ = select.select([conn, sys.stdin], [], [], 0.5)
            if conn in r:
                data = conn.recv(4096)
                if not data:
                    print("[listen] 对端关", file=sys.stderr)
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            if sys.stdin in r:
                line = sys.stdin.buffer.readline()
                if not line:
                    break
                conn.sendall(line)
    finally:
        conn.close()
        srv.close()
    return 0


def run_self_test() -> list[str]:
    fails: list[str] = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.close()

    box: dict[str, Any] = {}

    def server() -> None:
        box["rec"] = serve_once("127.0.0.1", port, timeout=3.0, case="")

    t = threading.Thread(target=server, daemon=True)
    t.start()
    time.sleep(0.15)
    c = socket.create_connection(("127.0.0.1", port), timeout=2)
    c.sendall(b"uid=0 se-listen\n")
    c.close()
    t.join(timeout=4)
    rec = box.get("rec") or {}
    if not rec.get("ok"):
        fails.append("no-accept")
    if "se-listen" not in (rec.get("preview") or ""):
        fails.append("preview")
    return fails


def main() -> int:
    ap = argparse.ArgumentParser(description="大爱仙尊回连监听")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--lhost", default="0.0.0.0")
    ap.add_argument("--lport", type=int, default=4444)
    ap.add_argument("--case", default="")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--timeout", type=float, default=30.0)
    args = ap.parse_args()
    if args.self_test:
        fails = run_self_test()
        if fails:
            for f in fails:
                print(f"FAIL {f}")
            return 1
        print("self-test ok  se_listen")
        return 0
    if args.once:
        rec = serve_once(args.lhost, args.lport, timeout=args.timeout, case=args.case)
        print(json.dumps(rec, ensure_ascii=False))
        return 0 if rec.get("ok") else 1
    return serve_interactive(args.lhost, args.lport, case=args.case)


if __name__ == "__main__":
    raise SystemExit(main())
