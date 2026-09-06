#!/usr/bin/env python3
"""Redis 未授权/弱口只读探针（授权范围内）。

默认只做 PING / INFO / DBSIZE / 有限 SCAN。
不加 CONFIG SET、不写 crontab、不 MODULE LOAD。
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import require_in_scope  # noqa: E402


def _readline(sock: socket.socket) -> bytes:
    data = b""
    while True:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
        if data.endswith(b"\r\n") or len(data) > 65536:
            break
    return data


def _read_resp(sock: socket.socket) -> bytes:
    """读一条完整 RESP（含 * 数组 / $ bulk），避免 SCAN 卡满 timeout。"""
    line = _readline(sock)
    if not line:
        return b""
    t = line[:1]
    if t in (b"+", b"-", b":"):
        return line
    if t == b"$":
        try:
            n = int(line[1:-2])
        except ValueError:
            return line
        if n < 0:
            return line
        body = b""
        need = n + 2
        while len(body) < need:
            chunk = sock.recv(need - len(body))
            if not chunk:
                break
            body += chunk
        return line + body
    if t == b"*":
        try:
            n = int(line[1:-2])
        except ValueError:
            return line
        parts = [line]
        for _ in range(max(0, n)):
            parts.append(_read_resp(sock))
        return b"".join(parts)
    return line


def _redis_cmd(sock: socket.socket, *parts: str) -> str:
    buf = f"*{len(parts)}\r\n"
    for p in parts:
        b = p.encode("utf-8")
        buf += f"${len(b)}\r\n{p}\r\n"
    sock.sendall(buf.encode("utf-8"))
    sock.settimeout(8)
    try:
        return _read_resp(sock).decode("utf-8", errors="replace")[:8000]
    except TimeoutError:
        return ""


def try_auth(host: str, port: int, password: str) -> dict[str, Any]:
    s = socket.create_connection((host, port), timeout=8)
    try:
        if password:
            auth = _redis_cmd(s, "AUTH", password)
            if auth.startswith("-"):
                return {"ok": False, "auth": auth[:200]}
        ping = _redis_cmd(s, "PING")
        if "PONG" not in ping:
            return {"ok": False, "ping": ping[:200]}
        info = _redis_cmd(s, "INFO", "server")
        dbsize = _redis_cmd(s, "DBSIZE")
        keys = _redis_cmd(s, "SCAN", "0", "COUNT", "20")
        return {
            "ok": True,
            "ping": ping[:80],
            "info_snippet": info[:600],
            "dbsize": dbsize[:80],
            "scan_snippet": keys[:400],
        }
    finally:
        s.close()


def run(host: str, port: int, passwords: list[str], case: str, out: Path | None) -> dict[str, Any]:
    require_in_scope(host)
    findings: list[dict[str, Any]] = []
    for pwd in passwords:
        tag = "(empty)" if pwd == "" else "(set)"
        try:
            r = try_auth(host, port, pwd)
        except OSError as e:
            findings.append({"level": "fail", "password": tag, "error": str(e)[:120]})
            break
        if r.get("ok"):
            findings.append({
                "level": "L2",
                "password": tag,
                "signal": "unauth-or-weak",
                "info_snippet": r.get("info_snippet"),
                "dbsize": r.get("dbsize"),
                "scan_snippet": r.get("scan_snippet"),
            })
            try:
                s2 = socket.create_connection((host, port), timeout=8)
                if pwd:
                    _redis_cmd(s2, "AUTH", pwd)
                hot = []
                for pat in ("captcha*", "captcha_codes:*", "login_tokens*", "*session*"):
                    blob = _redis_cmd(s2, "SCAN", "0", "MATCH", pat, "COUNT", "40")
                    if any(x in blob.lower() for x in ("captcha", "login_token", "session")):
                        hot.append({"match": pat, "snippet": blob[:300]})
                s2.close()
                if hot:
                    findings[-1]["hot_keys"] = hot
                    findings[-1]["next"] = "传承/若府·验纹旁路.md"
            except OSError:
                pass
            break
        findings.append({"level": "auth-fail", "password": tag, "detail": r})
    report = {
        "host": host,
        "port": port,
        "ts": datetime.now(UTC).isoformat(),
        "findings": findings,
        "playbook": "传承/契柜·无门.md",
        "note": "未授权则读 captcha/session 键名；不写 CONFIG SET / webshell",
    }
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    written: list[Path] = []
    if case:
        d = ROOT / "案卷" / case / "测绘" / "redis"
        d.mkdir(parents=True, exist_ok=True)
        p = d / "unauth.json"
        p.write_text(text, encoding="utf-8")
        written.append(p)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        written.append(out)
    if not written:
        p = Path("redis_unauth.json")
        p.write_text(text, encoding="utf-8")
        written.append(p)
    out_path = written[-1] if out else written[0]
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"[+] wrote {out_path}", file=sys.stderr)
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Redis 未授权只读探针")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=6379)
    ap.add_argument("--passwords", default=",redis,123456,root",
                    help="逗号分隔，首位空表示先试无密码")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    pwds = args.passwords.split(",")
    run(args.host, args.port, pwds, args.case, args.out)


if __name__ == "__main__":
    main()
