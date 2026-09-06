#!/usr/bin/env python3
"""C2 零信任控制台面（授权目标）。黑洞 + 敲门 + HMAC + Vue/PTY，不靠扫 65535 结案。

用法:
  python3 炼蛊房/c2_zt_probe.py drive --base https://授权站 --case <案>
  python3 炼蛊房/c2_zt_probe.py drive --base https://授权站 --origin-ip 1.2.3.4 --case <案>
  python3 炼蛊房/c2_zt_probe.py hmac --key <钥> --method GET --path /api/knock
  python3 炼蛊房/c2_zt_probe.py extract --path bundle.js
  python3 炼蛊房/c2_zt_probe.py knock --host <源IP> --seq 7000,8000,9000
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

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

UA = "Mozilla/5.0 大爱仙尊-c2-zt"
FOCUS_PORTS = (22, 80, 443, 1234, 3000, 6666, 8000, 8080, 8443, 8888, 8889, 9000, 9090)
CONSOLE_PATHS = (
    "/api/v1/keys/apply",
    "/user/api-key/apply",
    "/api/keys/apply",
    "/console/",
    "/pty/",
    "/pty/ws",
    "/api/db/query",
    "/api/db/export",
    "/api/sandbox/exec",
    "/api/assets/export",
    "/api/assets/export?format=zip",
)
JS_CANDIDATES = (
    "/assets/index.js",
    "/app.js",
    "/static/js/app.js",
    "/console/app.js",
)
KNOCK_WORD = re.compile(r"(port[_-]?knock|knockd|spake2|handshake|port_knock)", re.I)
KNOCK_SEQ = re.compile(
    r"(?:knock|handshake)[^;]{0,160}?(\d{2,5}\s*,\s*\d{2,5}(?:\s*,\s*\d{2,5})+)",
    re.I,
)
HMAC_NEAR = re.compile(
    r"(?is)(?:hmac|x-auth|xauth|spake2|sign(?:ature)?)[A-Za-z0-9_-]{0,24}\s*[:=]?\s*['\"]([A-Za-z0-9+/=_\-]{8,64})['\"]"
)
WS_PATH = re.compile(r"(wss?://[^\s\"']+)|((?:/pty/|/console/ws|/terminal)[^\s\"']*)", re.I)
ICE = re.compile(r"(stun:|turn:)[^\s\"']+", re.I)
API_QUOT = re.compile(r"\"(/[a-zA-Z0-9_./-]{2,80})\"")
BACK_HOST = re.compile(
    r"(?:backaddress|hidden.?host|c2\.internal)[^\n]{0,80}['\"]([A-Za-z0-9._:-]{4,80})['\"]",
    re.I,
)
SCRIPT_SRC = re.compile(r"""<script[^>]+src=['\"]([^'\"]+\.js[^'\"]*)['\"]""", re.I)
CF_NEEDLE = ("cloudflare", "cf-ray", "cf-cache-status", "__cf_bm")
APP_NEEDLE = ("vue", "c2", "console", "pty", "knock", "spake", "webrtc")


def hmac_x_auth(key: str, ts: str, method: str, path: str) -> str:
    msg = f"{ts}|{method.upper()}|{path}".encode()
    sig = hmac.new(key.encode(), msg, hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"


def extract_console_js(text: str) -> dict[str, Any]:
    text = text or ""
    seqs = []
    for m in KNOCK_SEQ.finditer(text):
        nums = [int(x.strip()) for x in m.group(1).split(",")]
        if 2 <= len(nums) <= 8 and all(1 <= n <= 65535 for n in nums):
            seqs.append(nums)
    keys = []
    for m in HMAC_NEAR.finditer(text):
        val = m.group(1)
        if val.lower() in {"hmac", "sha256", "signature", "password", "undefined"}:
            continue
        keys.append(val)
    ws = [a or b for a, b in WS_PATH.findall(text)]
    ice = ICE.findall(text)
    apis = sorted({p for p in API_QUOT.findall(text) if any(x in p for x in ("/api", "/pty", "/console", "/knock"))})
    backs = [m.group(1) for m in BACK_HOST.finditer(text)]
    return {
        "knock_word": bool(KNOCK_WORD.search(text)),
        "knock_seq": seqs[:5],
        "hmac_keys": keys[:8],
        "ws": ws[:8],
        "ice": ice[:8],
        "apis": apis[:40],
        "back_hosts": backs[:8],
    }


def tun_illusion(tcp_open: list[int], http_status: dict[int, int]) -> bool:
    if len(tcp_open) < 6:
        return False
    codes = [http_status[p] for p in tcp_open if p in http_status]
    if len(codes) < 4:
        return False
    return len(set(codes)) == 1 and codes[0] in {0, 502, 503}


def _get(sess: requests.Session, url: str, *, headers: dict[str, str] | None = None, timeout: int = 8) -> dict[str, Any]:
    try:
        r = sess.get(url, timeout=timeout, verify=False, allow_redirects=True, headers=headers or {})
    except Exception as e:
        return {"url": url, "error": str(e)[:120], "status": 0, "text": "", "hdr": {}}
    text = r.text or ""
    hdr = {k.lower(): v for k, v in r.headers.items()}
    return {
        "url": url,
        "status": r.status_code,
        "size": len(text),
        "text": text[:8000],
        "snip": re.sub(r"\s+", " ", text)[:160],
        "hdr": hdr,
        "ct": (hdr.get("content-type") or "")[:80],
    }


def parse_knock_seq(raw: str) -> list[int]:
    nums = [int(x.strip()) for x in (raw or "").split(",") if x.strip().isdigit()]
    if not (2 <= len(nums) <= 8 and all(1 <= n <= 65535 for n in nums)):
        raise ValueError("knock 序列要 2–8 个 1–65535 端口")
    return nums


def send_knock(host: str, ports: list[int], *, proto: str = "tcp") -> None:
    for port in ports:
        if proto == "udp":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.sendto(b"\x00", (host, port))
            finally:
                s.close()
            continue
        s = socket.socket()
        s.settimeout(0.3)
        try:
            s.connect_ex((host, port))
        finally:
            s.close()


def tcp_open(host: str, port: int, timeout: float = 0.45) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def _looks_app(row: dict[str, Any]) -> bool:
    blob = ((row.get("text") or "") + " " + str(row.get("hdr") or "")).lower()
    if any(n in blob for n in CF_NEEDLE) and row.get("status") in {403, 503}:
        return False
    return any(n in blob for n in APP_NEEDLE) or (
        row.get("status") == 200 and "json" in (row.get("ct") or "")
    )


def _require_scope(url_or_host: str) -> str:
    host = host_of(url_or_host) or url_or_host
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or url_or_host}", file=sys.stderr)
        sys.exit(2)
    return host


def _pull_js(sess: requests.Session, base: str, html: str) -> str:
    blobs = [html]
    srcs = SCRIPT_SRC.findall(html)[:8]
    for rel in list(srcs) + list(JS_CANDIDATES):
        if rel.startswith("http"):
            url = rel
        else:
            url = urljoin(base.rstrip("/") + "/", rel.lstrip("/"))
        row = _get(sess, url)
        if row.get("status") == 200 and (row.get("text") or "").strip():
            blobs.append(row["text"])
    return "\n".join(blobs)


def cmd_hmac(args: argparse.Namespace) -> int:
    tok = hmac_x_auth(args.key, args.ts or str(int(datetime.now(UTC).timestamp())), args.method, args.path)
    print(json.dumps({"X-Auth": tok, "method": args.method, "path": args.path}, ensure_ascii=False))
    return 0


def cmd_knock(args: argparse.Namespace) -> int:
    host = _require_scope(args.host)
    seq = parse_knock_seq(args.seq)
    send_knock(host, seq, proto=args.proto)
    after = [p for p in FOCUS_PORTS if tcp_open(host, p)]
    print(json.dumps({"host": host, "seq": seq, "proto": args.proto, "focus_open_after": after}, ensure_ascii=False))
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    if args.path:
        text = Path(args.path).read_text(encoding="utf-8", errors="replace")
    elif args.base:
        _require_scope(args.base)
        sess = requests.Session()
        sess.headers["User-Agent"] = UA
        home = _get(sess, args.base)
        text = _pull_js(sess, args.base, home.get("text") or "")
    else:
        print("[!] 需要 --path 或 --base", file=sys.stderr)
        return 2
    rec = extract_console_js(text)
    print(json.dumps(rec, ensure_ascii=False, indent=2))
    return 0


def cmd_drive(args: argparse.Namespace) -> int:
    host = _require_scope(args.base)
    if args.origin_ip:
        _require_scope(args.origin_ip)
    base = args.base.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    findings: list[dict[str, Any]] = []

    home = _get(sess, base)
    hdr_blob = " ".join(f"{k}:{v}" for k, v in (home.get("hdr") or {}).items()).lower()
    if any(n in hdr_blob or n in (home.get("text") or "").lower() for n in CF_NEEDLE):
        findings.append({"level": "L1", "signal": "cf-front", "path": "/"})
    js = extract_console_js(_pull_js(sess, base, home.get("text") or ""))
    if js["knock_word"] or js["knock_seq"]:
        findings.append({
            "level": "L2" if js["knock_seq"] else "L1",
            "signal": "knock-js",
            "seq": js["knock_seq"],
            "note": "序列在前端；复现用 knock，不默认对全端口喷",
        })
    if js["hmac_keys"]:
        findings.append({
            "level": "L2",
            "signal": "hmac-key-js",
            "keys": [k[:8] + "…" for k in js["hmac_keys"]],
            "note": "用 hmac 子命令铸 X-Auth，先短窗重放再谈爆破",
        })
        tok = hmac_x_auth(js["hmac_keys"][0], str(int(datetime.now(UTC).timestamp())), "GET", "/api/knock")
        replay = _get(sess, urljoin(base + "/", "api/knock"), headers={"X-Auth": tok})
        if replay.get("status") in {200, 204} and "json" in (replay.get("ct") or "") + (replay.get("text") or "")[:40].lower():
            findings.append({"level": "L2", "signal": "hmac-replay", "path": "/api/knock", "status": replay.get("status")})
        elif replay.get("status") in {400, 401, 403} and not replay.get("error"):
            findings.append({"level": "L1", "signal": "hmac-surface", "path": "/api/knock", "status": replay.get("status")})
    if js["ws"]:
        findings.append({"level": "L1", "signal": "pty-ws", "ws": js["ws"][:4]})
    if js["ice"]:
        findings.append({"level": "L1", "signal": "webrtc-ice", "ice": js["ice"][:4]})
    if js.get("back_hosts"):
        findings.append({"level": "L1", "signal": "js-back-host", "hosts": js["back_hosts"][:4]})

    origin = args.origin_ip or ""
    if origin:
        for port in (80, 443, 8080, 8888, 8889):
            url = f"http://{origin}:{port}/"
            host_hit = _get(sess, url, headers={"Host": host})
            xff = _get(sess, url, headers={"Host": host, "X-Forwarded-For": "1.1.1.1"})
            if _looks_app(host_hit) or _looks_app(xff):
                findings.append({
                    "level": "L2",
                    "signal": "origin-host-bypass",
                    "url": url,
                    "host_status": host_hit.get("status"),
                    "xff_status": xff.get("status"),
                })
                break
            if host_hit.get("status") in {401, 403} and not host_hit.get("error"):
                findings.append({"level": "L1", "signal": "origin-alive", "url": url, "status": host_hit.get("status")})

    scan_host = origin or host
    if args.knock_seq:
        seq = parse_knock_seq(args.knock_seq)
        send_knock(scan_host, seq, proto=args.knock_proto)
        findings.append({"level": "L1", "signal": "knock-sent", "seq": seq, "proto": args.knock_proto})
    opened: list[int] = []
    http_st: dict[int, int] = {}
    for port in FOCUS_PORTS:
        if tcp_open(scan_host, port):
            opened.append(port)
            scheme = "https" if port in {443, 8443} else "http"
            row = _get(sess, f"{scheme}://{scan_host}:{port}/", timeout=4)
            http_st[port] = int(row.get("status") or 0)
    if tun_illusion(opened, http_st):
        findings.append({"level": "L1", "signal": "tun-illusion", "open": opened, "note": "TCP 全通且 HTTP 同码，当代理假 OPEN"})
    elif opened:
        findings.append({"level": "L1", "signal": "focus-open", "open": opened, "http": http_st})
    elif not opened:
        findings.append({"level": "L1", "signal": "blackhole-focus", "note": "重点口全关；广谱 65535 别空转"})

    for path in CONSOLE_PATHS:
        row = _get(sess, urljoin(base + "/", path.lstrip("/")))
        js_ok = False
        try:
            data = json.loads(row.get("text") or "")
            js_ok = isinstance(data, (dict, list))
        except Exception:
            js_ok = False
        htmlish = "<html" in (row.get("text") or "").lower()
        if row.get("status") == 200 and js_ok and not htmlish:
            findings.append({"level": "L2", "signal": "console-unauth", "path": path, "status": 200})
        elif row.get("status") in {400, 401, 415} and not htmlish and row.get("size", 0) < 4000:
            findings.append({"level": "L1", "signal": "console-surface", "path": path, "status": row.get("status")})

    level = "none"
    for want in ("L3", "L2", "L1"):
        if any(f.get("level") == want for f in findings):
            level = want
            break
    report = {
        "target": base,
        "origin_ip": origin,
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "findings": findings,
        "js": {k: js.get(k) for k in ("knock_word", "knock_seq", "ws", "ice", "apis", "back_hosts")},
        "playbook": "传承/行器·敲门.md",
        "skill": "行器·敲门",
        "next": "L2=JS 里敲门序列/HMAC 钥，或源站 Host/XFF 出控制台，或未授权 JSON。改超管密/持久化先问。",
    }
    out = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="c2_zt", filename="surface.json",
    )
    print(json.dumps({"level": level, "findings": len(findings), "out": str(out)}, ensure_ascii=False))
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="C2 零信任控制台面（授权内）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("drive")
    d.add_argument("--base", "-u", required=True)
    d.add_argument("--origin-ip", default="")
    d.add_argument("--knock-seq", default="", help="仅显式给出才发，如 7000,8000,9000")
    d.add_argument("--knock-proto", choices=("tcp", "udp"), default="tcp")
    d.add_argument("--case", default="")
    d.add_argument("--out", type=Path, default=None)
    k = sub.add_parser("knock")
    k.add_argument("--host", required=True)
    k.add_argument("--seq", required=True)
    k.add_argument("--proto", choices=("tcp", "udp"), default="tcp")
    h = sub.add_parser("hmac")
    h.add_argument("--key", required=True)
    h.add_argument("--method", default="GET")
    h.add_argument("--path", default="/api/knock")
    h.add_argument("--ts", default="")
    e = sub.add_parser("extract")
    e.add_argument("--path", default="")
    e.add_argument("--base", "-u", default="")
    args = ap.parse_args()
    if args.cmd == "hmac":
        raise SystemExit(cmd_hmac(args))
    if args.cmd == "extract":
        raise SystemExit(cmd_extract(args))
    if args.cmd == "knock":
        raise SystemExit(cmd_knock(args))
    raise SystemExit(cmd_drive(args))


if __name__ == "__main__":
    main()
