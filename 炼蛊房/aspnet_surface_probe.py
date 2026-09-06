#!/usr/bin/env python3
"""ASP.NET WebForms 猎面（授权范围内）。

L1：X-AspNet-Version / __VIEWSTATE / IIS。
L2：空 VIEWSTATEENCRYPTED、匿名 elmah/trace、Telerik RAU。
--parser-diff 只比错误文案。不发 gadget。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, UTC
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

UA = "Mozilla/5.0 大爱仙尊-aspnet"
AXD = (
    "/trace.axd",
    "/elmah.axd",
    "/Telerik.Web.UI.WebResource.axd?type=rau",
    "/ScriptResource.axd",
)


def _get(sess: requests.Session, url: str) -> dict[str, Any]:
    try:
        r = sess.get(url, timeout=12, verify=False, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    text = r.text or ""
    hdrs = {k.lower(): v[:180] for k, v in r.headers.items()}
    return {
        "url": url,
        "status": r.status_code,
        "size": len(text),
        "headers": {
            k: hdrs[k] for k in hdrs
            if k in (
                "x-aspnet-version", "x-aspnetmvc-version", "x-powered-by",
                "server", "set-cookie", "microsoftsharepointteamservices",
                "sprequestguid",
            )
        },
        "snip": re.sub(r"\s+", " ", text)[:200],
        "text": text[:60000],
    }


def _title(text: str) -> str:
    m = re.search(r"<title>([^<]+)</title>", text or "", re.I)
    return (m.group(1) if m else "")[:120]


def _hidden(html: str, name: str) -> tuple[bool, str | None]:
    """name/value 属性顺序不限。返回 (是否存在, value 或 None)。"""
    pat = (
        rf'(?:name=["\']{name}["\'][^>]*value=["\']([^"\']*)["\']'
        rf'|value=["\']([^"\']*)["\'][^>]*name=["\']{name}["\'])'
    )
    m = re.search(pat, html or "", re.I)
    if m:
        val = m.group(1) if m.group(1) is not None else (m.group(2) or "")
        return True, val
    if re.search(rf'(?:id|name)=["\']{name}["\']', html or "", re.I):
        return True, None
    return False, None


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    base = args.base.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    findings: list[dict[str, Any]] = []
    home = _get(sess, base + "/")
    blob = json.dumps(home.get("headers") or {}) + (home.get("text") or "")
    if re.search(r"sharepoint|_layouts|_vti_bin|microsoftsharepoint", blob, re.I):
        findings.append({"level": "L1", "signal": "sharepoint-handoff", "next": "sharepoint-unauth-rce"})
        print("  L1 SharePoint → sharepoint-unauth-rce")
    asp = bool(re.search(
        r"x-aspnet|__VIEWSTATE|\.ASPXAUTH|ASP\.NET_SessionId|X-Powered-By.:.ASP\.NET",
        blob,
        re.I,
    ))
    if asp:
        findings.append({"level": "L1", "signal": "aspnet-fingerprint", "status": home.get("status")})
        print("  L1 ASP.NET fingerprint")
    html = home.get("text") or ""
    vs_ok, vs_val = _hidden(html, "__VIEWSTATE")
    enc_ok, enc_val = _hidden(html, "__VIEWSTATEENCRYPTED")
    if vs_ok:
        findings.append({"level": "L1", "signal": "viewstate-present"})
    if enc_ok and enc_val == "":
        findings.append({"level": "L2", "signal": "viewstate-signed-only"})
        print("  L2 VIEWSTATEENCRYPTED empty (signed-only)")

    for p in AXD:
        row = _get(sess, urljoin(base + "/", p.lstrip("/")))
        st = int(row.get("status") or 0)
        body = (row.get("text") or "") + (row.get("snip") or "")
        if st == 200 and p.endswith("trace.axd") and re.search(r"application trace|request details", body, re.I):
            findings.append({"level": "L2", "signal": "trace-axd-anon", "path": p})
            print("  L2 trace.axd")
        elif st == 200 and "elmah" in p.lower() and re.search(r"elmah|error log", body, re.I):
            findings.append({"level": "L2", "signal": "elmah-axd-anon", "path": p})
            print("  L2 elmah.axd")
        elif "telerik" in p.lower() and st == 200 and re.search(
            r"RadAsyncUpload|rauPostData|Telerik\.Web\.UI", body,
        ):
            findings.append({"level": "L2", "signal": "telerik-rau", "path": p, "status": st})
            print("  L2 Telerik RAU")
        elif p.lower().endswith("scriptresource.axd") and st == 200 and re.search(
            r"Type\.registerNamespace|Sys\.Application", body,
        ):
            findings.append({"level": "L1", "signal": "scriptresource-axd", "path": p, "status": st})
            print("  L1 ScriptResource.axd")

    if args.parser_diff and vs_ok and vs_val:
        real = vs_val
        shapes = [
            ("trivial", "AAAA"),
            ("xml", "<xss/>"),
            ("los", "/wEPDwUKMTcxNzgyOTQwMmRk" + "A" * 20),
        ]
        titles: dict[str, str] = {}
        for label, payload in shapes:
            try:
                r = sess.post(
                    base + "/",
                    timeout=12,
                    verify=False,
                    data={"__VIEWSTATE": payload[:4000], "__VIEWSTATEGENERATOR": "AAAA"},
                )
                titles[label] = _title(r.text or "") or str(r.status_code)
            except Exception as e:
                titles[label] = str(e)[:80]
        uniq = set(titles.values())
        if len(uniq) >= 2:
            findings.append({"level": "L2", "signal": "viewstate-parser-diff", "titles": titles})
            print("  L2 parser-diff titles diverge")
        else:
            findings.append({"level": "L1", "signal": "viewstate-parser-same", "titles": titles})
        _ = real  # keep extracted VS unused (no gadget)

    levels = {f.get("level") for f in findings}
    level = "L2" if "L2" in levels else ("L1" if "L1" in levels else "none")
    report = {
        "target": base,
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "findings": findings,
        "playbook": "传承/残网·猎面.md",
        "next": "SharePoint 交接专卡。gadget/machineKey 先问。",
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="aspnet", filename="surface.json",
    )
    print(json.dumps({"level": level, "findings": len(findings), "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="ASP.NET ViewState 猎面探针")
    ap.add_argument("-u", "--url", "--base", dest="base", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--parser-diff", action="store_true", help="只比错误文案，不发 gadget")
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
