#!/usr/bin/env python3
"""ThinkPHP 探针（授权范围内）。默认做指纹 + Client-IP 差分 + .env 暴露。"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import require_in_scope  # noqa: E402


def _get(sess: requests.Session, url: str) -> requests.Response | None:
    try:
        return sess.get(url, timeout=12, verify=False, allow_redirects=True)
    except Exception:
        return None


def run(base_url: str, case: str, out: Path | None, probe_ip: bool = True) -> dict[str, Any]:
    host = urlparse(base_url).hostname or ""
    if host:
        require_in_scope(host)
    base = base_url.rstrip("/") + "/"
    sess = requests.Session()
    sess.headers["User-Agent"] = "Mozilla/5.0 (compatible; 大爱仙尊-ThinkPHP/1.0)"
    findings: list[dict[str, Any]] = []
    rmd = _get(sess, urljoin(base, "/ThinkPHP/README.md"))
    if rmd is not None and rmd.status_code == 200 and "thinkphp" in rmd.text.lower():
        findings.append({
            "level": "L1",
            "path": "/ThinkPHP/README.md",
            "status": rmd.status_code,
            "signal": "thinkphp-readme",
            "next": "传承/幻三·分销.md · tp3_fenxiao_probe.py",
        })
        if "3.1" in rmd.text or "魔改" in rmd.text:
            findings.append({
                "level": "L1",
                "path": "/ThinkPHP/README.md",
                "signal": "tp3-modded",
                "next": "python3 炼蛊房/tp3_fenxiao_probe.py -u " + base_url,
            })
    fen = _get(sess, urljoin(base, "/index.php/ApiUserFenxiao/get_fenxiao_db_data"))
    if fen is not None and fen.status_code == 200 and "admin_now_money" in fen.text:
        findings.append({
            "level": "L2",
            "path": "/index.php/ApiUserFenxiao/get_fenxiao_db_data",
            "signal": "fenxiao-hint",
            "next": "python3 炼蛊房/tp3_fenxiao_probe.py -u " + base_url,
        })
    paths = ["/", "/index.php", "/index.php?s=", "/public/index.php", "/admin"]
    for p in paths:
        r = _get(sess, urljoin(base, p))
        if not r:
            continue
        blob = (r.headers.get("X-Powered-By", "") + " " + r.text[:4000]).lower()
        if "thinkphp" in blob or "think\\app" in r.text.lower() or "think\\lang" in r.text.lower():
            findings.append({
                "level": "L1",
                "path": p,
                "status": r.status_code,
                "signal": "thinkphp-fingerprint",
                "x-powered-by": r.headers.get("X-Powered-By", ""),
            })
            break
    for p in ("/.env", "/.env.production", "/application/.env"):
        r = _get(sess, urljoin(base, p))
        if not r or r.status_code != 200:
            continue
        body = r.text[:4000]
        if "APP_KEY" in body or "DB_PASSWORD" in body or "REDIS_PASSWORD" in body:
            keys = []
            for line in body.splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    keys.append(line.split("=", 1)[0].strip()[:40])
            findings.append({
                "level": "L2",
                "path": p,
                "status": r.status_code,
                "signal": "env-exposed",
                "env_keys": keys[:30],
                "next": "密钥打码后回灌假支付 / 面板；不把 .env 全文进 git",
            })
            break
    if probe_ip:
        admin = urljoin(base, "/admin")
        r0 = _get(sess, admin)
        r1 = None
        try:
            r1 = sess.get(
                admin, timeout=12, verify=False, allow_redirects=True,
                headers={"Client-IP": "127.0.0.1", "X-Forwarded-For": "127.0.0.1"},
            )
        except Exception:
            pass
        s0 = r0.status_code if r0 else None
        s1 = r1.status_code if r1 else None
        if s0 is not None and s1 is not None and s0 != s1:
            findings.append({
                "level": "L2a-hint",
                "path": "/admin",
                "status_plain": s0,
                "status_client_ip": s1,
                "signal": "ip-header-status-delta",
                "next": "传承/踪·破禁.md",
            })
    report = {
        "target": base_url,
        "ts": datetime.now(UTC).isoformat(),
        "findings": findings,
        "playbook": "传承/幻页·认族.md",
        "next": "L2 信任头/.env 后切 IP白名单或假支付；README/ApiXxx 切 tp3_fenxiao_probe",
    }
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    written: list[Path] = []
    if case:
        d = ROOT / "案卷" / case / "测绘" / "thinkphp"
        d.mkdir(parents=True, exist_ok=True)
        p = d / "surface.json"
        p.write_text(text, encoding="utf-8")
        written.append(p)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        written.append(out)
    if not written:
        p = Path("thinkphp_surface.json")
        p.write_text(text, encoding="utf-8")
        written.append(p)
    out_path = written[-1] if out else written[0]
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"[+] wrote {out_path}", file=sys.stderr)
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="ThinkPHP 指纹探针")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--no-probe-ip-header", action="store_true", help="关掉 /admin Client-IP 差分")
    args = ap.parse_args()
    run(args.url, args.case, args.out, probe_ip=not args.no_probe_ip_header)


if __name__ == "__main__":
    main()
