#!/usr/bin/env python3
"""缓存投毒未键控头 + 路径欺骗（授权目标）。结果落 案卷/cache_poison/。

用法:
  python3 炼蛊房/cache_poison_probe.py --url https://授权站/ --case <案卷>
  python3 炼蛊房/cache_poison_probe.py --url https://授权站/ --case <案卷> --deception-only
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
KIT = OPS / "cache_poison_detector.py"
if not KIT.is_file():
    KIT = ENGINE / "tools" / "stdlib-kit" / "cache_poison_detector.py"
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

DECEPTION_PATHS = (
    "account",
    "profile",
    "user",
    "api/me",
    "api/user",
    "me",
    "dashboard",
    "settings",
    "member",
)
DECEPTION_SUFFIX = ("/x.css", "/x.js", "/x.png", "/x.svg", "/x.json")
CACHE_HEADS = (
    "x-cache",
    "cf-cache-status",
    "age",
    "x-cache-hits",
    "x-varnish",
    "cdn-cache-control",
    "x-iinfo",
)


def looks_like_dynamic(body: str, content_type: str, *, status: int = 200) -> bool:
    if status not in {200, 206, 304}:
        return False
    ct = (content_type or "").lower()
    blob = body[:4000]
    low = blob.lower()
    if "404" in low and ("not found" in low or "找不到" in low or "does not exist" in low):
        return False
    if blob.lstrip().startswith("{") or "application/json" in ct:
        return any(
            k in blob
            for k in ('"email"', '"username"', '"userId"', '"phone"', '"balance"', '"user"')
        )
    if "text/html" in ct or "<html" in low or "<!doctype" in low:
        return any(
            k in low
            for k in (
                "logout", "sign out", "dashboard", "profile", "balance",
                "欢迎", "余额", "退出登录", "会员",
            )
        )
    return False


def cache_hints_from_headers(headers: dict[str, str]) -> list[str]:
    hits: list[str] = []
    low = {str(k).lower(): str(v) for k, v in headers.items()}
    for name in CACHE_HEADS:
        if name in low and low[name]:
            hits.append(f"{name}={low[name][:40]}")
    cc = low.get("cache-control", "")
    if "public" in cc.lower() or "max-age=" in cc.lower():
        hits.append(f"cache-control={cc[:60]}")
    return hits


def _load_kit():
    spec = importlib.util.spec_from_file_location("cache_poison_detector", KIT)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _deception(url: str, timeout: int) -> list[dict[str, Any]]:
    try:
        import requests

        requests.packages.urllib3.disable_warnings()  # type: ignore
    except ImportError:
        return []
    sess = requests.Session()
    sess.headers["User-Agent"] = "Mozilla/5.0 大爱仙尊-cache-deception"
    root = url if url.endswith("/") else url + "/"
    rows: list[dict[str, Any]] = []
    for path in DECEPTION_PATHS:
        for suf in DECEPTION_SUFFIX:
            target = urljoin(root, path.strip("/") + suf)
            try:
                r = sess.get(target, timeout=timeout, verify=False, allow_redirects=False)
            except Exception:
                continue
            body = r.text or ""
            hints = cache_hints_from_headers(dict(r.headers))
            dynamic = looks_like_dynamic(
                body, r.headers.get("Content-Type", ""), status=r.status_code
            )
            if not dynamic:
                continue
            level = "L2" if hints else "L1"
            rows.append({
                "level": level,
                "url": target,
                "status": r.status_code,
                "cache_hints": hints,
                "len": len(body),
            })
            if level == "L2":
                try:
                    r2 = sess.get(target, timeout=timeout, verify=False, allow_redirects=False)
                    h2 = cache_hints_from_headers(dict(r2.headers))
                    if any("hit" in x.lower() for x in h2):
                        rows[-1]["level"] = "L2"
                        rows[-1]["second_cache"] = h2
                except Exception:
                    pass
            if len(rows) >= 8:
                return rows
    return rows


def run(url: str, case: str = "", timeout: int = 10, deception_only: bool = False) -> dict:
    host = host_of(url)
    if host and not in_scope(host):
        raise SystemExit(f"[scope] {host} 不在授权范围")
    rows: list[dict[str, Any]] = []
    crit = 0
    hints: list[str] = []
    reachable = True
    if not deception_only:
        kit = _load_kit()
        if kit is None:
            reachable = False
        else:
            st, hints = kit.detect_cache(url, timeout)
            reachable = st is not None
            if st is not None:
                for name, payload, risk in kit.DEFAULT_HEADERS:
                    reflected, cached = kit.probe(url, name, payload, timeout)
                    if reflected or cached:
                        rows.append({
                            "header": name,
                            "payload": payload,
                            "risk": risk,
                            "reflected": bool(reflected),
                            "cached": bool(cached),
                        })
                    if reflected and cached:
                        crit += 1
    deception = _deception(url, timeout)
    if deception:
        reachable = True
    report = {
        "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "url": url,
        "reachable": reachable,
        "cache_hints": hints or [],
        "critical": crit,
        "hits": rows,
        "deception": deception,
        "playbook": "传承/浸窖.md",
        "skill": "网面窖",
        "next": "投毒 CRITICAL → 清缓存交差；欺骗 L2 → 无会话复拉同一 URL",
    }
    if case:
        write_probe_json(
            report, case=case, case_subdir="cache_poison", filename="CACHE_POISON.json"
        )
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="授权目标缓存投毒未键控头 + 路径欺骗")
    ap.add_argument("--url", "-u", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--deception-only", action="store_true")
    args = ap.parse_args()
    report = run(
        args.url,
        case=args.case,
        timeout=args.timeout,
        deception_only=args.deception_only,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report.get("reachable") else 2


if __name__ == "__main__":
    raise SystemExit(main())
