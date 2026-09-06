#!/usr/bin/env python3
"""芋道 / Qzino / 加密网关表面探针（授权范围内）。

认 /runtime/app-config.js、sk_encrypt.json、/app-api、Qzino /api.html。
命中密钥文件会尝试抽出 encrypt_key（L2 未授权读）。不默认打 initData 登录。
"""
from __future__ import annotations

import argparse
import base64
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

UA = "Mozilla/5.0 大爱仙尊-yudao-appapi"
SK_PATHS = (
    "/sys-upload/data/json/sk_encrypt.json",
    "/dflt/sys-upload/data/json/sk_encrypt.json",
    "/app-api/sys-upload/data/json/sk_encrypt.json",
)
FINGER_PATHS = (
    "/runtime/app-config.js",
    "/vue/config.js",
    "/app-api/",
    "/api.html",
    "/admin-api/",
)


def _get(sess: requests.Session, url: str) -> requests.Response | None:
    try:
        return sess.get(url, timeout=12, verify=False, allow_redirects=True)
    except Exception:
        return None


def _is_html(r: requests.Response, body: str) -> bool:
    ct = (r.headers.get("content-type") or "").lower()
    head = (body or "").lstrip()[:80].lower()
    return "text/html" in ct or head.startswith("<!doctype") or head.startswith("<html")


def _looks_json(body: str) -> bool:
    s = (body or "").lstrip()
    return s.startswith("{") or s.startswith("[")


def _extract_sk_key(text: str) -> str:
    raw = (text or "").strip()
    if not raw:
        return ""
    candidates = [raw]
    try:
        candidates.append(base64.b64decode(raw).decode("utf-8", errors="replace"))
    except Exception:
        pass
    for blob in candidates:
        try:
            obj = json.loads(blob)
        except Exception:
            continue
        enc = obj.get("encrypt_key") if isinstance(obj, dict) else None
        if isinstance(enc, dict):
            val = enc.get("configValue") or enc.get("value") or ""
            if val:
                return str(val)
        if isinstance(obj, dict) and obj.get("encodeKey"):
            return str(obj["encodeKey"])
    return ""


def run(base_url: str, case: str, out: Path | None) -> dict[str, Any]:
    host = host_of(base_url)
    if host and not in_scope(host):
        print(f"[!] 不在 scope：{host}", file=sys.stderr)
        sys.exit(2)
    base = base_url.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA

    family = "unknown"
    hits: list[dict[str, Any]] = []
    keys: list[str] = []
    app_config: dict[str, Any] = {}

    home = _get(sess, base + "/")
    home_text = home.text if home is not None else ""
    if home is not None:
        hits.append({"path": "/", "status": home.status_code, "len": len(home.content or b"")})
        if re.search(r"<title>\s*Qzino\s*</title>", home_text, re.I):
            family = "qzino-tma"
        if "系统选择" in home_text and "tgcloud_pc" in home_text:
            family = "tg-cloud-dual-app"

    for path in FINGER_PATHS:
        r = _get(sess, urljoin(base + "/", path.lstrip("/")))
        if r is None:
            continue
        body = r.text or ""
        rec: dict[str, Any] = {
            "path": path,
            "status": r.status_code,
            "len": len(r.content or b""),
            "ctype": (r.headers.get("content-type") or "")[:80],
        }
        html = _is_html(r, body)
        if path.endswith("app-config.js") and r.status_code == 200 and (not html) and "PLATFORM_ID" in body:
            family = "yudao-tma"
            m_pid = re.search(r"PLATFORM_ID\s*[:=]\s*(\d+)", body)
            apis = re.findall(r"https?://[A-Za-z0-9._:-]+", body)
            app_config = {
                "platform_id": int(m_pid.group(1)) if m_pid else None,
                "api_list": sorted(set(apis))[:12],
            }
            rec["hint"] = "PLATFORM_ID"
        if path == "/vue/config.js" and r.status_code == 200 and not html:
            family = family if family != "unknown" else "qzino-tma"
            rec["hint"] = "vue-config"
        if path == "/api.html" and r.status_code in (200, 405, 400):
            rec["hint"] = "api.html"
            # SPA 回退 HTML 200 不算 Qzino
            if family == "unknown" and (not html) and r.status_code in (400, 405):
                family = "qzino-tma"
        if path == "/app-api/" and r.status_code in (200, 401, 403, 404, 405):
            rec["hint"] = "app-api-prefix"
            if family == "unknown" and (not html) and (_looks_json(body) or r.status_code in (401, 403)):
                family = "yudao-web"
        hits.append(rec)

    for path in SK_PATHS:
        r = _get(sess, urljoin(base + "/", path.lstrip("/")))
        if r is None or r.status_code != 200:
            hits.append({"path": path, "status": getattr(r, "status_code", None)})
            continue
        key = _extract_sk_key(r.text or "")
        rec = {"path": path, "status": 200, "len": len(r.content or b""), "key_hit": bool(key)}
        if key:
            keys.append(key)
            family = "yudao-web-encrypt" if family in ("unknown", "yudao-web") else family
            rec["key_preview"] = key[:4] + "…" + key[-2:] if len(key) > 8 else "(short)"
        hits.append(rec)

    next_steps = [
        "认族后打开 传承/商心慈·白标.md",
    ]
    if family.startswith("yudao-tma"):
        next_steps.append("读 芋府·微域.md §2 + extended-pack yudao-tma-pentest")
    if "encrypt" in family or keys:
        next_steps.append("用 sk_encrypt 密钥解 /app-api/encrypt 响应；明文 /app-api 探活")
    if family == "qzino-tma":
        next_steps.append("读 telegram-gambling-tma-pentest；抽 /vue/index-*.js 的 AES+salt")
    if family == "tg-cloud-dual-app":
        next_steps.append("读 extended-pack tg-cloud-control-pentest（OSS STS / 客服提权）")

    report: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "base": base,
        "family": family,
        "hits": hits,
        "app_config": app_config,
        "sk_keys": keys,
        "playbook": "传承/商心慈·白标.md",
        "skill": "杀招/商心慈·芋府",
        "next": next_steps,
    }
    out_path = write_probe_json(
        report, case=case, out=out, case_subdir="yudao_appapi", filename="probe.json"
    )
    print(
        json.dumps(
            {
                "family": family,
                "sk_keys": len(keys),
                "platform_id": app_config.get("platform_id"),
                "out": str(out_path),
            },
            ensure_ascii=False,
        )
    )
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="芋道/Qzino/加密网关指纹探针")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    run(args.url, args.case, args.out)


if __name__ == "__main__":
    main()
