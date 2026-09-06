#!/usr/bin/env python3
"""Ollama 未授权 API 表面（授权范围内）。

默认只 GET version/tags/ps。--deep 才用假模型探 /api/generate 鉴权。
禁止 pull/push/delete 与真对话。
"""
from __future__ import annotations

import argparse
import json
import re
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

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-ollama"
PREFIXES = ("/", "/ollama/", "/api/")
VERSION_PATHS = ("/api/version", "/ollama/api/version")
TAGS_PATHS = ("/api/tags", "/ollama/api/tags")
PS_PATHS = ("/api/ps", "/ollama/api/ps")


def _get(sess: requests.Session, url: str, timeout: float = 12) -> dict[str, Any]:
    try:
        r = sess.get(url, timeout=timeout, verify=False, allow_redirects=True)
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
        "json": data if isinstance(data, dict) else None,
        "title_ollama": bool(re.search(r"<title>[^<]*Ollama", text, re.I)),
        "snip": re.sub(r"\s+", " ", text)[:160],
    }


def _models(data: Any) -> list[str]:
    if not isinstance(data, dict):
        return []
    models = data.get("models") or []
    names: list[str] = []
    if isinstance(models, list):
        for m in models[:20]:
            if isinstance(m, dict) and m.get("name"):
                names.append(str(m["name"])[:80])
            elif isinstance(m, str):
                names.append(m[:80])
    return names


def _bases(raw: str) -> list[str]:
    s = (raw or "").strip()
    if "://" not in s:
        s = "https://" + s
    u = urlparse(s)
    host = u.hostname or ""
    scheme = u.scheme or "https"
    out = [s.rstrip("/")]
    if host and u.port != 11434:
        out.append(f"{scheme}://{host}:11434")
    # 去重保序
    seen: set[str] = set()
    uniq: list[str] = []
    for b in out:
        if b not in seen:
            seen.add(b)
            uniq.append(b)
    return uniq


def _generate_surface(sess: requests.Session, base: str) -> dict[str, Any]:
    url = urljoin(base + "/", "api/generate")
    try:
        r = sess.post(
            url,
            json={"model": "daaixianzun-noexist", "prompt": "", "stream": False},
            timeout=8,
            verify=False,
        )
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    text = (r.text or "")[:200]
    return {
        "url": url,
        "status": r.status_code,
        "auth_wall": r.status_code in {401, 403},
        "unauth_write": r.status_code in {400, 404, 200}
        and any(k in text.lower() for k in ("model", "ollama", "not found", "error")),
        "snip": re.sub(r"\s+", " ", text)[:160],
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    findings: list[dict[str, Any]] = []
    version = ""
    models: list[str] = []
    used_base = args.base.rstrip("/")

    for base in _bases(args.base):

        used_base = base
        tmo = 4.0 if ":11434" in base else 12.0
        for p in VERSION_PATHS:
            row = _get(sess, urljoin(base + "/", p.lstrip("/")), timeout=tmo)
            js = row.get("json") or {}
            if row.get("status") == 200 and isinstance(js, dict) and js.get("version"):
                version = str(js.get("version"))[:40]
                row.update({"level": "L1", "signal": "api-version", "path": p, "version": version, "base": base})
                findings.append(row)
                print(f"  L1 version {base}{p} {version}")
                break

        for p in TAGS_PATHS:
            row = _get(sess, urljoin(base + "/", p.lstrip("/")), timeout=tmo)
            names = _models(row.get("json"))
            if row.get("status") == 200 and names:
                models = names
                row.update({"level": "L2", "signal": "api-tags", "path": p, "models": names, "base": base})
                findings.append(row)
                print(f"  L2 tags {base}{p} models={len(names)}")
                break
            if row.get("status") == 200 and isinstance(row.get("json"), dict) and "models" in (row.get("json") or {}):
                row.update({"level": "L1", "signal": "api-tags-empty", "path": p, "base": base})
                findings.append(row)
                print(f"  L1 tags-empty {base}{p}")
                break

        for p in PS_PATHS:
            row = _get(sess, urljoin(base + "/", p.lstrip("/")), timeout=tmo)
            if row.get("status") == 200 and isinstance(row.get("json"), dict):
                row.update({"level": "L1", "signal": "api-ps", "path": p, "base": base})
                findings.append(row)
                break

        if findings:
            if args.deep:
                gen = _generate_surface(sess, base)
                if gen.get("unauth_write"):
                    gen.update({"level": "L2", "signal": "generate-unauth"})
                    findings.append(gen)
                    print(f"  L2 generate-unauth {base} status={gen.get('status')}")
                elif gen.get("auth_wall"):
                    gen.update({"level": "L1", "signal": "generate-auth"})
                    findings.append(gen)
            break

        if not findings:
            for p in PREFIXES:
                row = _get(sess, urljoin(base + "/", p.lstrip("/")), timeout=tmo)
                if row.get("title_ollama"):
                    row.update({"level": "L1", "signal": "title", "path": p, "base": base})
                    findings.append(row)
                    print(f"  L1 title {base}{p}")
                    break
        if findings:
            break

    level = "none"
    if any(f.get("level") == "L2" for f in findings):
        level = "L2"
    elif findings:
        level = "L1"
    report = {
        "target": used_base,
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "version": version,
        "models": models,
        "findings": findings,
        "playbook": "传承/羊驼·无门.md",
        "next": "默认 GET：L2=tags 列模型。--deep 才探 generate。禁止 pull/push/真对话。",
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="ollama", filename="surface.json",
    )
    print(json.dumps({"level": level, "version": version, "models": len(models), "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Ollama 未授权表面（默认 GET；--deep 探 generate）")
    ap.add_argument("--base", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--deep", action="store_true", help="假模型探 /api/generate 鉴权")
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
