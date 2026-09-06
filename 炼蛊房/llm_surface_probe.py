#!/usr/bin/env python3
"""LLM / Agent 网关只读指纹（授权范围内）。

探测 /v1/models、Langflow auto_login、Flowise version/ping、LiteLLM 路径，
以及 /api/openapi.json 里的 CMS/RAG 知识库 path（不拉全量邮箱）。
不发送越狱/恶意 Skill，不默认对话注入。不带内部头打 Flowise apikey。
"""
from __future__ import annotations

import argparse
import json
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
ROOT = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-llm-surface"

PATHS = [
    ("openai-models", "GET", "/v1/models", ("\"data\"", "object")),
    ("openai-models", "GET", "/models", ("\"data\"",)),
    ("health", "GET", "/health", ("ok", "healthy", "status")),
    ("litellm-key", "GET", "/key/health", ("key", "status")),
    ("litellm-settings", "GET", "/settings", ("litellm", "master_key")),
    ("langflow-auto", "GET", "/api/v1/auto_login", ("access_token", "token", "auto_login")),
    ("langflow-ver", "GET", "/api/v1/version", ("langflow",)),
    ("flowise-ver", "GET", "/api/v1/version", ("flowise",)),
    ("flowise-ping", "GET", "/api/v1/ping", ("pong",)),
    ("openapi", "GET", "/openapi.json", ("openapi", "chat/completions")),
    ("openapi-api", "GET", "/api/openapi.json", ("openapi",)),
    ("cms-files", "GET", "/cms/files/?db_type=general&limit=1&offset=0", ()),
    ("cms-prompts", "GET", "/api/suggested_prompts", ()),
]

CMS_PATH_HINTS = (
    "cms/", "get_emails", "suggested_prompt", "ingest", "similarity_search",
)


def _json(r: requests.Response) -> Any:
    try:
        return r.json()
    except Exception:
        return None


def _cms_paths_from_spec(spec: Any) -> list[str]:
    if not isinstance(spec, dict):
        return []
    keys = list((spec.get("paths") or {}).keys())
    return [p for p in keys if any(h in p.lower() for h in CMS_PATH_HINTS)]


def _is_cms_files(data: Any) -> bool:
    if isinstance(data, dict):
        if any(k in data for k in ("s3_link", "file_id", "file_ids")):
            return True
        files = data.get("files") or data.get("data") or data.get("documents")
        if isinstance(files, list) and files:
            return True
        if isinstance(data.get("count"), int):
            return True
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return any(k in data[0] for k in ("s3_link", "file_id", "s3"))
    return False


def _is_cms_prompts(data: Any) -> bool:
    if isinstance(data, list) and data and all(isinstance(x, str) for x in data[:8]):
        return True
    if isinstance(data, dict):
        for k in ("prompts", "suggested_prompts", "data", "questions"):
            v = data.get(k)
            if isinstance(v, list) and v and isinstance(v[0], str):
                return True
    return False


def _tag_product(product: str, extra: str) -> str:
    if not extra:
        return product
    if not product:
        return extra
    if extra == product or extra in product.split("+"):
        return product
    return f"{product}+{extra}"


def _get(sess: requests.Session, url: str) -> requests.Response | None:
    try:
        return sess.get(url, timeout=10, verify=False, allow_redirects=True)
    except Exception:
        return None


def _hit_body(body: str, needles: tuple[str, ...]) -> bool:
    b = body.lower()
    return any(n.lower() in b for n in needles)


def run(base_url: str, case: str, out: Path | None) -> dict[str, Any]:
    host = host_of(base_url)
    if host and not in_scope(host):
        print(f"[!] 不在 scope：{host}", file=sys.stderr)
        sys.exit(2)
    base = base_url.rstrip("/") + "/"
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    findings: list[dict[str, Any]] = []

    home = _get(sess, base)
    product = ""
    if home is not None:
        blob = (home.text[:6000] + " " + str(home.headers)).lower()
        if "litellm" in blob:
            product = "litellm"
        elif "langflow" in blob:
            product = "langflow"
        elif "flowise" in blob:
            product = "flowise"
        elif "openai" in blob or "/v1/chat/completions" in blob:
            product = "openai-compat"

    for kind, _method, path, needles in PATHS:
        r = _get(sess, urljoin(base, path.lstrip("/")))
        if r is None:
            continue
        body = r.text[:4000]
        if r.status_code == 401 or r.status_code == 403:
            findings.append({
                "level": "L1",
                "path": path,
                "status": r.status_code,
                "signal": f"{kind}-auth-required",
            })
            continue
        if r.status_code != 200:
            continue
        parsed = _json(r)
        if kind == "cms-files" and not _is_cms_files(parsed):
            continue
        if kind == "cms-prompts" and not _is_cms_prompts(parsed):
            continue
        if kind == "health":
            ok_health = False
            if isinstance(parsed, dict):
                st = str(parsed.get("status") or parsed.get("health") or "").lower()
                ok_health = st in {"ok", "healthy", "up", "pass", "success"}
            if not ok_health and body.strip().lower() in {"ok", "healthy", "up", "pong"}:
                ok_health = True
            if not ok_health:
                continue
        elif kind == "openai-models":
            if not (isinstance(parsed, dict) and isinstance(parsed.get("data"), list)):
                continue
        elif kind not in ("cms-files", "cms-prompts"):
            if needles and not _hit_body(body, needles):
                continue
        models = []
        if kind == "openai-models" and isinstance(parsed, dict):
            for item in (parsed.get("data") or [])[:20]:
                if isinstance(item, dict) and item.get("id"):
                    models.append(str(item["id"])[:80])
        nxt = "未授权模型列表 → LiteLLM/Langflow/Flowise 专卡"
        cms_paths: list[str] = []
        if "langflow" in kind:
            nxt = "传承/流语·开天.md"
            product = _tag_product(product, "langflow")
        elif "flowise" in kind:
            nxt = "传承/流思·内额.md"
            product = _tag_product(product, "flowise")
        elif "litellm" in kind:
            nxt = f"python3 炼蛊房/litellm_badhost.py probe --base {base_url} --case <案卷>"
        elif "openapi" in kind:
            cms_paths = _cms_paths_from_spec(parsed)
            if cms_paths:
                product = _tag_product(product, "ai-cms")
                nxt = "传承/大灵.md §5（默认只读；勿拉全量邮箱）"
        elif kind.startswith("cms"):
            product = _tag_product(product, "ai-cms")
            nxt = "传承/大灵.md §5"
        rec: dict[str, Any] = {
            "level": "L2" if models or kind.startswith("cms") or (
                kind == "langflow-auto" and (
                    (isinstance(parsed, dict) and parsed.get("access_token"))
                    or "access_token" in body.lower()
                )
            ) else "L1",
            "path": path,
            "status": r.status_code,
            "signal": kind,
            "next": nxt,
        }
        if models:
            rec["models"] = models
        if cms_paths:
            rec["cms_paths"] = cms_paths
        findings.append(rec)
        extra = f" cms={cms_paths[:8]}" if cms_paths else ""
        print(f"  [{r.status_code}] {path} {kind}{extra}")

    if product == "litellm" and not any("litellm" in f.get("signal", "") for f in findings):
        findings.append({
            "level": "L1",
            "signal": "litellm-fingerprint",
            "next": f"python3 炼蛊房/litellm_badhost.py probe --base {base_url}",
        })

    report = {
        "target": base_url,
        "ts": datetime.now(UTC).isoformat(),
        "product": product,
        "findings": findings,
        "playbook": "传承/大灵.md",
        "next": "LiteLLM/Langflow/Flowise 走专卡；CMS path 走 大灵.md §5；禁止越狱包",
    }
    out_path = write_probe_json(
        report, case=case, out=out, case_subdir="llm", filename="surface.json",
    )
    print(json.dumps({"product": product, "findings": len(findings), "out": str(out_path)}, ensure_ascii=False))
    print(f"[+] wrote {out_path}", file=sys.stderr)
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="LLM/Agent 只读指纹探针")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    run(args.url, args.case, args.out)


if __name__ == "__main__":
    main()
