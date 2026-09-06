#!/usr/bin/env python3
"""大爱仙尊批量 HTTP 对照：同一轮比 status / 长度 / hash。

DIFF 是 L1，不是注入结案。要 L2 必须交接 sqli / 核心 Web / 越权专卡。
目标必须在 scope。same-body 只说明这两发对运行时无差。

  python3 炼蛊房/http_probe_batch.py --base https://授权站 --case <案卷> \\
    --variant '{"label":"clean","path":"/api","params":{"q":"ok"}}' \\
    --variant '{"label":"probe","path":"/api","params":{"q":"1 OR 1=1"}}'
"""
from __future__ import annotations

import argparse
import hashlib
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
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import in_scope, require_in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-http-batch"


def _one(sess: requests.Session, base: str, spec: dict[str, Any], timeout: int) -> dict[str, Any]:
    path = spec.get("path") or "/"
    url = spec.get("url") or urljoin(base.rstrip("/") + "/", str(path).lstrip("/"))
    method = str(spec.get("method") or "GET").upper()
    headers = dict(spec.get("headers") or {})
    params = spec.get("params")
    cookies = spec.get("cookies")
    json_body = spec.get("json")
    data = spec.get("data") or spec.get("body")
    raw_url = spec.get("raw_url")
    if raw_url:
        url = raw_url
    require_in_scope(url)
    try:
        r = sess.request(
            method,
            url,
            params=params,
            headers=headers,
            cookies=cookies,
            json=json_body,
            data=None if json_body is not None else data,
            timeout=timeout,
            verify=False,
            allow_redirects=bool(spec.get("follow", False)),
        )
    except requests.RequestException as e:
        return {"ok": False, "url": url, "method": method, "error": str(e)[:200]}
    final = str(r.url)
    if final and not in_scope(final):
        return {"ok": False, "url": url, "method": method, "error": f"最终 URL 不在 scope: {final[:180]}"}
    body = r.content or b""
    digest = hashlib.sha256(body).hexdigest()[:16]
    text = body.decode(r.encoding or "utf-8", errors="replace") if body else ""
    return {
        "ok": True,
        "method": method,
        "url": str(r.url),
        "status": r.status_code,
        "len": len(body),
        "hash": digest,
        "headers": {k: v for k, v in list(r.headers.items())[:20]},
        "preview": text[:400],
        "label": spec.get("label") or f"{method} {path}",
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    require_in_scope(args.base)
    specs: list[dict[str, Any]] = []
    for raw in args.variant or []:
        try:
            specs.append(json.loads(raw))
        except json.JSONDecodeError as e:
            print(f"[!] --variant JSON 坏了: {e}", file=sys.stderr)
            sys.exit(2)
    if args.variants_file:
        try:
            blob = json.loads(Path(args.variants_file).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"[!] variants-file: {e}", file=sys.stderr)
            sys.exit(2)
        if isinstance(blob, list):
            specs.extend(blob)
        elif isinstance(blob, dict) and "variants" in blob:
            specs.extend(blob["variants"])
        else:
            print("[!] variants-file 要是 JSON 数组或 {variants:[...]}", file=sys.stderr)
            sys.exit(2)
    if not specs:
        print("[!] 至少一条 --variant 或 --variants-file", file=sys.stderr)
        sys.exit(2)
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    rows = [_one(sess, args.base, spec, args.timeout) for spec in specs]
    buckets: dict[str, list[int]] = {}
    for i, row in enumerate(rows):
        if row.get("ok"):
            buckets.setdefault(row["hash"], []).append(i)
    same = [idxs for idxs in buckets.values() if len(idxs) > 1]
    diffs = [i for i, row in enumerate(rows) if row.get("ok") and len(buckets.get(row["hash"], [])) == 1]
    for i, row in enumerate(rows):
        mark = "DIFF" if i in diffs else ("SAME" if row.get("ok") else "ERR")
        if row.get("ok"):
            print(f"  [{mark}] {row['status']} {row['len']:6} {row['hash']}  {row['label']}")
        else:
            print(f"  [ERR] {row.get('error')}  {row.get('label', '')}")
    level = "L1" if diffs else "L0"
    payload = {
        "ts": datetime.now(UTC).isoformat(),
        "base": args.base,
        "level": level,
        "note": "DIFF=L1 对照信号；L2 须专卡复现。same-body 不是阴性结案。",
        "count": len(rows),
        "same_body_groups": same,
        "unique_idx": diffs,
        "rows": rows,
    }
    if args.case:
        write_probe_json(payload, case=args.case, case_subdir="http_batch", filename="batch.json")
    if args.out:
        write_probe_json(payload, out=Path(args.out))
    return payload


def main() -> int:
    ap = argparse.ArgumentParser(description="批量 HTTP 变体对照")
    ap.add_argument("--base", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out")
    ap.add_argument("--variant", action="append", help="JSON 对象，可重复")
    ap.add_argument("--variants-file")
    ap.add_argument("--timeout", type=int, default=12)
    args = ap.parse_args()
    data = run(args)
    print(json.dumps({"level": data["level"], "count": data["count"], "unique": len(data["unique_idx"]), "same_groups": data["same_body_groups"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
