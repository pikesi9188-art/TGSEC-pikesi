#!/usr/bin/env python3
"""大爱仙尊 IDOR 换号探针：同一接口换对象 ID，比状态码和长度。

水平越权最少两个 ID。有第二套 Cookie/Authorization 再交叉。
EQ 改一个 id 阴性不算隔离（Shop 卡已钉 GT/IN）。本探针先做可验证差异。

示例:
  python3 炼蛊房/idor_swap_probe.py --url 'https://授权/api/order?id=1' \\
    --ids 1,2 --header 'Authorization: Bearer <票A>' --case <案>
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

from probe_http import get, session  # noqa: E402
from scope_lib import require_in_scope, write_probe_json  # noqa: E402


def _swap(url: str, name: str, value: str) -> str:
    u = urlparse(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    if name in q:
        q[name] = value
        return urlunparse(u._replace(query=urlencode(q)))
    if re.search(r"/\d+/?$", u.path or ""):
        path = re.sub(r"/\d+(/?)$", f"/{value}\\1", u.path)
        return urlunparse(u._replace(path=path))
    q[name] = value
    return urlunparse(u._replace(query=urlencode(q)))


def probe(url: str, ids: list[str], *, param: str, headers: dict[str, str]) -> dict[str, Any]:
    require_in_scope(url)
    s = session()
    rows = []
    for i in ids:
        target = _swap(url, param, i)
        r = get(target, sess=s, headers=headers or None, timeout=12)
        rows.append(
            {
                "id": i,
                "url": target,
                "status": r.status,
                "len": len(r.text or ""),
                "error": r.error or "",
            }
        )
    lens = {x["len"] for x in rows}
    stats = {x["status"] for x in rows}
    differ = len(rows) >= 2 and (len(lens) > 1 or len(stats) > 1)
    return {
        "url": url,
        "param": param,
        "rows": rows,
        "differ": differ,
        "note": "differ=true 只说明响应不同，还要读 body 确认是他人对象",
        "playbook": "传承/万我大手印.md",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="大爱仙尊 IDOR 换号")
    ap.add_argument("--url", required=True)
    ap.add_argument("--ids", required=True, help="逗号分隔，至少两个")
    ap.add_argument("--param", default="id")
    ap.add_argument("--header", action="append", default=[], help="Name: value，可重复")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    ids = [x.strip() for x in args.ids.split(",") if x.strip()]
    if len(ids) < 2:
        raise SystemExit("[err] --ids 至少两个")
    headers: dict[str, str] = {}
    for h in args.header:
        if ":" not in h:
            raise SystemExit(f"[err] 坏 header: {h}")
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    data = probe(args.url, ids, param=args.param, headers=headers)
    dest = None
    if args.out:
        from pathlib import Path

        dest = Path(args.out)
    path = write_probe_json(data, case=args.case, out=dest, case_subdir="idor", filename="idor_swap.json")
    print(json.dumps({"differ": data["differ"], "rows": data["rows"], "out": str(path)}, ensure_ascii=False))
    return 0 if data["differ"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
