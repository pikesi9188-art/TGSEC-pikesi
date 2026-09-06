#!/usr/bin/env python3
"""大爱仙尊 GraphQL 越权探针：introspection / 未授权读 / 换 id / batch。

jwt_gql_probe 只摸面。本探针打已确认的 /graphql。
GitLab /api/graphql 走 gitlab-graphql-unauth。不 dump 全 schema。

示例:
  python3 炼蛊房/gql_authz_probe.py introspect --url https://授权/graphql --case <案>
  python3 炼蛊房/gql_authz_probe.py query --url https://授权/graphql \\
    --query '{ user(id:1){id email} }' --case <案>
  python3 炼蛊房/gql_authz_probe.py swap --url https://授权/graphql \\
    --query '{ user(id:1){id email} }' --ids 1,2 --header 'Authorization: Bearer <票>' --case <案>
  python3 炼蛊房/gql_authz_probe.py batch --url https://授权/graphql \\
    --query '{ __typename }' --case <案>
  python3 炼蛊房/gql_authz_probe.py --self-test
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

OPS = __import__("pathlib").Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from probe_http import get, post, session  # noqa: E402
from scope_lib import require_in_scope, write_probe_json  # noqa: E402

INTROSPECT = "{__schema{queryType{name fields{name}} mutationType{name fields{name}}}}"
INTROSPECT_TYPE = '{__type(name:"Query"){fields{name}}}'
INTROSPECT_NL = "{\n__schema\n{queryType{name}}}\n"
GQL_HINT = re.compile(r"graphql|__typename|must provide query|syntax error|introspection", re.I)
ID_RX = re.compile(r"(\bid\s*:\s*)(['\"]?)(\d+)\2")


def swap_id(query: str, new_id: str) -> str:
    if not ID_RX.search(query):
        raise ValueError("query 里没有 id:数字")
    return ID_RX.sub(lambda m: f"{m.group(1)}{m.group(2)}{new_id}{m.group(2)}", query, count=1)


def alias_wrap(query: str, n: int = 4) -> str:
    inner = query.strip()
    if inner.startswith("{") and inner.endswith("}"):
        inner = inner[1:-1].strip()
    parts = [f"a{i}:{inner}" for i in range(n)]
    return "{" + " ".join(parts) + "}"


def gql_data(text: str) -> Any:
    try:
        return json.loads(text or "")
    except json.JSONDecodeError:
        return None


def has_data(blob: Any) -> bool:
    if isinstance(blob, list):
        return any(has_data(x) for x in blob)
    if not isinstance(blob, dict):
        return False
    data = blob.get("data")
    if data in (None, {}, []):
        return False
    return True


def field_names(blob: Any) -> list[str]:
    names: list[str] = []
    if not isinstance(blob, dict):
        return names
    schema = ((blob.get("data") or {}) if isinstance(blob.get("data"), dict) else {}).get("__schema") or {}
    for side in ("queryType", "mutationType"):
        fields = ((schema.get(side) or {}) or {}).get("fields") or []
        for f in fields:
            if isinstance(f, dict) and f.get("name"):
                names.append(str(f["name"]))
    typ = ((blob.get("data") or {}) if isinstance(blob.get("data"), dict) else {}).get("__type") or {}
    for f in typ.get("fields") or []:
        if isinstance(f, dict) and f.get("name"):
            names.append(str(f["name"]))
    return names[:80]


def _fp(r: Any) -> dict[str, Any]:
    text = r.text or ""
    blob = gql_data(text)
    return {
        "status": r.status,
        "len": len(text),
        "data": has_data(blob),
        "gqlish": bool(GQL_HINT.search(text)) or blob is not None,
        "fields": field_names(blob) if blob is not None else [],
        "error": r.error or "",
    }


def _headers(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in items:
        if ":" not in raw:
            raise SystemExit(f"--header 要 Name: value：{raw}")
        k, v = raw.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def _post_query(url: str, query: str, extra: dict[str, str], *, sess, batch: bool = False) -> Any:
    headers = {"Content-Type": "application/json", **extra}
    body: Any = [{"query": query}, {"query": query}] if batch else {"query": query}
    return post(url, sess=sess, headers=headers, json=body, timeout=15)


def probe_introspect(url: str, extra: dict[str, str]) -> dict[str, Any]:
    require_in_scope(url)
    s = session()
    hits = []
    for name, q, use_get in (
        ("schema", INTROSPECT, False),
        ("type-query", INTROSPECT_TYPE, False),
        ("schema-nl", INTROSPECT_NL, False),
        ("get-query", INTROSPECT, True),
    ):
        if use_get:
            u = urlparse(url)
            qstr = urlencode({"query": q})
            sep = "&" if u.query else ""
            target = urlunparse(u._replace(query=(u.query + sep + qstr) if u.query else qstr))
            r = get(target, sess=s, headers=extra or None, timeout=15)
        else:
            r = _post_query(url, q, extra, sess=s)
        row = {"kind": name, **_fp(r)}
        hits.append(row)
    live = [h for h in hits if h["data"] or h["gqlish"]]
    leaked = [h for h in hits if h["fields"] or h["data"]]
    return {
        "url": url,
        "hits": hits,
        "l1": bool(live),
        "l2": bool(leaked),
        "playbook": "传承/星念.md",
    }


def probe_query(url: str, query: str, extra: dict[str, str]) -> dict[str, Any]:
    require_in_scope(url)
    s = session()
    unauth = _fp(_post_query(url, query, {}, sess=s))
    auth = _fp(_post_query(url, query, extra, sess=s)) if extra else None
    rec = {
        "url": url,
        "query": query[:240],
        "unauth": unauth,
        "auth": auth,
        "l1": bool(unauth["gqlish"] or (auth and auth["gqlish"])),
        "l2": bool(unauth["data"]),
        "playbook": "传承/星念.md",
        "note": "unauth.data=true 才是未授权读。有票才有 data 不算越权。",
    }
    return rec


def probe_swap(url: str, query: str, ids: list[str], extra: dict[str, str]) -> dict[str, Any]:
    require_in_scope(url)
    s = session()
    rows = []
    for i in ids:
        q = swap_id(query, i)
        rows.append({"id": i, "query": q[:200], **_fp(_post_query(url, q, extra, sess=s))})
    lens = {x["len"] for x in rows}
    datas = [x["data"] for x in rows]
    differ = len(rows) >= 2 and (len(lens) > 1 or (all(datas) and lens))
    return {
        "url": url,
        "rows": rows,
        "differ": differ,
        "l2": bool(differ and all(datas)),
        "note": "differ 且两边都有 data：换 id 读到不同对象。还要看是不是他人数据。",
        "playbook": "传承/星念.md",
    }


def probe_batch(url: str, query: str, extra: dict[str, str]) -> dict[str, Any]:
    require_in_scope(url)
    s = session()
    one = _fp(_post_query(url, query, extra, sess=s))
    batched = _fp(_post_query(url, query, extra, sess=s, batch=True))
    aliased = _fp(_post_query(url, alias_wrap(query), extra, sess=s))
    return {
        "url": url,
        "one": one,
        "batch": batched,
        "alias": aliased,
        "l2": bool(batched["data"] or aliased["data"]),
        "l1": bool(one["gqlish"] or batched["gqlish"]),
        "playbook": "传承/星念.md",
        "note": "数组 batch 或别名放大成立后，限流/鉴权按「一次请求」算就可能被绕。",
    }


def run_self_test() -> list[str]:
    fails: list[str] = []
    q = "{ user(id:1){id email} }"
    if "id:2" not in swap_id(q, "2") or "id:1" in swap_id(q, "2"):
        fails.append("swap")
    if 'id:"9"' not in swap_id('{user(id:"1"){id}}', "9"):
        fails.append("swap-quote")
    aw = alias_wrap(q, 3)
    if aw.count("a0:") != 1 or aw.count("user(id:1)") != 3:
        fails.append("alias")
    if not has_data({"data": {"user": {"id": 1}}}):
        fails.append("data")
    if has_data({"data": None, "errors": [{"message": "x"}]}):
        fails.append("errors")
    if has_data([{"data": {}}, {"data": None}]):
        fails.append("empty-batch")
    if not has_data([{"data": {"x": 1}}]):
        fails.append("batch-data")
    names = field_names({"data": {"__schema": {"queryType": {"fields": [{"name": "user"}]}}}})
    if "user" not in names:
        fails.append("fields")
    return fails


def main() -> int:
    ap = argparse.ArgumentParser(description="大爱仙尊 GraphQL 越权")
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    def common(p: argparse.ArgumentParser, *, need_query: bool) -> None:
        p.add_argument("--url", required=True)
        if need_query:
            p.add_argument("--query", required=True)
        p.add_argument("--header", action="append", default=[])
        p.add_argument("--case", default="")

    common(sub.add_parser("introspect"), need_query=False)
    common(sub.add_parser("query"), need_query=True)
    p_s = sub.add_parser("swap")
    common(p_s, need_query=True)
    p_s.add_argument("--ids", required=True)
    common(sub.add_parser("batch"), need_query=True)

    args = ap.parse_args()
    if args.self_test:
        fails = run_self_test()
        if fails:
            for f in fails:
                print(f"FAIL {f}")
            return 1
        print("self-test ok  gql_authz")
        return 0

    extra = _headers(getattr(args, "header", []) or [])
    if args.cmd == "introspect":
        data = probe_introspect(args.url, extra)
        name = "introspect.json"
    elif args.cmd == "query":
        data = probe_query(args.url, args.query, extra)
        name = "query.json"
    elif args.cmd == "swap":
        ids = [x.strip() for x in args.ids.split(",") if x.strip()]
        if len(ids) < 2:
            raise SystemExit("--ids 至少两个")
        data = probe_swap(args.url, args.query, ids, extra)
        name = "swap.json"
    elif args.cmd == "batch":
        data = probe_batch(args.url, args.query, extra)
        name = "batch.json"
    else:
        ap.error("需要 introspect / query / swap / batch / --self-test")
        return 2
    path = write_probe_json(data, case=args.case, case_subdir="gql_authz", filename=name)
    slim = {k: data[k] for k in data if k not in ("playbook",)}
    print(json.dumps({**slim, "out": str(path)}, ensure_ascii=False)[:2000])
    return 0 if data.get("l2") or data.get("l1") else 1


if __name__ == "__main__":
    raise SystemExit(main())
