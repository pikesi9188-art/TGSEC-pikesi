#!/usr/bin/env python3
"""大爱仙尊通用竞态探针：同一请求并发 N 次，对照单发。

success>1 只是候选，要对照余额/库存/券次数。耗余额下单先问。
博彩充提扫面仍走 logic_vuln_probe；发卡共享货走 acg-faka。

示例:
  python3 炼蛊房/race_probe.py --url https://授权/api/coupon/claim \\
    --body '{"code":"A"}' --n 20 --header 'Authorization: Bearer <票>' --case <案>
  python3 炼蛊房/race_probe.py --self-test
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import threading
from typing import Any

OPS = __import__("pathlib").Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from probe_http import post  # noqa: E402
from scope_lib import require_in_scope, write_probe_json  # noqa: E402

DEFAULT_OK = re.compile(
    r'"code"\s*:\s*0\b|"success"\s*:\s*true|"status"\s*:\s*"ok"',
    re.I,
)


def parse_body(raw: str) -> bytes:
    if not raw:
        return b"{}"
    raw = raw.strip()
    try:
        json.loads(raw)
    except json.JSONDecodeError as e:
        raise SystemExit(f"--body 要 JSON：{e}") from e
    return raw.encode()


def is_success(status: int, text: str, rx: re.Pattern[str]) -> bool:
    if status not in (200, 201, 202, 204):
        return False
    if not text:
        return status in (200, 201, 202, 204)
    if rx.search(text):
        return True
    if re.search(r'"code"\s*:\s*([1-9]\d{2,}|-\d+)', text):
        return False
    return status in (200, 201, 204) and "error" not in text.lower()


def grade(success_n: int, sequential_ok: bool, n: int) -> dict[str, Any]:
    return {
        "l1": success_n >= 1 or sequential_ok,
        "l2": success_n >= 2,
        "note": (
            f"并发成功 {success_n}/{n}。l2 只是候选，必须对照业务次数/余额。"
            if success_n >= 2
            else "并发没有多笔成功。换窗口或 HTTP/2 单包，不要结案。"
        ),
    }


def probe(
    url: str,
    *,
    body: bytes,
    n: int,
    extra: dict[str, str],
    ok_rx: re.Pattern[str],
) -> dict[str, Any]:
    require_in_scope(url)
    headers = {"Content-Type": "application/json", **extra}
    seq = post(url, headers=headers, data=body, timeout=15)
    seq_ok = is_success(seq.status, seq.text or "", ok_rx)
    barrier = threading.Barrier(n)
    rows: list[dict[str, Any]] = []
    lock = threading.Lock()

    def one() -> None:
        try:
            barrier.wait(timeout=8)
        except threading.BrokenBarrierError:
            return
        r = post(url, headers=headers, data=body, timeout=15)
        rec = {
            "status": r.status,
            "len": len(r.text or ""),
            "ok": is_success(r.status, r.text or "", ok_rx),
            "error": r.error or "",
        }
        with lock:
            rows.append(rec)

    threads = [threading.Thread(target=one, daemon=True) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    success_n = sum(1 for x in rows if x["ok"])
    rec = {
        "url": url,
        "n": n,
        "sequential": {"status": seq.status, "len": len(seq.text or ""), "ok": seq_ok, "error": seq.error or ""},
        "success_n": success_n,
        "rows": rows[:40],
        "playbook": "传承/时道抢先.md",
        **grade(success_n, seq_ok, n),
    }
    return rec


def run_self_test() -> list[str]:
    fails: list[str] = []
    if not is_success(200, '{"code":0,"msg":"ok"}', DEFAULT_OK):
        fails.append("ok")
    if is_success(200, '{"code":500,"msg":"fail"}', DEFAULT_OK):
        fails.append("err-code")
    if is_success(404, '{"code":0}', DEFAULT_OK):
        fails.append("404")
    g = grade(3, True, 20)
    if not g["l2"]:
        fails.append("l2")
    if grade(1, True, 20)["l2"]:
        fails.append("single")
    try:
        parse_body("{")
        fails.append("bad-json")
    except SystemExit:
        pass
    if parse_body('{"a":1}') != b'{"a":1}':
        fails.append("body")
    return fails


def main() -> int:
    ap = argparse.ArgumentParser(description="大爱仙尊通用竞态")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--url")
    ap.add_argument("--body", default="{}")
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--success-re", default="")
    ap.add_argument("--case", default="")
    args = ap.parse_args()
    if args.self_test:
        fails = run_self_test()
        if fails:
            for f in fails:
                print(f"FAIL {f}")
            return 1
        print("self-test ok  race")
        return 0
    if not args.url:
        ap.error("需要 --url 或 --self-test")
    extra: dict[str, str] = {}
    for raw in args.header:
        if ":" not in raw:
            raise SystemExit(f"--header 要 Name: value：{raw}")
        k, v = raw.split(":", 1)
        extra[k.strip()] = v.strip()
    rx = re.compile(args.success_re, re.I) if args.success_re else DEFAULT_OK
    n = max(2, min(args.n, 80))
    data = probe(args.url, body=parse_body(args.body), n=n, extra=extra, ok_rx=rx)
    path = write_probe_json(data, case=args.case, case_subdir="race", filename="race.json")
    print(json.dumps({"l1": data["l1"], "l2": data["l2"], "success_n": data["success_n"], "note": data["note"], "out": str(path)}, ensure_ascii=False))
    return 0 if data.get("l2") or data.get("l1") else 1


if __name__ == "__main__":
    raise SystemExit(main())
