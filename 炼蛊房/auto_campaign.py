#!/usr/bin/env python3
"""
auto_campaign.py — 智能作战路由器（授权范围内）

核心思路：
  不需要手动决定用哪个工具。给一个目标域名/URL，自动：
    1. 指纹识别（技术栈、WAF/CDN、功能模块、接入方式）
    2. 按指纹匹配工具清单
    3. 输出优先级排序的完整作战计划（带可直接执行的命令）
    4. 可选：自动执行每一步并汇总结果

用法：
  # 仅输出作战计划（不执行）
  python3 炼蛊房/auto_campaign.py plan -d target.com

  # 自动执行全链（轻量，只读操作）
  python3 炼蛊房/auto_campaign.py run -d target.com

  # 只执行指定阶段（0=侦察 1=绕过 2=漏洞 3=接管 4=社工）
  python3 炼蛊房/auto_campaign.py run -d target.com --phases 0,1

  # 指定 admin URL（已知后台地址）
  python3 炼蛊房/auto_campaign.py plan -d target.com --admin https://admin.target.com/login

  # 完整案卷目录输出（自动创建 exports/ 下的案卷）
  python3 炼蛊房/auto_campaign.py run -d target.com --case wldzylbot_20260810

依赖: pip install requests
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[-] pip install requests")
    sys.exit(1)

ROOT = (Path(__file__).resolve().parent.parent if (Path(__file__).resolve().parent.parent / "杀招").is_dir() else Path(__file__).resolve().parent.parent.parent)   # 大爱仙尊根目录
TOOLS = ROOT / "炼蛊房"
EXPORTS = ROOT / "案卷"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from jwt_mask import extract_masked_tokens  # noqa: E402
from scope_lib import host_of, in_scope  # noqa: E402
from browser_loot_triage import case_has_loot  # noqa: E402
try:
    from se_inject import workspace_injected  # noqa: E402
except ImportError:
    def workspace_injected(_root):  # type: ignore[misc]
        return True

# ══════════════════════════════════════════════════════════════════
#  指纹库：检测条件 → 激活工具
# ══════════════════════════════════════════════════════════════════

# 每条规则结构：
# {
#   "id": str,                          唯一 ID
#   "name": str,                        显示名
#   "phase": int,                       0=侦察 1=绕过 2=漏洞 3=接管 4=社工
#   "priority": int,                    1=最高 5=最低
#   "trigger": callable(fingerprints),  返回 True 则激活
#   "tool": str,                        工具文件名（炼蛊房/）
#   "cmd_template": str,               命令模板（{domain} {admin_url} {out} 等占位符）
#   "note": str,                        为什么要跑这个
# }

RULES: list[dict] = [

    # ── Phase 0: 侦察 ──────────────────────────────────────────────

    {
        "id": "se_inject_ensure",
        "name": "助手身份注入（Claude/Codex）",
        "phase": 0, "priority": 1,
        "trigger": lambda fp: not fp.get("se_inject_ok"),
        "tool": "se_inject.py",
        "cmd_template": "python3 {tools}/se_inject.py ensure",
        "note": "工作区缺 CLAUDE.md / .claude/memory 时先 ensure，Claude/Codex 才认本库授权闸",
    },
    {
        "id": "browser_loot_triage",
        "name": "浏览器 Cookie / 窃密包离线分诊",
        "phase": 0, "priority": 1,
        "trigger": lambda fp: fp.get("has_browser_loot"),
        "tool": "browser_loot_triage.py",
        "cmd_template": "python3 {tools}/browser_loot_triage.py from-case --case {case} --url {base_url}",
        "note": "案卷有 sqlite/rar/窃密目录则分诊 + 整包 Cookie/指纹 UA 回放授权 URL",
    },
    {
        "id": "subdomain_enum",
        "name": "测试/暂存子域探测",
        "phase": 0, "priority": 1,
        "trigger": lambda fp: True,   # 任何目标都跑
        "tool": "test_subdomain_enum.py",
        "cmd_template": "python3 {tools}/test_subdomain_enum.py scan --domain {domain} --case {case}",
        "note": "dev/test/staging 子域通常没有 CF，直通源站，绕过 WAF",
    },
    {
        "id": "osint_recon",
        "name": "四维侦察 L1（首页/DNS）",
        "phase": 0, "priority": 2,
        "trigger": lambda fp: True,
        "tool": "osint_recon.py",
        "cmd_template": "python3 {tools}/osint_recon.py --url {base_url} --case {case} --out {out}/recon/osint.json",
        "note": "L1 首页维；必须接 origin/FOFA。人员维默认关",
    },
    {
        "id": "sensitive_dir_space_hunt",
        "name": "开放目录空间测绘（带域 v5 语法）",
        "phase": 0, "priority": 2,
        "trigger": lambda fp: True,
        "tool": "sensitive_dir_dump_probe.py",
        "cmd_template": "python3 {tools}/sensitive_dir_dump_probe.py space-hunt --domain {domain} --case {case} --tier extra,ai",
        "note": "FOFA/Shodan/Censys 全带 domain=；禁止去域全网猎杀。命中后再 hunt",
    },
    {
        "id": "origin_recon",
        "name": "源站真实 IP 溯源",
        "phase": 0, "priority": 1,
        "trigger": lambda fp: fp.get("has_cdn") or fp.get("has_cloudflare"),
        "tool": "origin_recon.py",
        "cmd_template": "python3 {tools}/origin_recon.py --domain {domain} --case {case}",
        "note": "CF/CDN 后找源站 IP；默认 crt.sh（按域）+ whois",
    },
    {
        "id": "cache_poison",
        "name": "缓存投毒未键控头",
        "phase": 2, "priority": 2,
        "trigger": lambda fp: fp.get("has_cdn") or fp.get("has_cache") or fp.get("has_cloudflare"),
        "tool": "cache_poison_probe.py",
        "cmd_template": "python3 {tools}/cache_poison_probe.py --url {base_url} --case {case}",
        "note": "CRITICAL 交接 web-cache-poisoning；测完清缓存",
    },
    {
        "id": "js_secret_hunter",
        "name": "JS 文件密钥提取",
        "phase": 0, "priority": 2,
        "trigger": lambda fp: True,
        "tool": "js_secret_hunter.py",
        "cmd_template": "python3 {tools}/js_secret_hunter.py hunt -u {base_url} --out {out}/recon/js_secrets.json --case {case}",
        "note": "前端 JS + SourceMap 猎 AES/salt/JWT；命中接 api_dispatcher 或假支付",
    },
    {
        "id": "yudao_appapi_probe",
        "name": "芋道/Qzino/加密网关认族",
        "phase": 0, "priority": 2,
        "trigger": lambda fp: fp.get("is_gambling") or fp.get("has_yudao_appapi") or fp.get("has_api_dispatcher"),
        "tool": "yudao_appapi_probe.py",
        "cmd_template": "python3 {tools}/yudao_appapi_probe.py -u {base_url} --case {case} --out {out}/recon/yudao_appapi.json",
        "note": "认 TMA/sk_encrypt/Qzino；命中切白标家族分流，勿只记指纹",
    },
    {
        "id": "dirbrute_probe",
        "name": "短字典备份/隐藏 path",
        "phase": 0, "priority": 3,
        "trigger": lambda fp: True,
        "tool": "dirbrute_probe.py",
        "cmd_template": "python3 {tools}/dirbrute_probe.py -u {base_url} --out {out}/recon/dirbrute.json --case {case}",
        "note": "短字典 .git/.env/备份/面板；命中切宝塔/DeepAudit/假支付，勿百万级爆破",
    },
    {
        "id": "apk_recon",
        "name": "APK 逆向提取密钥",
        "phase": 0, "priority": 2,
        "trigger": lambda fp: fp.get("has_app_download") or fp.get("is_gambling"),
        "tool": "apk_recon.py",
        "cmd_template": "test -f {out}/recon/app.apk && python3 {tools}/apk_recon.py strings --apk {out}/recon/app.apk --case {case} || echo '先把 APK 放到 {out}/recon/app.apk'",
        "note": "APK 里有后台 API 地址、密钥、hardcoded token，博彩站必查",
    },
    {
        "id": "webview_bridge",
        "name": "WebView/Deeplink 桥静态面",
        "phase": 0, "priority": 3,
        "trigger": lambda fp: fp.get("has_app_download") or fp.get("is_gambling"),
        "tool": "webview_bridge_probe.py",
        "cmd_template": "test -d {out}/recon/jadx && python3 {tools}/webview_bridge_probe.py scan --dir {out}/recon/jadx --case {case} || echo 'jadx 目录不在 recon/jadx，有反编译产物再扫 WebView 桥'",
        "note": "Deeplink/JsBridge/文件域；L2 只认强标签",
    },
    {
        "id": "port_scan",
        "name": "非标端口管理面扫描",
        "phase": 0, "priority": 2,
        "trigger": lambda fp: fp.get("is_gambling") or fp.get("has_cloudflare"),
        "tool": "port_admin_scan.py",
        "cmd_template": "python3 {tools}/port_admin_scan.py scan --domain {domain} --case {case}",
        "note": "CF 只代理 80/443，8888/9000/7001 等端口直通源站管理面",
    },
    {
        "id": "tg_enum",
        "name": "Telegram Bot/群枚举",
        "phase": 0, "priority": 3,
        "trigger": lambda fp: fp.get("has_tg") or fp.get("is_gambling"),
        "tool": "tg_cmd_enum.py",
        "cmd_template": "python3 {tools}/tg_cmd_enum.py find-bots --site-domain {domain} --case {case}",
        "note": "博彩站常有 TG 客服/充提机器人，可枚举命令/劫持 webhook",
    },

    # ── Phase 1: 绕过 ──────────────────────────────────────────────

    {
        "id": "ip_whitelist_bypass",
        "name": "IP 白名单全向量绕过",
        "phase": 1, "priority": 1,
        "trigger": lambda fp: fp.get("has_ip_restriction") or fp.get("admin_403") or fp.get("has_cloudflare"),
        "tool": "ip_whitelist_bypass.py",
        "cmd_template": "python3 {tools}/ip_whitelist_bypass.py probe -u {admin_url} -d {domain} --out {out}/bypass/ip_whitelist",
        "note": "Header 注入/XFF 首项/非标端口/IPv6/协议降级 7 个向量全枚举",
    },
    {
        "id": "cf_backup_bypass",
        "name": "CF WAF 绕过 + 备份文件泄露",
        "phase": 1, "priority": 2,
        "trigger": lambda fp: fp.get("has_cloudflare"),
        "tool": "cf_backup_bypass.py",
        "cmd_template": "python3 {tools}/cf_backup_bypass.py scan --base {base_url} --case {case}",
        "note": ".git/.env/.bak 等备份文件可能未被 CF 规则保护",
    },
    {
        "id": "waf_evasion",
        "name": "WAF 检测与绕过路由",
        "phase": 1, "priority": 2,
        "trigger": lambda fp: fp.get("has_waf"),
        "tool": "waf_detect.py",
        "cmd_template": "python3 {tools}/waf_detect.py detect --url {base_url} --case {case}",
        "note": "识别 WAF 类型后选最优绕过路径",
    },

    # ── Phase 2: 漏洞利用 ──────────────────────────────────────────

    {
        "id": "api_dispatcher",
        "name": "API 调度器方法枚举",
        "phase": 2, "priority": 1,
        "trigger": lambda fp: fp.get("has_api_dispatcher") or fp.get("is_gambling"),
        "tool": "api_dispatcher_enum.py",
        "cmd_template": "python3 {tools}/api_dispatcher_enum.py scan --base {base_url}/api.html --case {case}",
        "note": "博彩站常用 /api.html?method=xxx 单点调度，枚举隐藏方法",
    },
    {
        "id": "logic_vuln",
        "name": "业务逻辑漏洞探测",
        "phase": 2, "priority": 1,
        "trigger": lambda fp: fp.get("is_gambling") or fp.get("has_payment"),
        "tool": "logic_vuln_probe.py",
        "cmd_template": "python3 {tools}/logic_vuln_probe.py scan --base {base_url} --case {case}",
        "note": "负数金额/并发/订单重放/科学记数法绕过数值校验",
    },
    {
        "id": "fund_edge",
        "name": "会员资金面边缘越权",
        "phase": 2, "priority": 1,
        "trigger": lambda fp: fp.get("is_gambling") or fp.get("has_payment") or fp.get("has_fund_edge"),
        "tool": "fund_edge_ops_probe.py",
        "cmd_template": "python3 {tools}/fund_edge_ops_probe.py harvest --base {base_url} --case {case}",
        "note": "wallet_id/双路径/展示层地址；有 A/B 票再跑 matrix",
    },
    {
        "id": "ssrf_probe",
        "name": "SSRF 探测（图片上传/URL预览）",
        "phase": 2, "priority": 2,
        "trigger": lambda fp: fp.get("has_upload") or fp.get("has_url_preview"),
        "tool": "ssrf_probe.py",
        "cmd_template": "python3 {tools}/ssrf_probe.py scan --base {base_url} --case {case}",
        "note": "SSRF → 内网扫描 / 云厂商元数据接口 / Redis/Nacos 等",
    },
    {
        "id": "stored_xss",
        "name": "客服 IM 存储型 XSS",
        "phase": 2, "priority": 2,
        "trigger": lambda fp: fp.get("has_im") or fp.get("is_gambling"),
        "tool": "stored_xss_probe.py",
        "cmd_template": "python3 {tools}/stored_xss_probe.py scan --base {base_url} --case {case}",
        "note": "在线客服/IM 存储 XSS → 偷 admin cookie",
    },
    {
        "id": "ws_probe",
        "name": "WebSocket 游戏逻辑测试",
        "phase": 2, "priority": 2,
        "trigger": lambda fp: fp.get("has_websocket") or fp.get("is_gambling"),
        "tool": "ws_probe.py",
        "cmd_template": "python3 {tools}/ws_probe.py scan --base {base_url} --case {case}",
        "note": "博彩游戏用 WebSocket 通信，可能未鉴权订阅/注入消息",
    },
    {
        "id": "fastjson_probe",
        "name": "Fastjson RCE 检测",
        "phase": 2, "priority": 2,
        "trigger": lambda fp: fp.get("tech_java") or fp.get("has_spring"),
        "tool": "fastjson_probe.py",
        "cmd_template": "python3 {tools}/fastjson_probe.py scan -u {base_url} --out {out}/vulns/fastjson",
        "note": "Java 后端 Fastjson CVE-2026-16723 RCE",
    },
    {
        "id": "nginx_rift_probe",
        "name": "NGINX Rift CVE-2026-42945 指纹",
        "phase": 2, "priority": 2,
        "trigger": lambda fp: fp.get("has_nginx"),
        "tool": "nginx_rift_probe.py",
        "cmd_template": "python3 {tools}/nginx_rift_probe.py scan -u {base_url} --out {out}/vulns/nginx_rift/",
        "note": "rewrite 堆溢出 L1/L2；授权内 L3/L4 见 Playbook → poc-db/nginx-rift/poc.py",
    },
    {
        "id": "actuator_probe",
        "name": "Spring Actuator 探测",
        "phase": 2, "priority": 1,
        "trigger": lambda fp: fp.get("has_spring") or fp.get("tech_java"),
        "tool": "actuator_probe.py",
        "cmd_template": "python3 {tools}/actuator_probe.py --base {base_url} --out {out}/vulns/actuator",
        "note": "Spring Boot /actuator；heapdump 可达则下一刀 Range+蓝鸟，禁止只扫 health",
    },
    {
        "id": "heap_cred_scan",
        "name": "Heapdump 蓝鸟拆堆",
        "phase": 2, "priority": 2,
        "trigger": lambda fp: fp.get("has_spring") or fp.get("tech_java"),
        "tool": "heap_cred_scan.py",
        "cmd_template": (
            "python3 {tools}/heap_cred_scan.py from-probe "
            "--probe {out}/vulns/actuator/probe.json "
            "--dump-dir {out}/案卷/heapdump --out {out}/接管/heap_creds --case {case}"
        ),
        "note": "必须排在 actuator_probe 之后。probe 说可达才下堆；已有 hprof 也拆。禁止只扫 LTAI",
    },
    {
        "id": "java_web_surface",
        "name": "Java 网站面分流（Jeecg/Shiro/Druid/XXL）",
        "phase": 2, "priority": 1,
        "trigger": lambda fp: (
            fp.get("tech_java") or fp.get("has_spring")
            or fp.get("has_jeecg") or fp.get("has_shiro") or fp.get("has_druid")
            or fp.get("has_oa")
        ),
        "tool": "java_web_surface_probe.py",
        "cmd_template": "python3 {tools}/java_web_surface_probe.py -u {base_url} --out {out}/vulns/java_web_surface.json --case {case}",
        "note": "Jeecg/Shiro/Druid/XXL + 国产 OA 指纹(cnoa) → 切对应手法卡",
    },
    {
        "id": "thinkphp_surface",
        "name": "ThinkPHP 指纹（盘口 PHP）",
        "phase": 2, "priority": 1,
        "trigger": lambda fp: fp.get("has_thinkphp") or fp.get("tech_php"),
        "tool": "thinkphp_surface_probe.py",
        "cmd_template": "python3 {tools}/thinkphp_surface_probe.py -u {base_url} --out {out}/vulns/thinkphp.json --case {case}",
        "note": "ThinkPHP 指纹；默认 Client-IP 差分 + .env",
    },
    {
        "id": "tp3_fenxiao",
        "name": "ThinkPHP3 魔改分销 API",
        "phase": 2, "priority": 1,
        "trigger": lambda fp: fp.get("has_tp3_fenxiao") or (
            fp.get("has_thinkphp") and fp.get("has_fenxiao_api")
        ),
        "tool": "tp3_fenxiao_probe.py",
        "cmd_template": "python3 {tools}/tp3_fenxiao_probe.py -u {base_url} --case {case} --out {out}/vulns/tp3_fenxiao.json",
        "note": "ApiXxx/分销资金/chk_update/布尔 SQLi；禁止 DELETE OR",
    },
    {
        "id": "xxljob_admin",
        "name": "XXL-JOB 管理台组合链",
        "phase": 2, "priority": 1,
        "trigger": lambda fp: fp.get("has_xxljob"),
        "tool": "xxljob_admin_probe.py",
        "cmd_template": "python3 {tools}/xxljob_admin_probe.py --base {base_url} --case {case} --out {out}/vulns/xxljob.json",
        "note": "默认口+列执行器；GLUE 下发先问",
    },
    {
        "id": "tg_number_admin",
        "name": "TG 号码管理后台",
        "phase": 2, "priority": 1,
        "trigger": lambda fp: fp.get("has_tg_number_admin"),
        "tool": "tg_number_admin_probe.py",
        "cmd_template": "python3 {tools}/tg_number_admin_probe.py --base {base_url} --case {case}",
        "note": "admin/admin123 + export 只读头；禁止改原密",
    },
    {
        "id": "pay_matrix",
        "name": "假支付验签矩阵",
        "phase": 2, "priority": 0,
        "trigger": lambda fp: fp.get("has_payment") or fp.get("is_php_faka")
        or fp.get("is_acg_faka") or fp.get("is_dujiao_next"),
        "tool": "pay_matrix.py",
        "cmd_template": "python3 {tools}/pay_matrix.py --base {base_url} --case {case}",
        "note": "notify 矩阵；严签先日志抽钥再支付栈。Go Next 走 dujiao-next-1yuan-pay",
    },
    {
        "id": "usdt_chain_scan",
        "name": "USDT 链上 approve 拓线",
        "phase": 2, "priority": 3,
        "trigger": lambda fp: fp.get("has_payment"),
        "tool": "usdt_attr_hijack.py",
        "cmd_template": "python3 {tools}/usdt_attr_hijack.py chain-scan --case {case} --pages 15",
        "note": "只读链上；候选再 chain-verify。站点归属劫持仍走 bind-dup",
    },
    {
        "id": "sensitive_dir_dump",
        "name": "敏感目录/日志抽钥",
        "phase": 2, "priority": 0,
        "trigger": lambda fp: fp.get("tech_php") or fp.get("is_php_faka") or fp.get("has_dir_listing"),
        "tool": "sensitive_dir_dump_probe.py",
        "cmd_template": "python3 {tools}/sensitive_dir_dump_probe.py hunt --base {base_url} --case {case}",
        "note": "hunt 默认 SSH whoami；余额先问再 --verify-balance；laravel.log/merchant_pem → 假支付",
    },
    {
        "id": "fastadmin_daifu",
        "name": "FastAdmin 代付/卡商",
        "phase": 2, "priority": 0,
        "trigger": lambda fp: fp.get("has_fastadmin_daifu"),
        "tool": "fastadmin_daifu_probe.py",
        "cmd_template": "python3 {tools}/fastadmin_daifu_probe.py recon --base {base_url} --case {case} --insecure",
        "note": "demo 未授权 + backend JS；part 拖树后才 crack。multi money ≠ 结算",
    },
    {
        "id": "fastadmin_shop_tenant",
        "name": "FastAdmin Shop GT-filter",
        "phase": 2, "priority": 0,
        "trigger": lambda fp: fp.get("has_fastadmin_shop"),
        "tool": "fastadmin_shop_tenant_probe.py",
        "cmd_template": "python3 {tools}/fastadmin_shop_tenant_probe.py recon --base {base_url} --case {case} --insecure",
        "note": "shop_hq 多租户；有票后 gt-probe。EQ 阴性不算隔离",
    },
    {
        "id": "cognito_s3",
        "name": "Cognito 未认证池打 S3",
        "phase": 2, "priority": 0,
        "trigger": lambda fp: fp.get("has_cognito_s3"),
        "tool": "cognito_s3_probe.py",
        "cmd_template": "python3 {tools}/cognito_s3_probe.py extract --path <apk或前端> --case {case}",
        "note": "IdentityPoolId → chain；Cognito/S3 不扩 targets；写只用 marker",
    },
    {
        "id": "captcha_auto",
        "name": "极验 / 验证码自动过闸",
        "phase": 2, "priority": 0,
        "trigger": lambda fp: fp.get("has_geetest"),
        "tool": "captcha_auto.py",
        "cmd_template": "python3 {tools}/captcha_auto.py solve --url {base_url} --case {case} --probe-api",
        "note": "有头真鼠标滑块；有打码 Key 则 token。过闸后会话在 接管/session/",
    },
    {
        "id": "panel_surface",
        "name": "宝塔 / phpMyAdmin 面板指纹",
        "phase": 2, "priority": 2,
        "trigger": lambda fp: fp.get("has_panel") or fp.get("tech_php") or fp.get("is_gambling"),
        "tool": "panel_surface_probe.py",
        "cmd_template": "python3 {tools}/panel_surface_probe.py -u {base_url} --out {out}/vulns/panel.json --case {case}",
        "note": "登录页指纹 + PMA/Adminer 短字典弱口；改密/拉库不要默认做",
    },
    {
        "id": "redis_unauth",
        "name": "Redis 未授权只读探针",
        "phase": 2, "priority": 3,
        "trigger": lambda fp: fp.get("tech_java") or fp.get("has_druid"),
        "tool": "redis_unauth_probe.py",
        "cmd_template": "python3 {tools}/redis_unauth_probe.py --host {domain} --port 6379 --out {out}/vulns/redis.json --case {case}",
        "note": "PING/INFO + captcha 键名；源站 IP 更准。写盘 webshell 不做默认",
    },
    {
        "id": "oa_surface",
        "name": "国产 OA 指纹（通达/泛微/用友/致远）",
        "phase": 2, "priority": 2,
        "trigger": lambda fp: fp.get("has_oa"),
        "tool": "nuclei",
        "cmd_template": "python3 {root}/tools/1day-kit/od_kit.py nuclei --url {base_url} --case {case} -t {root}/tools/1day-kit/custom-templates/yonyou-seeyon-oa-surface.yaml",
        "note": "nuclei 面 + java_web cnoa；通达/泛微先读 中原骨架.md",
    },
    {
        "id": "harbor_product",
        "name": "Harbor/容器仓库指纹",
        "phase": 2, "priority": 2,
        "trigger": lambda fp: fp.get("has_harbor"),
        "tool": "nday_route.py",
        "cmd_template": "python3 {tools}/nday_route.py -u {base_url} --case {case}",
        "note": "nday 钉 harbor/cn-oa；默认口令先问改密",
    },
    {
        "id": "bucket_probe",
        "name": "云存储桶枚举",
        "phase": 2, "priority": 3,
        "trigger": lambda fp: fp.get("has_cdn") or fp.get("has_oss"),
        "tool": "bucket_probe.py",
        "cmd_template": "python3 {tools}/bucket_probe.py scan -d {domain}",
        "note": "OSS/S3/COS 公开读/写/列目录，获取备份文件/密钥",
    },
    {
        "id": "1day_nuclei",
        "name": "1day CVE 批量扫描",
        "phase": 2, "priority": 3,
        "trigger": lambda fp: True,
        "tool": "nuclei",
        "cmd_template": "python3 {root}/tools/1day-kit/od_kit.py nuclei --url {base_url} --case {case} --custom-only",
        "note": "自定义模板库：NGINX Rift/Langflow/TeamCity/WordPress/Fastjson/Laravel 等",
    },
    {
        "id": "jwt_gql_probe",
        "name": "JWT / GraphQL 表面",
        "phase": 2, "priority": 2,
        "trigger": lambda fp: True,
        "tool": "jwt_gql_probe.py",
        "cmd_template": "python3 {tools}/jwt_gql_probe.py -u {base_url} --out {out}/vulns/jwt_gql.json --case {case}",
        "note": "introspection + 页面 JWT；弱 HS256；掩码票 eyJ…XXXX 原样重放",
    },
    {
        "id": "tg_cloud_panel",
        "name": "TG 云控四族认族",
        "phase": 2, "priority": 1,
        "trigger": lambda fp: fp.get("has_tg_wasm") or fp.get("has_masked_jwt"),
        "tool": "tg_cloud_panel_probe.py",
        "cmd_template": "python3 {tools}/tg_cloud_panel_probe.py -u {base_url} --case {case}",
        "note": "Fernet / 系统选择 / JWT 默认钥 / Go-WASM 掩码票；成功=可登录 session",
    },
    {
        "id": "ato_reset_withdraw",
        "name": "任意 code 重置 + 无旧密提现密",
        "phase": 2, "priority": 1,
        "trigger": lambda fp: fp.get("has_reset_api"),
        "tool": "ato_reset_withdraw_probe.py",
        "cmd_template": (
            "echo '[ato] 有自己的用户名再跑: python3 {tools}/ato_reset_withdraw_probe.py "
            "oracle --base {base_url} --case {case} --exist-user <自己> --ghost-user nosuchuser999'"
        ),
        "note": "页面出现 resetPassword 才激活。禁止用占位符 SELF 真打；真提现先问",
    },
    {
        "id": "strike_probe",
        "name": "侦察后黑盒突击 S1–S8",
        "phase": 2, "priority": 1,
        "trigger": lambda fp: True,
        "tool": "strike_probe.py",
        "cmd_template": "python3 {tools}/strike_probe.py -u {base_url} --out {out}/vulns/strike.json --case {case}",
        "note": "侦察后、专卡前；短字典单向量。有 TP3/XXL/假支付仍先专卡。不落马",
    },
    {
        "id": "core_web_surface",
        "name": "核心 Web 漏洞面",
        "phase": 2, "priority": 2,
        "trigger": lambda fp: True,
        "tool": "core_web_surface_probe.py",
        "cmd_template": "python3 {tools}/core_web_surface_probe.py -u {base_url} --fast --out {out}/vulns/core_web.json --case {case}",
        "note": "XXE/SSTI/LFI/CORS/上传/重置（--fast）；深挖去掉 --fast。RCE 先问",
    },
    {
        "id": "auth_brute",
        "name": "登录面短字典弱口",
        "phase": 2, "priority": 2,
        "trigger": lambda fp: True,
        "tool": "auth_brute_probe.py",
        "cmd_template": "python3 {tools}/auth_brute_probe.py -u {base_url} --out {out}/vulns/auth_brute.json --case {case}",
        "note": "最多 24 次；锁号即停。PMA/Nacos 走专卡",
    },
    {
        "id": "middleware_unauth",
        "name": "Mongo/ES/Memcached 未授权",
        "phase": 2, "priority": 2,
        "trigger": lambda fp: True,
        "tool": "middleware_unauth_probe.py",
        "cmd_template": "python3 {tools}/middleware_unauth_probe.py --host {domain} --out {out}/vulns/middleware.json --case {case}",
        "note": "只读握手。Redis 另条 redis_unauth",
    },
    {
        "id": "doris_unauth",
        "name": "Doris/StarRocks 9030+8030 三板斧",
        "phase": 2, "priority": 1,
        "trigger": lambda fp: any(
            x in str(fp).lower()
            for x in ("doris", "starrocks", "palo", "9030", "8030", "default_cluster")
        ),
        "tool": "doris_probe.py",
        "cmd_template": "python3 {tools}/doris_probe.py --host {domain} --out {out}/vulns/doris.json --case {case}",
        "note": "空口令+HTTP 翻库。OUTFILE/甩马先问",
    },
    {
        "id": "nday_route",
        "name": "N-day 指纹→专卡路由",
        "phase": 2, "priority": 0,
        "trigger": lambda fp: True,
        "tool": "nday_route.py",
        "cmd_template": "python3 {tools}/nday_route.py -u {base_url} --out {out}/vulns/nday_route.json --case {case}",
        "note": "先钉组件再跑专卡；禁止只拿 CVE 编号结案",
    },
    {
        "id": "llm_surface",
        "name": "LLM/Agent 只读指纹",
        "phase": 2, "priority": 2,
        "trigger": lambda fp: fp.get("has_llm"),
        "tool": "llm_surface_probe.py",
        "cmd_template": "python3 {tools}/llm_surface_probe.py -u {base_url} --out {out}/vulns/llm.json --case {case}",
        "note": "/v1/models 未授权；LiteLLM/Langflow 切专卡。不做越狱",
    },

    # ── Phase 3: 接管 ──────────────────────────────────────────────

    {
        "id": "agent_probe",
        "name": "代理账号体系测试（BOLA/提权）",
        "phase": 3, "priority": 1,
        "trigger": lambda fp: fp.get("has_agent_system") or fp.get("is_gambling"),
        "tool": "agent_probe.py",
        "cmd_template": "python3 {tools}/agent_probe.py discover --base {base_url} --case {case}",
        "note": "代理注册 → BOLA 遍历 → JWT 密钥提取 → 伪造 admin token",
    },
    {
        "id": "grpc_probe",
        "name": "gRPC 服务探测",
        "phase": 3, "priority": 3,
        "trigger": lambda fp: fp.get("tech_grpc"),
        "tool": "grpc_probe.py",
        "cmd_template": "python3 {tools}/grpc_probe.py detect --target {domain}:443 --case {case}",
        "note": "gRPC 反射接口 → 枚举服务方法 → 越权调用",
    },
    {
        "id": "evidence_gate",
        "name": "证据闸（结案前只读）",
        "phase": 3, "priority": 9,
        "trigger": lambda fp: True,
        "tool": "evidence_gate.py",
        "cmd_template": "python3 {tools}/evidence_gate.py --case {case} --from-status",
        "note": "口头结论对案卷/接管/支付/证据原文；不打目标。矩阵未测拦住结案",
    },

    # ── Phase 4: 社工 ──────────────────────────────────────────────

    {
        "id": "social_engineer",
        "name": "社工身份方案生成",
        "phase": 4, "priority": 1,
        "trigger": lambda fp: fp.get("is_gambling") or fp.get("has_agent_system"),
        "tool": "social_engineer_agent.py",
        "cmd_template": "python3 {tools}/social_engineer_agent.py run -d {domain} --goal agent_url",
        "note": "分析目标特征 → 推荐最佳社工身份 → 生成完整对话脚本",
    },
]


# ══════════════════════════════════════════════════════════════════
#  指纹识别器
# ══════════════════════════════════════════════════════════════════

PHASE_NAMES = {
    0: "侦察",
    1: "绕过",
    2: "漏洞利用",
    3: "接管",
    4: "社工",
}


def fingerprint(domain: str, base_url: str, admin_url: str = "") -> dict:
    """
    HTTP 探测目标，识别：CDN/WAF、技术栈、功能模块、访问限制。
    返回特征字典，用于激活匹配的工具规则。
    """
    fp: dict = {
        "domain": domain,
        "base_url": base_url,
        "admin_url": admin_url or "",
        # CDN / 保护层
        "has_cloudflare": False,
        "has_cdn": False,
        "has_waf": False,
        "has_ip_restriction": False,
        # 技术栈
        "tech_java": False,
        "has_spring": False,
        "has_jeecg": False,
        "has_shiro": False,
        "has_druid": False,
        "tech_php": False,
        "has_thinkphp": False,
        "has_fastadmin_daifu": False,
        "has_fastadmin_shop": False,
        "has_cognito_s3": False,
        "has_geetest": False,
        "has_panel": False,
        "has_oa": False,
        "has_cache": False,
        "has_harbor": False,
        "has_tg_wasm": False,
        "has_masked_jwt": False,
        "has_reset_api": False,
        "tech_node": False,
        "tech_grpc": False,
        "has_nginx": False,
        "has_oss": False,
        # 功能模块
        "is_gambling": False,
        "has_payment": False,
        "is_dujiao_next": False,
        "is_acg_faka": False,
        "is_php_faka": False,
        "has_agent_system": False,
        "has_api_dispatcher": False,
        "has_im": False,
        "has_upload": False,
        "has_url_preview": False,
        "has_websocket": False,
        "has_app_download": False,
        "has_tg": False,
        "has_yudao_appapi": False,
        "has_graphql": False,
        "has_jwt": False,
        "has_llm": False,
        "has_dir_listing": False,
        "has_browser_loot": False,
        "se_inject_ok": True,
        "has_tp3_fenxiao": False,
        "has_fenxiao_api": False,
        "has_xxljob": False,
        "has_tg_number_admin": False,
        # 访问状态
        "admin_403": False,
        "admin_200": False,
        "site_up": False,
        # 原始数据
        "headers": {},
        "title": "",
        "body_snippet": "",
        "status_code": 0,
        "tg_contacts": [],
        "errors": [],
    }

    sess = requests.Session()
    sess.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    })

    def _get(url: str, timeout: int = 12) -> requests.Response | None:
        try:
            return sess.get(url, timeout=timeout, verify=False, allow_redirects=True)
        except Exception as e:
            fp["errors"].append(str(e)[:80])
            return None

    # ── 主站探测
    r = _get(base_url)
    if r:
        fp["site_up"] = True
        fp["status_code"] = r.status_code
        fp["headers"] = dict(r.headers)
        body = r.text[:8000]
        fp["body_snippet"] = body[:400]

        # 标题提取
        m = re.search(r"<title[^>]*>([^<]{1,120})</title>", body, re.I)
        if m:
            fp["title"] = m.group(1).strip()

        # Cloudflare
        if "cf-ray" in r.headers or "cloudflare" in r.headers.get("server", "").lower():
            fp["has_cloudflare"] = True
            fp["has_cdn"] = True
        # 其他 CDN
        if any(h in r.headers for h in ("x-cache", "x-akamai", "x-amz-cf-id", "x-cdn")):
            fp["has_cdn"] = True
        # WAF
        waf_headers = ("x-waf", "x-sucuri", "x-firewall", "x-fw-hash")
        if any(h in r.headers for h in waf_headers):
            fp["has_waf"] = True
        server_hdr = r.headers.get("server", "").lower()
        if any(w in server_hdr for w in ("waf", "safedog", "ngx_lua", "openresty")):
            fp["has_waf"] = True

        # 技术栈 — Java/Spring
        java_hints = ("java", "spring", "tomcat", "jetty", "jboss", "glassfish",
                      "x-application-context", "x-powered-by")
        body_lower = body.lower()
        if (any(h in r.headers for h in ("x-application-context", "x-powered-by"))
                or any(w in body_lower for w in ("spring", "tomcat", "java", "struts"))
                or "jsessionid" in r.headers.get("set-cookie", "").lower()):
            fp["tech_java"] = True
        if "spring" in body_lower or "actuator" in body_lower or "springboot" in body_lower:
            fp["has_spring"] = True
        if any(w in body_lower for w in ("jeecg", "jeecg-boot", "window._config")):
            fp["has_jeecg"] = True
            fp["tech_java"] = True
        sc_all = ";".join(v for k, v in r.headers.items() if k.lower() == "set-cookie")
        sc_all += ";" + r.headers.get("Set-Cookie", "")
        if "rememberme=deleteme" in sc_all.lower():
            fp["has_shiro"] = True
            fp["tech_java"] = True
        if "druid" in body_lower or "/druid/" in body_lower:
            fp["has_druid"] = True
            fp["tech_java"] = True

        # PHP
        if ("php" in server_hdr or "php" in r.headers.get("x-powered-by", "").lower()
                or ".php" in r.url or "phpsessid" in r.headers.get("set-cookie", "").lower()):
            fp["tech_php"] = True
        xpb = r.headers.get("x-powered-by", "").lower()
        if "thinkphp" in xpb or "thinkphp" in body_lower or "think\\app" in body_lower:
            fp["has_thinkphp"] = True
            fp["tech_php"] = True
        if any(w in body_lower for w in (
            "apiuserfenxiao", "get_fenxiao_db_data", "common_get_author_list",
            "thinkphp3.1", "/thinkphp/readme",
        )):
            fp["has_tp3_fenxiao"] = True
            fp["has_fenxiao_api"] = True
            fp["has_thinkphp"] = True
            fp["tech_php"] = True
        if fp.get("has_thinkphp") or fp.get("tech_php"):
            rmd = _get(urljoin(base_url.rstrip("/") + "/", "ThinkPHP/README.md"))
            if rmd is not None and rmd.status_code == 200 and "thinkphp" in rmd.text.lower():
                fp["has_thinkphp"] = True
                if "3.1" in rmd.text or "魔改" in rmd.text or "apiuser" in rmd.text.lower():
                    fp["has_tp3_fenxiao"] = True
            fen = _get(urljoin(base_url.rstrip("/") + "/", "index.php/ApiUserFenxiao/get_fenxiao_db_data"))
            if fen is not None and fen.status_code == 200 and "admin_now_money" in fen.text:
                fp["has_tp3_fenxiao"] = True
                fp["has_fenxiao_api"] = True
                fp["has_thinkphp"] = True
        if any(w in body_lower for w in (
            "xxl-job-admin", "xxl-job", "分布式任务调度",
        )):
            fp["has_xxljob"] = True
            fp["tech_java"] = True
        if any(w in body for w in ("TG号码管理", "TG号码")) or "tg号码管理" in body_lower:
            fp["has_tg_number_admin"] = True
        if any(w in body_lower for w in (
            "fastadmin", "/assets/js/backend", "/sh.php", "/ks.php",
            "require-backend", "代付", "卡商",
        )):
            fp["has_fastadmin_daifu"] = True
            fp["tech_php"] = True
        if any(w in body_lower for w in (
            "shop_hq", "shop_keeplogin", "/shop_hq/",
        )):
            fp["has_fastadmin_shop"] = True
            fp["tech_php"] = True
            fp["has_thinkphp"] = True
        if any(w in body_lower for w in ("宝塔", "aapanel", "bt-panel", "phpmyadmin", "adminer")):
            fp["has_panel"] = True
        if any(w in body_lower for w in (
            "yonyou", "用友", "nccloud", "seeyon", "致远", "/seeyon",
            "tongda", "通达", "logincheck.php", "weaver", "泛微", "/ecology/",
            "landray", "蓝凌", "/ekp/",
        )):
            fp["has_oa"] = True
        if any(k.lower() in r.headers for k in ("cf-cache-status", "x-cache", "x-cache-hits")) or (
            r.headers.get("age")
        ):
            fp["has_cache"] = True
        if any(w in body_lower for w in ("harbor", "goharbor", "/api/v2.0/systeminfo")):
            fp["has_harbor"] = True
        if any(w in body_lower for w in ("goencrypt", "godecrypt", "main.wasm", "taskprotocolrecovery")):
            fp["has_tg_wasm"] = True
        if extract_masked_tokens(r.text or ""):
            fp["has_masked_jwt"] = True
        if any(w in body_lower for w in ("resetpassword", "forgot/verify", "updatewithdrawpassword")):
            fp["has_reset_api"] = True

        # Node
        if "node" in server_hdr or "express" in server_hdr:
            fp["tech_node"] = True

        # gRPC（Content-Type / 头 / 页面提到 grpc-web）
        ctype = (r.headers.get("content-type") or "").lower()
        if (
            "application/grpc" in ctype
            or r.headers.get("grpc-status")
            or r.headers.get("grpc-message")
            or "grpc-web" in body_lower
            or "grpc.web" in body_lower
        ):
            fp["tech_grpc"] = True

        # NGINX / OpenResty（CVE-2026-42945 Rift 指纹）
        if "nginx" in server_hdr or "openresty" in server_hdr:
            fp["has_nginx"] = True

        # OSS/云存储
        if any(w in body_lower for w in ("aliyuncs.com", "amazonaws.com", "myqcloud.com",
                                          "cos.ap-", "oss-cn-", "s3.ap-")):
            fp["has_oss"] = True
        if any(w in body_lower for w in (
            "identitypoolid", "cognitoidentity", "aws-amplify",
            "cognito-identity", "awsconfiguration",
        )):
            fp["has_cognito_s3"] = True
        if any(w in body_lower for w in (
            "initgeetest", "geetest.com", "gcaptcha4", "geetest_slider", "geevisit.com",
            "vccgeetest.com", "gsensebot.com", "geetest_captcha_id",
        )):
            fp["has_geetest"] = True
            fp["has_cdn"] = True

        # 博彩站特征
        gambling_kw = ("彩票", "赌博", "体育", "老虎机", "百家乐", "棋牌", "真人",
                       "casino", "betting", "lottery", "slots", "sportsbook",
                       "sports", "live casino", "baccarat", "poker")
        if any(w in body_lower for w in gambling_kw):
            fp["is_gambling"] = True

        # 支付
        payment_kw = ("usdt", "支付", "充值", "提现", "payment", "deposit", "withdraw",
                      "recharge", "wallet", "tether")
        if any(w in body_lower for w in payment_kw):
            fp["has_payment"] = True
        if any(w in body_lower for w in (
            "wallet_id", "walletid", "fundsn", "turnwaterinit", "task-center", "taskcenter",
        )):
            fp["has_fund_edge"] = True
            fp["has_payment"] = True
        if any(w in body_lower for w in ("/dj.svg", "use_balance", "dujiao-next")):
            fp["is_dujiao_next"] = True
            fp["has_payment"] = True
        if any(w in body_lower for w in ("acg.js", "shared_id", "acg-shop", "/app/view/user/theme/toka")):
            fp["is_acg_faka"] = True
            fp["has_payment"] = True
        if any(w in body_lower for w in ("dujiaoka", "detail-order-sn", "独角数卡", "search-order-by-sn")):
            fp["is_php_faka"] = True
            fp["tech_php"] = True
            fp["has_payment"] = True

        # 代理体系
        agent_kw = ("代理", "代理商", "agent", "affiliate", "分佣", "邀请码",
                    "referral", "rebate", "返佣")
        if any(w in body_lower for w in agent_kw):
            fp["has_agent_system"] = True

        # API 调度器
        if "api.html" in body_lower or "method=" in body_lower or "action=" in body_lower:
            fp["has_api_dispatcher"] = True

        if any(w in body_lower for w in ("app-config.js", "sk_encrypt", "platform_id", "/app-api/", "x-ca-token")):
            fp["has_yudao_appapi"] = True

        # IM/客服
        im_kw = ("在线客服", "live chat", "客服", "intercom", "zendesk", "tawk",
                 "livechat", "crisp", "helpdesk")
        if any(w in body_lower for w in im_kw):
            fp["has_im"] = True

        # 上传 / URL 预览
        if "upload" in body_lower or "file" in body_lower:
            fp["has_upload"] = True
        if "preview" in body_lower or "thumbnail" in body_lower:
            fp["has_url_preview"] = True

        # WebSocket
        if "websocket" in body_lower or "ws://" in body_lower or "wss://" in body_lower:
            fp["has_websocket"] = True

        # App 下载
        if any(w in body_lower for w in ("下载", "download", "apk", "app store",
                                          "google play", ".apk", ".ipa")):
            fp["has_app_download"] = True

        # TG 联系方式
        tg_matches = re.findall(r"t\.me/([A-Za-z0-9_]{4,32})", body)
        if tg_matches:
            fp["has_tg"] = True
            fp["tg_contacts"] = list(set(tg_matches))[:5]

        if any(w in body_lower for w in ("/graphql", "graphiql", "__schema", "graphql")):
            fp["has_graphql"] = True
        if "eyj" in body_lower or "bearer " in body_lower or "jsonwebtoken" in body_lower:
            fp["has_jwt"] = True
        if any(w in body_lower for w in ("litellm", "langflow", "flowise", "/v1/models", "/v1/chat/completions", "openai")):
            fp["has_llm"] = True
        if any(w in body_lower for w in (
            "index of /", "directory listing", "parent directory",
            "href=\".env\"", "href=\".claude", "href=\".cursor", "href=\".hermes",
        )):
            fp["has_dir_listing"] = True

    r_dj = _get(base_url.rstrip("/") + "/dj.svg", timeout=6)
    if r_dj and r_dj.status_code in (200, 206):
        ct = (r_dj.headers.get("content-type") or "").lower()
        if "svg" in ct or "<svg" in (r_dj.text or "")[:240].lower():
            fp["is_dujiao_next"] = True
            fp["has_payment"] = True
    r_comp = _get(base_url.rstrip("/") + "/composer.json", timeout=6)
    if r_comp and r_comp.status_code in (200, 206):
        cj = (r_comp.text or "")[:4000].lower()
        if "require" in cj or '"name"' in cj:
            fp["tech_php"] = True
        if "dujiaoka" in cj or "faka" in cj:
            fp["is_php_faka"] = True
            fp["has_payment"] = True

    # ── Admin 入口探测（判断是否有 IP 白名单）
    admin_paths_to_try = [
        "/admin", "/admin/login", "/manage", "/backend",
        "/system/login", "/operator",
    ]
    admin_target = admin_url or base_url
    if admin_url:
        r_admin = _get(admin_url)
        if r_admin:
            if r_admin.status_code == 403:
                fp["admin_403"] = True
                fp["has_ip_restriction"] = True
            elif r_admin.status_code == 200:
                fp["admin_200"] = True
    else:
        for path in admin_paths_to_try:
            test_url = base_url.rstrip("/") + path
            r_admin = _get(test_url)
            if r_admin:
                if r_admin.status_code in (403, 520, 521):
                    fp["admin_403"] = True
                    fp["has_ip_restriction"] = True
                    fp["admin_url"] = test_url
                    break
                elif r_admin.status_code == 200:
                    body_a = r_admin.text[:500].lower()
                    if any(w in body_a for w in ("login", "username", "password", "用户名")):
                        fp["admin_200"] = True
                        fp["admin_url"] = test_url
                        break

    return fp


# ══════════════════════════════════════════════════════════════════
#  工具匹配引擎
# ══════════════════════════════════════════════════════════════════

def match_rules(fp: dict) -> list[dict]:
    """根据指纹匹配激活的工具规则，按 phase + priority 排序"""
    matched = []
    for rule in RULES:
        try:
            if rule["trigger"](fp):
                matched.append(rule)
        except Exception:
            pass
    matched.sort(key=lambda r: (r["phase"], r["priority"]))
    return matched


def render_cmd(rule: dict, fp: dict, out_dir: Path) -> str:
    """填充命令模板中的占位符"""
    admin_url = fp.get("admin_url") or fp.get("base_url", "")
    cmd = rule["cmd_template"]
    cmd = cmd.replace("{tools}", str(TOOLS))
    cmd = cmd.replace("{root}", str(ROOT))
    cmd = cmd.replace("{domain}", fp.get("domain", ""))
    cmd = cmd.replace("{base_url}", fp.get("base_url", ""))
    cmd = cmd.replace("{admin_url}", admin_url)
    cmd = cmd.replace("{out}", str(out_dir))
    cmd = cmd.replace("{case}", fp.get("case") or out_dir.name)
    return cmd


# ══════════════════════════════════════════════════════════════════
#  输出：作战计划
# ══════════════════════════════════════════════════════════════════

def print_plan(fp: dict, matched: list[dict], out_dir: Path):
    domain = fp["domain"]
    print(f"\n{'='*70}")
    print(f"  自动作战计划  —  {domain}")
    print(f"  生成时间: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*70}")

    # 指纹摘要
    flags = []
    if fp["has_cloudflare"]: flags.append("Cloudflare")
    if fp["has_waf"]: flags.append("WAF")
    if fp["has_ip_restriction"]: flags.append("IP白名单")
    if fp["tech_java"]: flags.append("Java")
    if fp["has_spring"]: flags.append("Spring")
    if fp.get("has_jeecg"): flags.append("Jeecg")
    if fp.get("has_shiro"): flags.append("Shiro")
    if fp.get("has_druid"): flags.append("Druid")
    if fp["tech_php"]: flags.append("PHP")
    if fp["tech_node"]: flags.append("Node")
    if fp["is_gambling"]: flags.append("博彩")
    if fp.get("has_yudao_appapi"): flags.append("芋道/加密API")
    if fp["has_payment"]: flags.append("支付")
    if fp.get("is_dujiao_next"): flags.append("独角Next")
    if fp.get("is_php_faka"): flags.append("独角PHP")
    if fp.get("is_acg_faka"): flags.append("异次元")
    if fp["has_agent_system"]: flags.append("代理体系")
    if fp["has_tg"]: flags.append(f"TG={','.join(fp['tg_contacts'])}")
    if fp.get("has_graphql"): flags.append("GraphQL")
    if fp.get("has_jwt"): flags.append("JWT")
    if fp.get("has_llm"): flags.append("LLM")
    if fp.get("has_browser_loot"): flags.append("浏览器包")
    if not fp.get("se_inject_ok", True): flags.append("助手未注入")
    if fp.get("has_tp3_fenxiao"): flags.append("TP3分销")
    if fp.get("has_xxljob"): flags.append("XXL-JOB")
    if fp.get("has_tg_number_admin"): flags.append("TG号码管理")

    print(f"\n  标题: {fp['title'] or '(未获取)'}")
    print(f"  状态: HTTP {fp['status_code']}  {'✓ 站点在线' if fp['site_up'] else '✗ 无响应'}")
    print(f"  指纹: {' | '.join(flags) or '(未识别出特征)'}")
    if fp.get("admin_url"):
        status = "403(IP白名单)" if fp["admin_403"] else "200(可达)"
        print(f"  后台: {fp['admin_url']}  [{status}]")

    # 按阶段输出工具列表
    current_phase = -1
    for i, rule in enumerate(matched, 1):
        if rule["phase"] != current_phase:
            current_phase = rule["phase"]
            print(f"\n  ── Phase {current_phase}: {PHASE_NAMES[current_phase]} ──────────────────────")

        # 优先级标识
        prio_mark = "🔴" if rule["priority"] == 1 else ("🟡" if rule["priority"] == 2 else "⚪")
        print(f"\n  {i:02d}. {prio_mark} {rule['name']}")
        print(f"      原因: {rule['note']}")
        print(f"      命令: {render_cmd(rule, fp, out_dir)}")

    print(f"\n{'='*70}")
    print(f"  共激活 {len(matched)} 个工具")
    print(f"  输出目录: {out_dir}")
    print(f"  快速执行全部: python3 {__file__} run -d {domain}")
    print(f"{'='*70}\n")


# ══════════════════════════════════════════════════════════════════
#  执行器
# ══════════════════════════════════════════════════════════════════

def run_tool(rule: dict, cmd: str, out_dir: Path, timeout: int = 120) -> dict:
    """执行单条工具命令，返回结果摘要"""
    result = {
        "id": rule["id"],
        "name": rule["name"],
        "cmd": cmd,
        "returncode": -1,
        "stdout": "",
        "stderr": "",
        "success": False,
        "hits": [],
    }

    # 检查工具文件是否存在（非 nuclei 等外部工具）
    if rule["tool"].endswith(".py"):
        tool_path = TOOLS / rule["tool"]
        if not tool_path.exists():
            result["stderr"] = f"工具文件不存在: {tool_path}"
            return result

    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        import shlex
        proc = subprocess.run(
            shlex.split(cmd) if isinstance(cmd, str) else cmd,
            shell=False, capture_output=True, text=True, timeout=timeout
        )
        result["returncode"] = proc.returncode
        result["stdout"] = proc.stdout[-3000:] if proc.stdout else ""
        result["stderr"] = proc.stderr[-1000:] if proc.stderr else ""
        result["success"] = proc.returncode == 0

        # 简单解析 stdout 中是否有命中
        if "★★" in proc.stdout or "BYPASS" in proc.stdout or "bypass" in proc.stdout.lower():
            result["hits"].append("发现绕过路径")
        if "secret" in proc.stdout.lower() or "token" in proc.stdout.lower():
            result["hits"].append("发现密钥/Token")
        if "vulnerable" in proc.stdout.lower() or "RCE" in proc.stdout:
            result["hits"].append("发现漏洞")
        if "200" in proc.stdout and "login" in proc.stdout.lower():
            result["hits"].append("发现登录页（可能已绕过）")

    except subprocess.TimeoutExpired:
        result["stderr"] = f"超时（>{timeout}s）"
    except Exception as e:
        result["stderr"] = str(e)

    return result


def run_campaign(fp: dict, matched: list[dict], out_dir: Path,
                 phases: list[int] = None, dry_run: bool = False):
    """按顺序执行所有激活的工具"""
    if phases:
        matched = [r for r in matched if r["phase"] in phases]

    print(f"\n[*] 开始执行 {len(matched)} 个工具...")
    results = []
    hits_summary = []

    for i, rule in enumerate(matched, 1):
        cmd = render_cmd(rule, fp, out_dir)
        phase_name = PHASE_NAMES[rule["phase"]]
        print(f"\n  [{i:02d}/{len(matched)}] [{phase_name}] {rule['name']}")
        print(f"         {cmd}")

        if dry_run:
            print("         [dry-run 跳过]")
            continue

        to = int(rule.get("timeout") or (180 if rule.get("id") == "strike_probe" else 90))
        result = run_tool(rule, cmd, out_dir, timeout=to)
        results.append(result)

        status_icon = "✓" if result["success"] else "✗"
        print(f"         {status_icon} 退出码 {result['returncode']}")

        if result["hits"]:
            for hit in result["hits"]:
                print(f"         ★ {hit}")
                hits_summary.append(f"[{rule['name']}] {hit}")

        if result["stderr"] and not result["success"]:
            print(f"         ! {result['stderr'][:100]}")

    # 汇总
    print(f"\n{'='*70}")
    print("  执行完毕")
    success_count = sum(1 for r in results if r["success"])
    print(f"  成功: {success_count}/{len(results)}  命中: {len(hits_summary)} 条")
    if hits_summary:
        print("\n  ★ 命中汇总:")
        for h in hits_summary:
            print(f"    {h}")

    # 保存结果 JSON
    report_path = out_dir / "campaign_report.json"
    report = {
        "domain": fp["domain"],
        "fingerprint": {k: v for k, v in fp.items() if k not in ("body_snippet",)},
        "tools_run": len(results),
        "hits": hits_summary,
        "tool_results": results,
    }
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\n  报告已保存: {report_path}")
    print(f"{'='*70}\n")


# ══════════════════════════════════════════════════════════════════
#  命令入口
# ══════════════════════════════════════════════════════════════════

def _parse_target(raw: str) -> tuple[str, str]:
    """URL 或裸域名 → (host, base_url)。不要用 lstrip('https://')，那是按字符集剥。"""
    s = (raw or "").strip()
    if "://" not in s:
        s = "https://" + s.lstrip("/")
    p = urlparse(s)
    host = (p.hostname or "").lower()
    if not host:
        raise SystemExit(f"[err] 无法解析目标: {raw}")
    netloc = f"{host}:{p.port}" if p.port else host
    scheme = p.scheme if p.scheme in ("http", "https") else "https"
    return host, f"{scheme}://{netloc}"


def _require_scope(domain: str) -> None:
    host = host_of(domain)
    if host and not in_scope(host):
        raise SystemExit(f"[scope] {host} 不在授权范围")


def cmd_plan(args: argparse.Namespace) -> int:
    domain, base_url = _parse_target(args.domain)
    _require_scope(domain)
    admin_url = args.admin or ""
    out_dir = _make_out_dir(args, domain)

    print(f"\n[*] 正在指纹识别: {domain} ...")
    fp = fingerprint(domain, base_url, admin_url)
    fp["case"] = (args.case or "").strip() or out_dir.name
    fp["has_browser_loot"] = bool(fp["case"] and case_has_loot(fp["case"]))
    fp["se_inject_ok"] = workspace_injected(ROOT)
    matched = match_rules(fp)
    print_plan(fp, matched, out_dir)

    # 保存指纹
    fp_path = out_dir / "fingerprint.json"
    fp_path.parent.mkdir(parents=True, exist_ok=True)
    fp_path.write_text(json.dumps(fp, ensure_ascii=False, indent=2))
    print(f"  指纹已保存: {fp_path}\n")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    domain, base_url = _parse_target(args.domain)
    _require_scope(domain)
    admin_url = args.admin or ""
    out_dir = _make_out_dir(args, domain)

    phases = None
    if args.phases:
        phases = [int(p) for p in args.phases.split(",")]

    print(f"\n[*] 正在指纹识别: {domain} ...")
    fp = fingerprint(domain, base_url, admin_url)
    fp["case"] = (args.case or "").strip() or out_dir.name
    fp["has_browser_loot"] = bool(fp["case"] and case_has_loot(fp["case"]))
    fp["se_inject_ok"] = workspace_injected(ROOT)
    matched = match_rules(fp)
    print_plan(fp, matched, out_dir)

    run_campaign(fp, matched, out_dir, phases=phases, dry_run=args.dry_run)
    return 0


def _make_out_dir(args: argparse.Namespace, domain: str) -> Path:
    if getattr(args, "case", None):
        out_dir = EXPORTS / args.case / "auto_campaign"
    else:
        safe_domain = re.sub(r"[^\w.-]", "_", domain)
        out_dir = EXPORTS / f"{safe_domain}_auto"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def main():
    ap = argparse.ArgumentParser(
        description="auto_campaign — 智能作战路由器（授权范围内）"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    # plan 命令
    p = sub.add_parser("plan", help="指纹识别 + 输出作战计划（不执行工具）")
    p.add_argument("-d", "--domain", required=True, help="目标域名或 URL")
    p.add_argument("--admin", default="", help="已知后台 URL（可选）")
    p.add_argument("--case", default="", help="案卷目录名（案卷/ 下）")
    p.set_defaults(func=cmd_plan)

    # run 命令
    p = sub.add_parser("run", help="指纹识别 + 自动执行所有匹配工具")
    p.add_argument("-d", "--domain", required=True, help="目标域名或 URL")
    p.add_argument("--admin", default="", help="已知后台 URL（可选）")
    p.add_argument("--phases", default="", help="只执行指定阶段，如 0,1,2（默认全部）")
    p.add_argument("--case", default="", help="案卷目录名")
    p.add_argument("--dry-run", action="store_true", help="只打印命令，不执行")
    p.set_defaults(func=cmd_run)

    args = ap.parse_args()
    sys.exit(args.func(args) or 0)


if __name__ == "__main__":
    main()
