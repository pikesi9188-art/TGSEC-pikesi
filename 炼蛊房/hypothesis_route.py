#!/usr/bin/env python3
"""假设作业信号 → 本库专卡 / 长文。ROUTES 表顺序先命中先赢，短英文按词边界。"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import sys

def _utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if reconf:
            try:
                reconf(encoding="utf-8")
            except Exception:
                pass

_utf8_stdio()

ROOT = Path(__file__).resolve().parents[1]


def _hypo_tech(name: str) -> str:
    """开源 NAMING.json 把假设长文改过挂号名就跟过去。"""
    p = ROOT / "NAMING.json"
    if not p.is_file():
        return name
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return str((data.get("hypothesis") or {}).get(name) or name)
    except Exception:
        return name


# 信号关键词 → (专卡, 长文文件名, 探针)
ROUTES: list[tuple[tuple[str, ...], str, str, str]] = [
    (("cookies.sqlite", "moz_cookies", "passwords.json", "fingerprint.json",
      "chrome.rar", "窃密包", "gaia accountid", "整包回放", "单包访问"),
     "credential-harvest", "forensic.md", "炼蛊房/browser_loot_triage.py"),
    (("se_inject", "助手注入器", "daaixianzun workstation", "大爱仙尊注入",
      "claude 拒答", "claude拒答", "codex 拒答", "codex拒答", "claude.md",
      "角色注入", "opus-injector", "究极角色注入器", "助手没身份",
      "部署 claude.md", "claude code 拒答"),
     "se-inject", "realworld-patterns.md", "炼蛊房/se_inject.py"),
    (("apiuserfenxiao", "get_fenxiao_db_data", "common_get_author_list",
      "thinkphp3.1", "chk_update", "save_agency_contract", "剪贴板劫持"),
     "tp3-fenxiao-api-pentest", "realworld-patterns.md",
     "炼蛊房/tp3_fenxiao_probe.py"),
    (("xxl-job", "xxljob", "glue_shell", "xxl-job-admin", "分布式任务调度"),
     "xxljob-admin-glue-chain", "器物谱.md", "炼蛊房/xxljob_admin_probe.py"),
    (("tg号码管理", "tg号码", "export/download", "phone_numbers"),
     "tg-number-admin-pentest", "realworld-patterns.md",
     "炼蛊房/tg_number_admin_probe.py"),
    (("goencrypt", "godecrypt", "main.wasm", "掩码 token", "掩码票",
      "taskprotocolrecovery", "clienter/pagelist"),
     "tg-cloud-panel", "realworld-patterns.md",
     "炼蛊房/tg_cloud_panel_probe.py"),
    (("任意验证码", "dummy-code", "updatewithdrawpassword", "resetpassword 任意"),
     "gambling-password-reset-ato", "realworld-patterns.md",
     "炼蛊房/ato_reset_withdraw_probe.py"),
    (("passkey", "webauthn", "fido2", "0-rtt", "early data", "rfc9700", "rfc 9700"),
     "identity-federation", "新印.md", "炼蛊房/jwt_gql_probe.py"),
    (("阿里云 ak", "阿里云ak", "accesskey", "ak-sk", "ltai", "oss ak",
      "sts 临时凭证", "sts临时凭证", "ram policy"),
     "credential-harvest", "cloud-cn.md", "炼蛊房/heap_cred_scan.py"),
    (("100.100.100.200", "云助手", "metadata.tencentyun", "openstack/latest/securitykey",
      "腾讯云", "华为云", "阿里云"),
     "cloud-metadata-harvesting", "cloud-cn.md", "炼蛊房/ssrf_probe.py"),
    (("若依", "ruoyi"),
     "ruoyi-fork-admin-pentest", "中原骨架.md", "炼蛊房/java_web_surface_probe.py"),
    (("通达oa", "通达", "泛微", "用友", "致远", "seeyon", "蓝凌", "万户", "nccloud"),
     "1day-nuclei-kit", "中原骨架.md",
     "炼蛊房/java_web_surface_probe.py"),
    (("actuator", "heapdump", "spring gateway", "gateway/routes",
      "heap_cred_scan", "蓝鸟猎手"),
     "spring-actuator-cloud-takeover", "中原骨架.md",
     "炼蛊房/actuator_probe.py"),
    (("doris", "starrocks", "9030", "8030", "default_cluster"),
     "doris-unauth", "database.md", "炼蛊房/doris_probe.py"),
    (("nacos", "/v3/auth/user", "nacos-authscope", "鉴权作用域"),
     "nacos-authscope-unauth", "器物谱.md",
     "炼蛊房/nacos_authscope_poc.py"),
    (("cyberbiz", "cyberbiz.co", "cyberbiz.io", "cybassets.com",
      "cyberbiz_settings", "board_comments_token"),
     "cyberbiz-saas-pentest", "realworld-patterns.md",
     "炼蛊房/strike_probe.py"),
    (("shopline", "shopline.com", "myshopline", "config_data 泄露"),
     "shopline-saas-pentest", "realworld-patterns.md",
     "炼蛊房/strike_probe.py"),
    (("getgoogleauthadmin", "多租户代理", "java multitenant agent",
      "login/{userid}", "oss policy ak"),
     "java-multitenant-agent-takeover", "realworld-patterns.md",
     "炼蛊房/java_agent_platform_probe.py"),
    (("ashx handler", "dotnet ashx", ".ashx idor", "fundaccount",
      "金融 idor", "投顾平台"),
     "dotnet-ashx-fintech-idor", "realworld-patterns.md",
     "炼蛊房/ashx_fintech_idor_probe.py"),
    (("微信小程序", "wxapkg", "unveilr", "wx.request"),
     "wxmini-static-audit", "reversing.md",
     "炼蛊房/wxmini_static_probe.py"),
    (("shop_hq", "fastadmin shop", "shop_keeplogin", "gt filter", "跨商户"),
     "fastadmin-shop-tenant-bola", "realworld-patterns.md",
     "炼蛊房/fastadmin_shop_tenant_probe.py"),
    (("tgcloud_pc", "系统选择", "tg-cloud-control"),
     "tg-cloud-control-pentest", "telegram.md",
     "炼蛊房/tg_cloud_panel_probe.py"),
    (("芋道", "sk_encrypt", "app-api", "yudao", "x-ca-token"),
     "yudao-appapi-pentest", "realworld-patterns.md",
     "炼蛊房/yudao_appapi_probe.py"),
    (("dujiao-next", "1元购", "use_balance", "dj.svg"),
     "dujiao-next-1yuan-pay", "realworld-patterns.md",
     "炼蛊房/pay_matrix.py"),
    (("dujiaoka", "独角发卡", "faka-card"),
     "faka-card-shop-pentest", "realworld-patterns.md",
     "炼蛊房/pay_matrix.py"),
    (("litellm", "badhost", "/spend/keys"),
     "litellm-badhost", "ai-llm.md", "炼蛊房/litellm_badhost.py"),
    (("qzino", "赌 bot", "赌bot", "telegram-tma-gambling", "tma gambling",
      "tma 博彩", "tma赌", "telegram mini app", "telegram tma"),
     "telegram-tma-gambling", "telegram.md",
     "炼蛊房/yudao_appapi_probe.py"),
    (("tg云控", "tg 云控", "tdata", "session 导出", "fernet", "sticker"),
     "tg-cloud-panel", "realworld-patterns.md", "炼蛊房/tg_cloud_panel_probe.py"),
    (("acg-faka", "异次元发卡", "acg发卡", "查单拖卡"),
     "acg-faka", "realworld-patterns.md", "炼蛊房/pay_matrix.py"),
    (("支付回调", "假支付", "验签绕过"),
     "payment-callback-forgery", "realworld-patterns.md", "炼蛊房/pay_matrix.py"),
    (("cognito", "identitypoolid"),
     "cognito-unauth-s3-chain", "realworld-patterns.md", "炼蛊房/cognito_s3_probe.py"),
    (("em5", "libmagic.so", "functag", "meshow/entrance", "getuploadkey",
      "ossststoken", "ukktv8", "kktv", "kk直播", "melot", "美秀",
      "cc16be4b", "apk jni 签名", "jni oss sts"),
     "apk-jni-sign-oss-sts", "realworld-patterns.md",
     "炼蛊房/apk_jni_oss_sts_probe.py"),
    (("argocd", "harbor", "portainer", "rabbitmq", "erlang cookie"),
     "1day-nuclei-kit", "器物谱.md", "炼蛊房/nday_route.py"),
    (("kafka", "memcache", "memcached", "11211"),
     "database-security", "database.md", "炼蛊房/middleware_unauth_probe.py"),
    (("winrm", "snmp", "vnc"),
     "ad-windows-router", "network-services.md", "炼蛊房/middleware_unauth_probe.py"),
    (("白盒", "源码审计", "sbom", "slsa"),
     "deepaudit-code-audit", "code-audit.md", "tools/deepaudit/bin/da_pipeline.py"),
    (("usdt approve", "链上测绘", "伪充值"),
     "usdt-deposit-attribution-hijack", "realworld-patterns.md",
     "炼蛊房/usdt_attr_hijack.py"),
    (("缓存投毒", "x-forwarded-host", "unkeyed"),
     "web-cache-poisoning", "web.md", "炼蛊房/cache_poison_probe.py"),
    (("wordpress", "wp-login", "wp-json", "xmlrpc"),
     "wordpress-attack-router", "web.md", "炼蛊房/wp_plugin_unauth_probe.py"),
    (("pwnkit", "cve-2021-4034", "baron samedit", "cve-2021-3156",
      "overlayfs", "cve-2021-3493", "linpeas", "suid enum"),
     "linux-post-exploit", "pwn.md", "炼蛊房/linux_lpe_checker.py"),
    (("printspoofer", "godpotato", "fodhelper", "alwaysinstallelevated",
      "seimpersonate", "unquoted service"),
     "windows-lpe", "ad.md", "炼蛊房/windows_lpe_checker.py"),
    (("fastjson", "fastjson exploitation", "fastjson 利用", "autotype绕过",
      "fastjson2 绕过", "fastjson2", "fastjson rce",
      "cve-2026-16723", "qvd-2026-45876", "bcel classloader",
      "jdbcrowsetimpl", "autotype"),
     "fastjson-exploitation", "中原骨架.md", "炼蛊房/fastjson_probe.py"),
    (("shiro", "shiro exploitation", "shiro 利用", "shiro-550", "shiro-721",
      "cve-2026-23901", "cve-2026-56091", "padding oracle attack",
      "remembermecookie", "rememberme", "shiro key", "shiro漏洞", "shiro利用",
      "shiro rce", "shiro反序列化"),
     "shiro-exploitation", "中原骨架.md", "炼蛊房/java_web_surface_probe.py"),
    (("spring4shell", "spring exploitation", "spring 利用", "spring ai",
      "cve-2026-22738", "cve-2022-22965",
      "spel注入", "spel rce", "spring内存马", "spring security绕过",
      "spring rce"),
     "spring-exploitation", "中原骨架.md", "炼蛊房/actuator_probe.py"),
    (("log4shell", "log4j", "cve-2021-44228", "log4shell exploitation",
      "log4shell 利用", "jndi注入", "log4j rce", "rogue jndi",
      "jndi:", "log4j2"),
     "log4shell-exploitation", "中原骨架.md", "炼蛊房/nday_route.py"),
    (("ci/cd攻击", "cicd攻击", "供应链攻击", "github actions注入",
      "pipeline injection", "cve-2025-30066", "依赖混淆"),
     "ci-cd-attack-testing", "器物谱.md", "炼蛊房/nday_route.py"),
    (("信息收集方法论", "osint 方法论", "攻击面发现", "子域接管"),
     "information-gathering", "recon.md", "炼蛊房/origin_recon.py"),
    (("内网渗透手册", "内网全链", "mimikatz", "ntds.dit", "lsass dump"),
     "intranet-penetration-testing", "ad.md", "炼蛊房/ad_surface_check.py"),
    (("xxe exploitation", "xxe 利用", "cve-2025-66516", "tika xxe",
      "xinclude", "blind xxe"),
     "xxe-injection-testing", "web.md", "炼蛊房/tpl_inject_probe.py"),
    (("s2-062", "struts2", "s2-045", "s2-048", "ognl注入"),
     "1day-nuclei-kit", "中原骨架.md", "炼蛊房/nday_route.py"),
    (("redis 未授权", "redis未授权", ":6379", "redis-cli", "config set dir"),
     "1day-nuclei-kit", "中原骨架.md", "炼蛊房/redis_unauth_probe.py"),
    (("langflow", "validate/code", "auto_login", "langflow rce"),
     "langflow-unauth-rce", "器物谱.md", "炼蛊房/langflow_probe.py"),
    (("flowise", "x-request-from", "nodevm", "flowise rce"),
     "flowise-internal-header-rce", "器物谱.md", "炼蛊房/flowise_probe.py"),
    (("src 挖洞", "src挖洞", "bug bounty", "漏洞赏金", "hackerone", "众测",
      "bug赏金", "挖洞", "src hunter"),
     "72stack-sec", "web.md", "炼蛊房/h1_search.py"),
    (("gopher redis", "ssrf redis", "into outfile", "gopher://"),
     "ssrf-testing", "web.md", "炼蛊房/ssrf_probe.py"),
    (("strike_probe", "黑盒突击", "s1攻击面", "s1-s8", "侦察后突击",
      "admin12345", "总后台短字典"),
     "strike-probe", "web.md", "炼蛊房/strike_probe.py"),
    (("x-nextjs", "next-action", "/_next/image", "__next_data__", "next.js",
      "react2shell", "cve-2025-55182", "cve-2026-75604", "cve-2025-29927",
      "flight协议", "rsc rce", "avif rce", "image optimization rce"),
     "nextjs-ssr-hunt", "web.md", "炼蛊房/nextjs_surface_probe.py"),
    (("__viewstate", "elmah.axd", "telerik.web.ui", "x-aspnet-version"),
     "aspnet-viewstate-hunt", "web.md", "炼蛊房/aspnet_surface_probe.py"),
    (("grpc-status", ":50051", "grpcurl", "serverreflection", "grpc-gateway"),
     "grpc-reflection-hunt", "web.md", "炼蛊房/grpc_surface_probe.py"),
    (("+cscoe+", "globalprotect", "dana-na", "svpncookie", "anyconnect ssl vpn"),
     "sslvpn-perimeter-fingerprint", "network-services.md",
     "炼蛊房/sslvpn_surface_probe.py"),
    (("xss", "sqli", "ssrf", "401", "403",
      "走私", "websocket", "负价格", "0元购", "业务逻辑"),
     "web-vuln-router", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("真假分离", "诱饵面", "矛盾侦察", "假面板", "真后台锁定"),
     "case-triage", "web.md", "炼蛊房/case_triage.py"),
    (("反逻辑", "anti-logic", "反目标", "反路径", "反协议",
      "反顺序", "反身份", "反入口", "a1-a6", "六轴反逻辑",
      "对手心理模型", "反逻辑刀", "qr upload换图"),
     "case-triage", "web.md", "炼蛊房/case_triage.py"),
    (("身份层roi", "算力别砸错", "业务系统不是cms", "crown surface",
      "crown面", "收款地址面"),
     "case-triage", "web.md", "炼蛊房/case_triage.py"),
    (("src进站", "src 进站", "进站四件套", "打穿短表", "一种子闭环",
      "三问门槛", "认什么打哪", "说清这摊", "js抽钥匙",
      "差分面四件套", "深挖优先闸", "锁面自由跳"),
     "72stack-sec", "web.md", "炼蛊房/h1_search.py"),
    (("证书san", "san拓线", "证书资产发现", "dev子域", "san字段"),
     "cdn-origin-tracing", "recon.md", "炼蛊房/cdn_tracer.py"),
    (("rce可行性分级", "攻击面排序", "多面盘点", "可行性矩阵"),
     "strike-probe", "web.md", "炼蛊房/strike_probe.py"),
    (("idor深挖后台", "ashx投顾后台", "nlpquant", "vol.core"),
     "dotnet-ashx-fintech-idor", "realworld-patterns.md",
     "炼蛊房/ashx_fintech_idor_probe.py"),
    (("组件情报搜索", "联网情报7步", "component-vuln-intel",
      "组件版本情报"),
     "information-gathering", "recon.md", "炼蛊房/origin_recon.py"),
    (("cdn", "源站", "子域", "fofa", "crt.sh", "侦察",
      "cdn溯源", "找真实ip", "绕过cdn", "源站ip", "origin ip",
      "cdn bypass", "cloudflare绕过", "dns rebinding", "贝叶斯评分",
      "cdn_tracer", "cdn_ranges", "ja3", "ja4"),
     "cdn-origin-tracing", "recon.md", "炼蛊房/cdn_tracer.py"),
    (("k8s", "kubernetes", "imds", "169.254.169.254", "云元数据"),
     "cloud-metadata-harvesting", "cloud.md", "炼蛊房/ssrf_probe.py"),
    (("mysql", "postgres", "mongodb", "数据库"),
     "database-security", "database.md", "炼蛊房/middleware_unauth_probe.py"),
    (("外挂", "游戏破解", "客户端破解", "反作弊", "il2cpp", "dump.cs",
      "cheat engine", "ce修改器", "内存挂", "封包挂", "unity3d",
      "gameassembly", "easyanticheat", "battleye"),
     "client-crack-cheat", "reversing.md", "炼蛊房/client_crack_cheat_probe.py"),
    (("apk", "ipa", "jadx", "逆向", "固件", "脱壳", "dobby"),
     "reverse-engineering", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    (("域控", "kerberos", "bloodhound", "active directory", "内网域",
      "petitpotam", "kerberoasting"),
     "ad-windows-router", "ad.md", "炼蛊房/ad_surface_check.py"),
    (("免杀", "amsi", "etw", "edr", "cobalt", "byovd", "dkom", "syswhispers",
      "写马", "载荷锻造"),
     "edr-bypass-re", "evasion.md", "炼蛊房/payload_forge.py"),
    (("代理商", "affiliate", "agent-probe"),
     "agent-probe", "web.md", "炼蛊房/agent_probe.py"),
    (("llm", "prompt 注入", "prompt注入", "owasp llm",
      "nanogcg", "garak", "mcp tool", "rag poisoning"),
     "llm-security", "ai-llm.md", "炼蛊房/llm_surface_probe.py"),
    (("telegram bot webhook", "tg bot webhook", "bot token hijack"),
     "tg-cloud-panel", "telegram.md", "炼蛊房/tg_cloud_panel_probe.py"),
    (("爆破", "喷洒", "弱口"),
     "auth-brute", "cracking.md", "炼蛊房/auth_brute_probe.py"),
    (("登录注入", "登录旁路", "认证绕过", "admin'--", "authentication bypass"),
     "authbypass-authentication-flaws", "web.md", "炼蛊房/auth_brute_probe.py"),
    (("quake", "360quake"),
     "quake", "recon.md", "炼蛊房/origin_recon.py"),
    (("ret2libc", "one_gadget", "kernel pwn", "栈溢", "格式串", "tcache", "fsop"),
     "binary-pwn", "pwn.md", "tools/pwn-kit/pwn_triage.py"),
    (("rsa", "coppersmith", "格密码", "长度扩展", "古典密码"),
     "crypto-toolkit", "crypto-attacks.md", "炼蛊房/crypto_decode.py"),
    (("智能合约", "defi", "web3", "闪贷", "重入"),
     "defi-attack-patterns", "blockchain.md", "炼蛊房/css_query.py"),
    (("volatility", "pcap", "隐写", "zsteg", "内存取证"),
     "digital-forensics", "forensic.md", "炼蛊房/host_ir_check.py"),
    (("隧道", "chisel", "ligolo", "frp", "meterpreter", "autoroute"),
     "internal-tunnel", "ad.md", "炼蛊房/ad_surface_check.py"),
    (("ledger.jsonl", "观察复现影响", "假设账本"),
     "hypothesis-ledger", "web.md", "炼蛊房/case_ledger.py"),
    (("druid", "druid/index.html", "druid监控"),
     "1day-nuclei-kit", "中原骨架.md", "炼蛊房/java_web_surface_probe.py"),
    (("jenkins", "/script", "groovy console", "jenkins-cli"),
     "1day-nuclei-kit", "中原骨架.md", "炼蛊房/java_web_surface_probe.py"),
    (("grafana", "/api/datasources", "grafana admin"),
     "1day-nuclei-kit", "中原骨架.md", "炼蛊房/java_web_surface_probe.py"),
    (("metabase", "/api/setup", "cve-2023-38646", "metabase rce"),
     "1day-nuclei-kit", "中原骨架.md", "炼蛊房/nday_route.py"),
    (("thinkphp", "tp5 rce", "_method", "filter[]"),
     "1day-nuclei-kit", "中原骨架.md", "炼蛊房/nday_route.py"),
    (("宝塔", "bt-panel", "bt.cn", "phpmyadmin"),
     "1day-nuclei-kit", "中原骨架.md", "炼蛊房/strike_probe.py"),
    (("laravel", "artisan", "laravel env", "app_key"),
     "1day-nuclei-kit", "中原骨架.md", "炼蛊房/nday_route.py"),
    (("redis", "6379", "redis未授权", "redis-cli"),
     "1day-nuclei-kit", "中原骨架.md", "炼蛊房/middleware_unauth_probe.py"),
    (("nginx misconfig", "alias 穿越", "off-by-slash", "add_header 覆盖"),
     "1day-nuclei-kit", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("grant_type=password", "oauth2 password", "password grant"),
     "oauth2-password-grant-login-testing", "web.md", "炼蛊房/auth_brute_probe.py"),
    (("oauth2", "sso 越权", "authorization_code", "openid-configuration"),
     "oauth-oidc-flow", "web.md", "炼蛊房/oauth_oidc_surface_probe.py"),
    (("firebase", "google-services.json", "realtime db"),
     "cloud-metadata-harvesting", "cloud.md", "炼蛊房/ssrf_probe.py"),
    (("supabase", "rls", "row level security"),
     "database-security", "database.md", "炼蛊房/middleware_unauth_probe.py"),
    (("竞态", "race condition", "toctou", "并发请求"),
     "race-condition", "web.md", "炼蛊房/race_probe.py"),
    (("nosql注入", "nosql injection", "$gt", "$regex"),
     "nosql-injection", "web.md", "炼蛊房/param_abuse_probe.py"),
    (("2fa绕过", "2fa bypass", "otp爆破", "totp复用"),
     "authbypass-authentication-flaws", "web.md", "炼蛊房/auth_brute_probe.py"),
    (("原型链污染", "prototype pollution", "__proto__"),
     "prototype-pollution", "web.md", "炼蛊房/param_abuse_probe.py"),
    (("文件上传", "webshell", "双扩展名", "content-type 绕过"),
     "web-vuln-router", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("ssti", "模板注入", "{{7*7}}", "jinja2 注入", "twig", "freemarker"),
     "ssti-exploit", "web.md", "炼蛊房/tpl_inject_probe.py"),
    (("反序列化", "ysoserial", "unserialize", "gadget chain"),
     "web-vuln-router", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("idor", "水平越权", "userid=", "orderid=", "insecure direct"),
     "web-vuln-router", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("社工", "钓鱼", "quishing", "水坑"),
     "autonomous-social-engagement", "social-engineering.md",
     "炼蛊房/social_engineer_agent.py"),
    (("sleep obfuscation", "ekko", "foliage", "hypnus",
      "beacon 加密休眠", "内存加密休眠"),
     "edr-bypass-re", "evasion.md", "炼蛊房/css_query.py"),
    (("间接系统调用", "indirect syscall", "tartarus gate", "halos gate",
      "mockingjay", "recycledgate", "syswhispers"),
     "edr-bypass-re", "evasion.md", "炼蛊房/css_query.py"),
    (("module stomping", "模块踩踏", "map injection", "映射注入",
      "early bird", "apc注入", "硬件断点注入"),
     "edr-bypass-re", "evasion.md", "炼蛊房/css_query.py"),
    (("白驱动", "byovd", "loldrivers", "minifilter致盲",
      "回调致盲", "驱动致盲edr"),
     "edr-bypass-re", "evasion.md", "炼蛊房/css_query.py"),
    (("device code phishing", "device code", "evilginx", "mfa fatigue",
      "oauth device", "device授权", "prt窃取"),
     "2fa-bypass", "web.md", "炼蛊房/auth_brute_probe.py"),
    (("容器逃逸", "docker逃逸", "runc逃逸", "ebpf逃逸",
      "cdk escape", "cgroup逃逸", "特权容器"),
     "container-security-testing", "cloud.md",
     "炼蛊房/middleware_unauth_probe.py"),
    (("ebpf rootkit", "ebpf verifier", "xdp", "bpf map",
      "linkpro", "tetragon"),
     "container-security-testing", "cloud.md",
     "炼蛊房/middleware_unauth_probe.py"),
    (("adcs", "esc1", "esc8", "esc9", "esc13", "esc15",
      "certipy", "证书服务", "shadow credentials", "pkinit"),
     "adcs-pentest", "ad.md", "炼蛊房/ad_surface_check.py"),
    (("cobalt strike", "beacon修改", "c2定制", "sliver",
      "brute ratel", "mythic", "havoc"),
     "edr-bypass-re", "evasion.md", "炼蛊房/css_query.py"),
    (("deepfake", "ai钓鱼", "lamehug", "sesamop", "shadowai",
      "ai恶意代码", "llm c2", "ai基础设施攻击"),
     "llm-security", "ai-llm.md", "炼蛊房/llm_surface_probe.py"),
    (("serverless攻击", "lambda注入", "函数注入", "managed identity"),
     "cloud-metadata-harvesting", "cloud.md", "炼蛊房/ssrf_probe.py"),
    (("包网", "bc站", "bc攻击", "cp站", "彩票站"),
     "strike-probe", "web.md", "炼蛊房/strike_probe.py"),
    (("chromekatz", "lazagne", "finalshelldecrypt", "dpapi",
      "browserpivot", "影子文件", "rdpthief"),
     "credential-harvest", "forensic.md",
     "炼蛊房/browser_loot_triage.py"),
    (("rlo", "lnk钓鱼", "chm", "html smuggling",
      "spf绕过", "恶意载荷制作"),
     "autonomous-social-engagement", "social-engineering.md",
     "炼蛊房/social_engineer_agent.py"),
    (("ntlm relay", "petitpotam", "printerbug", "dfscoerc",
      "coercer", "ntlm中继"),
     "ad-windows-router", "ad.md", "炼蛊房/ad_surface_check.py"),
    (("zerologon", "cve-2020-1472", "nopac", "cve-2021-42287",
      "printnightmare", "ms14-068", "pac伪造"),
     "ad-windows-router", "ad.md", "炼蛊房/ad_surface_check.py"),
    (("nas攻击", "exchange攻击", "proxylogon", "proxyshell",
      "vcenter攻击", "堡垒机攻击", "jumpserver"),
     "ad-windows-router", "ad.md", "炼蛊房/ad_surface_check.py"),
    (("wmiexec", "scshell", "dcomhijack", "rpc横向", "no445",
      "rpc2socks", "横向移动"),
     "ad-windows-router", "ad.md", "炼蛊房/ad_surface_check.py"),
    (("lotl", "living off the land", "无文件攻击", "msbuild",
      "certutil下载", "mshta", "bitsadmin"),
     "edr-bypass-re", "evasion.md", "炼蛊房/css_query.py"),
    # ── 新增精准路由 Batch 1: Web 漏洞类型 (28) ──
    (("点击劫持", "clickjacking", "x-frame-options绕过"),
     "clickjacking", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("crlf注入", "crlf injection", "response splitting"),
     "crlf-injection", "web.md", "炼蛊房/param_abuse_probe.py"),
    (("cors利用", "cors misconfiguration", "origin反射"),
     "cors-exploitation", "web.md", "炼蛊房/cors_csrf_probe.py"),
    (("csrf测试", "csrf bypass", "samesite绕过"),
     "csrf-testing", "web.md", "炼蛊房/cors_csrf_probe.py"),
    (("csv注入", "公式注入", "excel injection"),
     "csv-formula-injection", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("命令注入测试", "os command injection", "命令执行测试"),
     "command-injection-testing", "web.md", "炼蛊房/tpl_inject_probe.py"),
    (("xss payload", "dom型xss", "stored xss测试"),
     "xss-testing", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("sql注入测试", "union注入", "盲注测试", "时间盲注"),
     "sql-injection-testing", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("xxe测试", "xml entity test", "xxe poc"),
     "xxe-injection-testing", "web.md", "炼蛊房/tpl_inject_probe.py"),
    (("request smuggling poc", "cl.te", "te.cl", "h2.te"),
     "http-request-smuggling", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("重定向链", "redirect chain", "open redirect chain"),
     "open-redirect-chain", "web.md", "炼蛊房/open_redirect_surface_probe.py"),
    (("路径穿越", "目录遍历", "path traversal", "..%2f"),
     "core-web-vuln-kit", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("文件包含漏洞", "lfi exploit", "远程文件包含", "php://filter"),
     "lfi-rfi-exploit", "web.md", "炼蛊房/tpl_inject_probe.py"),
    (("参数污染", "hpp attack", "parameter pollution"),
     "http-parameter-pollution", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("host头攻击", "host header injection", "host头注入"),
     "http-host-header-attacks", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("缓存欺骗", "cache deception", "web cache deception"),
     "web-cache-poisoning", "web.md", "炼蛊房/cache_poison_probe.py"),
    (("表达式注入", "el injection", "表达式语言注入"),
     "expression-language-injection", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("xpath注入", "xpath injection", "xpath漏洞"),
     "xpath-injection-testing", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("xslt注入", "xslt injection", "xsl transform"),
     "xslt-injection", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("ldap注入", "ldap injection", "ldap绕过"),
     "ldap-injection-testing", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("dangling markup", "悬挂标记", "html悬挂注入"),
     "dangling-markup-injection", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("nosql注入漏洞", "mongodb注入漏洞", "$where注入"),
     "nosql-injection", "web.md", "炼蛊房/param_abuse_probe.py"),
    (("csp绕过", "csp bypass", "content-security-policy绕过"),
     "csp-bypass-advanced", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("邮件头注入", "email injection", "smtp header injection"),
     "email-header-injection", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("ssti利用链", "模板注入rce", "模板引擎rce"),
     "ssti-exploit", "web.md", "炼蛊房/rce_forge.py"),
    (("rce锻造", "一键rce", "表达式rce", "ssti落马"),
     "ssti-exploit", "web.md", "炼蛊房/rce_forge.py"),
    (("抢rce", "getshell", "rce百科", "rce矩阵", "远程代码执行", "拿shell"),
     "rce-encyclopedia", "web.md", "炼蛊房/rce_family_route.py"),
    (("天盾", "fndata", "nuitka", "pyinstaller破解", "卡密验证",
      "假认证服务器", "checklicense", "keygen", "网络验证卡密"),
     "net-license-crack", "reversing.md", "炼蛊房/net_license_probe.py"),
    (("技能别名", "别名对不上", "有没有某张卡"),
     "se-skill-alias", "web.md", "炼蛊房/se_skill_alias.py"),
    (("助手拒答回退", "助手没身份回退"),
     "se-inject", "realworld-patterns.md", "炼蛊房/se_inject.py"),
    (("勒索演练", "ransomware-builder", "案卷加密演练"),
     "authorized-ransom-lab", "evasion.md", "炼蛊房/ransom_lab.py"),
    (("僵尸网", "botnet-dev", "c2舰队", "授权botnet"),
     "authorized-botnet-lab", "evasion.md", "炼蛊房/botnet_lab.py"),
    (("bootkit", "启动链审计", "mbr感染", "uefi植入"),
     "authorized-bootkit-audit", "evasion.md", "炼蛊房/bootkit_audit.py"),
    (("ddos演练", "反射器探测", "syn洪水", "ddos-toolkit"),
     "authorized-ddos-surface", "evasion.md", "炼蛊房/ddos_surface_probe.py"),
    (("altcha", "rsa登录", "jsencrypt", "前端pow"),
     "frontend-auth-bypass", "web.md", "炼蛊房/frontend_auth_probe.py"),
    (("弱随机", "lcg反推", "prng助记词", "弱rng"),
     "weak-rng-wallet", "reversing.md", "炼蛊房/weak_rng_probe.py"),
    (("nuitka解包", "pyinstaller解包", "pyz-00"),
     "python-pack-reverse", "reversing.md", "炼蛊房/py_pack_reverse.py"),
    (("打印机pjl", "@pjl info", "ipp 631"),
     "printer-pjl-surface", "器物谱.md", "炼蛊房/printer_pjl_probe.py"),
    (("sip options", "voip 5060", "sip指纹"),
     "sip-surface", "network-services.md", "炼蛊房/sip_surface_probe.py"),
    (("dns外带", "oob rce", "无回显外带"),
     "oob-exfil-kit", "web.md", "炼蛊房/oob_exfil.py"),
    (("什么哈希", "hash identifier", "bcrypt识别"),
     "hash-identify", "web.md", "炼蛊房/hash_identify.py"),
    (("改密旧jwt", "jwt无状态", "票还在"),
     "jwt-stateless-persist", "新印.md", "炼蛊房/jwt_persist_probe.py"),
    (("lsb隐写", "png lsb"),
     "steganography-techniques", "forensic.md", "炼蛊房/stego_lsb_probe.py"),
    (("上传rce", "文件上传绕过", "upload bypass"),
     "file-upload-testing", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("graphql越权", "introspection query", "__schema查询"),
     "graphql-pentest", "web.md", "炼蛊房/gql_authz_probe.py"),
    (("idor测试", "越权测试用例", "对象引用测试"),
     "idor-testing", "web.md", "炼蛊房/core_web_surface_probe.py"),
    # ── Batch 2: Auth/Authz (12) ──
    (("ato链", "账户接管链", "account takeover chain"),
     "account-takeover-chain", "web.md", "炼蛊房/auth_brute_probe.py"),
    (("403 bypass技巧", "401 bypass技巧", "状态码绕过"),
     "401-403-bypass-techniques", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("api越权测试", "bola漏洞", "broken authorization"),
     "rbac-bypass-authz", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("jwt绕过", "jwt伪造", "jwk注入", "jwt none算法"),
     "jwt-bypass-pentest", "web.md", "炼蛊房/jwt_forge_probe.py"),
    (("oauth漏洞", "oidc漏洞", "redirect_uri劫持"),
     "oauth-oidc-flow", "web.md", "炼蛊房/oauth_oidc_surface_probe.py"),
    (("ssi注入", "esi注入", "server-side include", "<!--#echo"),
     "ssi-esi-injection", "web.md", "炼蛊房/ssi_esi_probe.py"),
    (("webdav put", "propfind", "trace method", "http方法面"),
     "http-method-webdav", "web.md", "炼蛊房/http_method_surface_probe.py"),
    (("rbac绕过", "角色提权", "权限绕过", "method override绕过"),
     "rbac-bypass-authz", "web.md", "炼蛊房/auth_brute_probe.py"),
    (("批量赋值", "mass assignment", "属性注入"),
     "mass-assignment", "web.md", "炼蛊房/param_abuse_probe.py"),
    (("类型混淆", "type juggling", "php弱比较", "0e hash"),
     "type-juggling", "web.md", "炼蛊房/param_abuse_probe.py"),
    (("saml攻击", "saml assertion伪造", "saml sso绕过"),
     "identity-federation", "web.md", "炼蛊房/auth_brute_probe.py"),
    (("重置token泄露", "密码重置token", "reset token外泄"),
     "reset-token-surface", "web.md", "炼蛊房/auth_brute_probe.py"),
    (("api签名绕过", "签名伪造", "hmac绕过", "api sign bypass"),
     "api-security-testing", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("jwt滥用", "jwt abuse", "api认证漏洞"),
     "api-security-testing", "web.md", "炼蛊房/jwt_gql_probe.py"),
    # ── Batch 3: Business Logic (7) ──
    (("竞态漏洞利用", "race exploit", "limit-overrun", "并发漏洞"),
     "race-condition", "web.md", "炼蛊房/race_probe.py"),
    (("业务逻辑测试", "逻辑漏洞测试", "business logic test"),
     "business-logic-testing", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("支付逻辑漏洞", "金额篡改", "支付业务逻辑"),
     "business-logic-payment", "web.md", "炼蛊房/pay_matrix.py"),
    (("客户端跳过", "前端绕过验证", "verified绕过"),
     "client-state-skip", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("电商逻辑漏洞", "购物车漏洞", "优惠券绕过"),
     "e-commerce-business-logic", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("免费领取绕过", "0元领取漏洞", "会员绕过领取"),
     "free-package-claim-bypass", "web.md", "炼蛊房/pay_matrix.py"),
    (("资金边缘越权", "wallet_id越权", "展示层地址", "幽灵单"),
     "fund-edge-ops", "realworld-patterns.md", "炼蛊房/pay_matrix.py"),
    # ── Batch 4: Mobile (10) ──
    (("ios渗透", "objection hook", "keychain dump", "ios app测试"),
     "ios-pentest", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    (("android渗透", "android pentest", "组件导出漏洞"),
     "apk-recon", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    (("apk情报提取", "apk recon", "apk密钥提取"),
     "apk-recon", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    (("apk反编译", "jadx分析", "apk逆向分析"),
     "apk-reverse", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    (("移动安全测试", "mobile pentest", "移动app渗透"),
     "mobile-app-security-testing", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    (("移动硬编码密钥", "apk aes key", "ipa硬编码"),
     "mobile-hardcoded-key-decrypt", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    (("ssl pinning绕过", "证书固定绕过", "ssl pin bypass"),
     "mobile-app-security-testing", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    (("政务小程序", "wepolice", "sm2国密", "粤居码", "rkbm"),
     "gov-wxmini-audit", "reversing.md", "炼蛊房/wxmini_static_probe.py"),
    (("mac wxapkg解密", "v1mmwx", "mac微信小程序"),
     "wxapkg-mac-decrypt", "reversing.md", "炼蛊房/wxmini_static_probe.py"),
    (("deeplink漏洞", "jsbridge劫持", "nanohttpd", "webview file"),
     "webview-deeplink-bridge", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    # ── Batch 5: Cloud/Container (6) ──
    (("k8s渗透", "kubernetes pentest", "pod逃逸"),
     "cloud-k8s", "cloud.md", "炼蛊房/ssrf_probe.py"),
    (("云安全审计", "cloud security audit", "云配置审计"),
     "cloud-security-audit", "cloud.md", "炼蛊房/ssrf_probe.py"),
    (("aws凭据利用", "aws credential leak", "aws key泄露"),
     "cloud-metadata-harvesting", "cloud-cn.md", "炼蛊房/heap_cred_scan.py"),
    (("容器安全测试", "docker安全审计", "dockerfile审计"),
     "container-security-testing", "cloud.md", "炼蛊房/middleware_unauth_probe.py"),
    (("firebase扫描", "firebase apk", "firebase未授权"),
     "firebase-apk-scanner", "cloud.md", "炼蛊房/ssrf_probe.py"),
    (("supabase渗透", "rls规则绕过", "supabase rls pentest"),
     "supabase-rls-pentest", "database.md", "炼蛊房/middleware_unauth_probe.py"),
    # ── Batch 6: Products/Infra (26) ──
    (("宝塔面板渗透", "bt-panel pentest", "宝塔后台漏洞"),
     "bt-panel-pentest", "中原骨架.md", "炼蛊房/strike_probe.py"),
    (("彩虹易支付", "epay后台", "易支付管理"),
     "epay-admin-pentest", "realworld-patterns.md", "炼蛊房/pay_matrix.py"),
    (("laravel渗透", "laravel漏洞利用", "laravel debug"),
     "laravel-pentest", "中原骨架.md", "炼蛊房/nday_route.py"),
    (("laravel api探测", "laravel auth probe"),
     "laravel-api-auth-probing", "中原骨架.md", "炼蛊房/nday_route.py"),
    (("nginx错误配置", "nginx alias穿越", "nginx off-by-slash"),
     "nginx-misconfig", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("nginx-rift", "cve-2026-42945", "nginx堆溢出"),
     "nginx-rift-cve-2026-42945", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("sharepoint未授权", "/_layouts/15/", "cve-2024-38094"),
     "sharepoint-unauth-rce", "web.md", "炼蛊房/nday_route.py"),
    (("teamcity漏洞", "/createtoken", "cve-2026-63077"),
     "teamcity-rce-supply-chain", "器物谱.md", "炼蛊房/nday_route.py"),
    (("websocket消息注入", "ws越权", "websocket hijack"),
     "websocket-pentest", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("gitea rce", "gitea diffpatch", "cve-2026-60004"),
     "gitea-diffpatch-rce", "器物谱.md", "炼蛊房/nday_route.py"),
    (("gitlab未授权", "gitlab graphql unauth"),
     "gitlab-graphql-unauth", "器物谱.md", "炼蛊房/nday_route.py"),
    (("mlflow ssrf", "mlflow webhook", "cve-2026-64849"),
     "mlflow-ssrf-webhook", "器物谱.md", "炼蛊房/nday_route.py"),
    (("zimbra rce", "cve-2026-73570", "zimbra漏洞"),
     "zimbra-snmp-rce", "器物谱.md", "炼蛊房/nday_route.py"),
    (("icecoder rce", "terminal-xhr", "cve-2026-63722"),
     "icecoder-unauth-rce", "器物谱.md", "炼蛊房/nday_route.py"),
    (("jetengine ssti", "cve-2026-66613", "jet-engine unauth"),
     "jetengine-unauth-rce", "web.md", "炼蛊房/nday_route.py"),
    (("owncloud漏洞", "cve-2023-49105", "webdav presign"),
     "owncloud-webdav-presign-bypass", "器物谱.md", "炼蛊房/nday_route.py"),
    (("freepbx rce", "voip后台漏洞", "freepbx exploit"),
     "freepbx-unauth-rce", "器物谱.md", "炼蛊房/nday_route.py"),
    (("geoserver sqli", "jsonarraycontains", "geoserver漏洞"),
     "geoserver-jsonarraycontains-sqli", "器物谱.md", "炼蛊房/nday_route.py"),
    (("mrbs ssrf", "会议室预订系统", "mrbs漏洞"),
     "mrbs-ssrf", "器物谱.md", "炼蛊房/nday_route.py"),
    (("upsnap rce", "upsnap漏洞", "upsnap未授权"),
     "upsnap-unauth-rce", "器物谱.md", "炼蛊房/nday_route.py"),
    (("ollama未授权", "ollama rce", "/api/tags未授权"),
     "ollama-unauth", "ai-llm.md", "炼蛊房/llm_surface_probe.py"),
    (("php-cgi rce", "cve-2024-4577", "php cgi漏洞"),
     "php-cgi-cve-2024-4577", "中原骨架.md", "炼蛊房/nday_route.py"),
    (("ray dashboard未授权", "ray :8265", "ray /api/jobs"),
     "ray-dashboard-unauth", "器物谱.md", "炼蛊房/nday_route.py"),
    (("weblogic rce", "cve-2026-21962", "weblogic proxy"),
     "weblogic-proxy-cve-2026-21962", "中原骨架.md", "炼蛊房/nday_route.py"),
    (("etcd未授权", "etcd:2379", "etcd漏洞"),
     "etcd-unauth", "器物谱.md", "炼蛊房/middleware_unauth_probe.py"),
    (("wolfstack密钥", "wolfstack hardcoded"),
     "wolfstack-hardcoded-secret", "器物谱.md", "炼蛊房/middleware_unauth_probe.py"),
    # ── Batch 7: Code Audit (4) ──
    (("codeql分析", "codeql query", "ql数据流"),
     "codeql", "code-audit.md", "tools/deepaudit/bin/da_pipeline.py"),
    (("安全代码审计", "secure code review", "代码审查"),
     "secure-code-review", "code-audit.md", "tools/deepaudit/bin/da_pipeline.py"),
    (("semgrep规则", "semgrep scan", "semgrep审计"),
     "semgrep", "code-audit.md", "tools/deepaudit/bin/da_pipeline.py"),
    (("autocve", "cve挖掘流水线", "漏洞自动挖掘"),
     "autocve-cve-hunt", "code-audit.md", "tools/deepaudit/bin/da_pipeline.py"),
    # ── Batch 8: Gambling/专项 (8) ──
    (("博彩家族指纹", "gambling router", "博彩站识别"),
     "gambling-family-router", "realworld-patterns.md", "炼蛊房/yudao_appapi_probe.py"),
    (("白标盘口渗透", "whitelabel gambling", "白标博彩测试"),
     "whitelabel-gambling-pentest", "realworld-patterns.md", "炼蛊房/yudao_appapi_probe.py"),
    (("1z博彩", "1z-gambling", "1z平台"),
     "1z-gambling-family-pentest", "realworld-patterns.md", "炼蛊房/yudao_appapi_probe.py"),
    (("666bet", "666 tma", "666博彩"),
     "666bet-tma-pentest", "telegram.md", "炼蛊房/yudao_appapi_probe.py"),
    (("777vvip", "vvip bfla", "777接管"),
     "777vvip-bfla-takeover", "realworld-patterns.md", "炼蛊房/yudao_appapi_probe.py"),
    (("充值链渗透", "博彩充值链", "deposit chain"),
     "gambling-deposit-chain-pentest", "realworld-patterns.md", "炼蛊房/pay_matrix.py"),
    (("芋道代付mock", "mock-enable", "df-user", "文件写rce"),
     "yudao-daifu-mock-file-rce", "realworld-patterns.md", "炼蛊房/yudao_appapi_probe.py"),
    (("fastadmin代付", "/sh.php", "/ks.php", "代付平台"),
     "fastadmin-daifu-pentest", "realworld-patterns.md", "炼蛊房/strike_probe.py"),
    # ── Batch 9: Reverse Engineering (8) ──
    (("js逆向", "webpack逆向", "jsvmp解析", "wasm worker"),
     "js-reverse", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    (("ghidra逆向", "analyzeheadless", "ghidra脚本"),
     "ghidra-reverse", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    (("go逆向", "rust逆向", "pclntab分析", "goresym"),
     "go-rust-reverse", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    (("mach-o逆向", "macos逆向", "macos app逆向"),
     "macos-reverse", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    (("crx逆向", "xpi逆向", "浏览器扩展逆向"),
     "browser-extension-reverse", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    (("spa协议逆向", "spa-protocol", "前端协议逆向"),
     "spa-protocol-reverse", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    (("加密api逆向", "blob加密请求", "encrypted api gateway"),
     "encrypted-api-spa", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    (("二进制协议逆向", "protobuf逆向", "自定义协议"),
     "protocol-reverse", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    # ── Batch 10: Misc/高频 (21) ──
    (("ctf赛题", "awd对抗", "靶场练习"),
     "ctf-sandbox", "web.md", "炼蛊房/css_query.py"),
    (("cve日报", "今天新cve", "cve情报日报"),
     "cve-daily-intel", "web.md", "炼蛊房/nday_route.py"),
    (("案卷交差", "证据链断", "案卷审查"),
     "case-review", "web.md", "炼蛊房/case_triage.py"),
    (("蓝鸟猎手专卡", "jdumpspider", "hprof对象图", "堆凭据扫描"),
     "heapdump-lanniao-hunter", "中原骨架.md", "炼蛊房/heap_cred_scan.py"),
    (("目录开放猎杀", ".env泄露", "index of猎杀", "credential hunter"),
     "sensitive-dir-dump", "web.md", "炼蛊房/strike_probe.py"),
    (("xff伪造", "x-forwarded-for绕过", "ip信任头绕过"),
     "trusted-ip-header", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("入侵排查", "排后门", "后门检测", "webshell查杀"),
     "host-ir-check", "forensic.md", "炼蛊房/host_ir_check.py"),
    (("零信任敲门", "端口敲门", "黑洞模式", "nftables drop", "vue c2",
      "hmac控制台", "hmac 控制台", "spake2", "c2控制台", "c2 控制台",
      "c2零信任", "c2 零信任", "内存沙箱控制台", "pty 8889", "pty8889"),
     "c2-zero-trust-console", "evasion.md", "炼蛊房/c2_zt_probe.py"),
    (("c2落地验证", "sliver验证", "c2回连测试"),
     "host-c2-verify", "evasion.md", "炼蛊房/host_c2_verify.py"),
    (("回连监听", "se_listen", "攻击机监听"),
     "host-c2-verify", "evasion.md", "炼蛊房/se_listen.py"),
    (("hitcon zeroday", "hitcon通报", "zeroday.hitcon"),
     "hitcon-zeroday-intel", "web.md", "炼蛊房/nday_route.py"),
    (("tg号库管理", "投递session", "清库只留"),
     "tg-account-library", "telegram.md", "炼蛊房/social_engineer_agent.py"),
    (("网狐登录", "qpaccountsdb", "protocal=167", "machine盲注"),
     "whgame-tp5-login-sqli", "realworld-patterns.md", "炼蛊房/strike_probe.py"),
    (("蜂群扫描", "pentest-swarm ai", "psa_scan"),
     "pentest-swarm", "web.md", "炼蛊房/strike_probe.py"),
    (("厚客户端渗透", "electron渗透", "qt逆向"),
     "thick-client", "reversing.md", "炼蛊房/reverse_skill_route.py"),
    (("硬编码系统token", "cf-connecting-ip加款", "cfip fund"),
     "hardcoded-token-cfip-fund", "realworld-patterns.md", "炼蛊房/strike_probe.py"),
    (("proxmox", "pve", "pve 7", "pve 8", ":8006", "tfa-challenge",
      "libpve-access-control", "accesscontrol.pm", "cve-2023-54391",
      "proxmox免密", "proxmox勒索", "proxmox auth bypass",
      "psa-2026-00043", "proxmox虚拟化"),
     "proxmox-auth-bypass", "器物谱.md", "炼蛊房/nday_route.py"),
    (("tg bot webhook劫持", "bot token hijack写", "admin/telegram/bot写",
      "tg bot渗透", "tg bot逆向", "bot token泄露", "bot token接管",
      "webhook伪造", "secret_token校验", "cve-2026-28454",
      "getme getwebhookinfo", "telegram bot token",
      "stealer bot", "drainer bot", "bot c2拦截",
      "matkap", "pyronut", "供应链投毒 bot",
      "callback_data篡改", "stars支付伪造",
      "forwardmessage情报", "bot api接管",
      "tg bot token probe", "webhook签名缺失"),
     "tg-bot-webhook-hijack", "telegram.md", "炼蛊房/tg_bot_token_probe.py"),
    (("tg nextauth接管", "nextauth_secret伪造", "tg bot nextauth"),
     "tg-bot-nextauth-takeover", "telegram.md", "炼蛊房/nday_route.py"),
    (("xxljob后渗透", "xxljob postex", "xxljob jar提取"),
     "xxljob-postex-infra-chain", "中原骨架.md", "炼蛊房/nday_route.py"),
    (("wp插件未授权", "wordpress plugin unauth", "wp插件接管"),
     "wordpress-plugin-unauth-takeover", "web.md", "炼蛊房/wp_plugin_unauth_probe.py"),
    (("wp xmlrpc攻击", "multicall暴力", "wp2shell"),
     "wordpress-xmlrpc-surface", "web.md", "炼蛊房/wp_plugin_unauth_probe.py"),
    (("wp rest cors", "wp密码重置host注入", "wp cors ato"),
     "wp-rest-cors-ato", "web.md", "炼蛊房/wp_plugin_unauth_probe.py"),
    (("gva开放注册", "ginvue接管", "ginvue-admin stealth"),
     "ginvue-admin-stealth-takeover", "realworld-patterns.md", "炼蛊房/strike_probe.py"),
    # ── Batch 11: WAF/Evasion/额外 (6) ──
    (("waf检测", "waf fingerprint", "waf型号识别"),
     "waf-detector", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("waf js challenge", "cf_clearance绕过", "bot fight绕过"),
     "waf-js-challenge-bypass", "web.md", "炼蛊房/core_web_surface_probe.py"),
    (("recaptcha绕过", "hcaptcha绕过", "人机验证绕过"),
     "recaptcha-bypass", "web.md", "炼蛊房/auth_brute_probe.py"),
    (("geetest绕过", "极验绕过", "geetest crack"),
     "geetest-captcha-bypass", "web.md", "炼蛊房/auth_brute_probe.py"),
    (("imunify360绕过", "wsidchk", "imunify直连"),
     "imunify360-direct-ip-bypass", "web.md", "炼蛊房/cdn_tracer.py"),
    (("subdomain takeover", "子域接管漏洞", "ns接管"),
     "subdomain-takeover", "recon.md", "炼蛊房/origin_recon.py"),
    # ── Batch 12: src-6k-skill 新知识 (3) ──
    (("ghost bits", "cast attack", "ghost字符", "char缩窄", "java char byte",
      "cjk绕过waf", "ghost bits bypass", "阮陪严灵", "writeBytes漏洞",
      "char narrowing", "16位转8位", "%2>绕过", "jetty hex折叠",
      "tomcat filename*绕过", "bcel classloader绕过"),
     "ghost-bits-cast-attack", "evasion.md", "杀招/残影/SKILL.md"),
    (("cloud ide rce", "codex rce", "codex rpc", "tenant-api", "codex-api",
      "ai编程台弱口令", "编程助手rce", "command/exec rpc", "编程沙箱逃逸"),
     "cloud-ide-codex-rce", "web.md", "杀招/盗天·文台/SKILL.md"),
    (("对话口工具真执行", "agent tool exec", "chat api命令执行",
      "对话口bash", "工具列表命令执行", "对话口不登录执行", "chat工具rce"),
     "llm-security", "LLM与Agent安全手法.md", "炼蛊房/llm_surface_probe.py"),
    (("工控", "scada", "modbus", "s7-1200", "iec 62443"),
     "ot-ics", "network-services.md", "炼蛊房/ot_ics_probe.py"),
    (("无线审计", "wifi beacon", "wps 面"),
     "wifi-wireless", "network-services.md", "炼蛊房/wireless_surface_probe.py"),
    (("听波", "sdr iq", "rtl-sdr"),
     "radio-sdr", "network-services.md", "炼蛊房/radio_sdr_probe.py"),
    (("固件串口", "jtag uart", "uboot console"),
     "hardware-security", "reversing.md", "炼蛊房/hardware_surface_probe.py"),
    (("杂器 mqtt", "ssdp 未授权", "coap well-known"),
     "iot-security-testing", "network-services.md", "炼蛊房/iot_surface_probe.py"),
]


def _contains(key: str, blob: str) -> bool:
    key = key.strip().lower()
    if not key:
        return False
    if re.fullmatch(r"[a-z0-9._-]+", key) and len(key) <= 5:
        return re.search(rf"(?<![a-z0-9]){re.escape(key)}(?![a-z0-9])", blob) is not None
    return key in blob


def _naming_pair() -> tuple[dict[str, str], dict[str, str]]:
    try:
        naming = ROOT / "NAMING.json"
        if not naming.is_file():
            return {}, {}
        data = json.loads(naming.read_text(encoding="utf-8"))
        s2g = {str(k): str(v) for k, v in (data.get("skills") or {}).items() if k and v}
        return s2g, {v: k for k, v in s2g.items()}
    except Exception:
        return {}, {}


def route(signal: str) -> dict[str, str]:
    blob = signal.lower()
    s2g, g2s = _naming_pair()
    for keys, skill, tech, tool in ROUTES:
        hits = [k.strip() for k in keys if _contains(k, blob)]
        if not hits:
            continue
        if skill == "se-inject":
            try:
                from scope_lib import is_oss_layout
                if is_oss_layout():
                    continue
            except Exception:
                pass
        cand = {
            "signal": signal,
            "skill": skill,
            "matched": ",".join(hits),
            "playbook": "传承/东方长凡·推演.md",
            "longform": f"智道藏书/智道推演/techniques/{_hypo_tech(tech)}",
            "tool": tool,
            "note": "先专卡后长文" if skill != "edr-bypass-re"
            else "授权机写马/回连：payload_forge campaign + se_listen",
        }
        if skill in s2g:
            cand["gu"] = s2g[skill]
        return cand
    for gu, slug in sorted(g2s.items(), key=lambda kv: len(kv[0]), reverse=True):
        if len(gu) >= 2 and gu.lower() in blob:
            return {
                "signal": signal,
                "skill": slug,
                "matched": gu,
                "playbook": "传承/东方长凡·推演.md",
                "longform": f"智道藏书/智道推演/techniques/{_hypo_tech('realworld-patterns.md')}",
                "tool": "",
                "note": "挂号命中，先专卡",
                "gu": gu,
            }
    return {
        "signal": signal,
        "skill": "春秋蝉-账本",
        "matched": "",
        "playbook": "传承/东方长凡·推演.md",
        "longform": "智道藏书/智道推演/MAP.md",
        "tool": "炼蛊房/case_ledger.py",
        "note": "未认族：先账本记下假设，再 case-triage / keyword-router",
    }


def cmd_doctor() -> int:
    tech = ROOT / "智道藏书" / "智道推演" / "techniques"
    need = [
        _hypo_tech(n) for n in (
            "auth-modern.md", "cloud-cn.md", "cn-frameworks.md", "code-audit.md",
            "network-services.md", "product.md", "realworld-patterns.md",
            "web.md", "recon.md", "cloud.md",
        )
    ]
    checks: list[tuple[str, bool, str]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append((name, ok, detail))
        print(f"[{'OK' if ok else 'FAIL'}] {name}: {detail}")

    try:
        from scope_lib import is_oss_layout
        _oss = is_oss_layout()
    except Exception:
        _oss = False

    def _skill_here(slug: str) -> bool:
        if _oss and slug == "se-inject":
            return True
        if (ROOT / "杀招" / slug / "SKILL.md").is_file():
            return True
        try:
            naming = json.loads((ROOT / "NAMING.json").read_text(encoding="utf-8"))
            gu = str((naming.get("skills") or {}).get(slug) or "")
            return bool(gu) and (ROOT / "杀招" / gu / "SKILL.md").is_file()
        except Exception:
            return False

    files = list(tech.glob("*.md")) if tech.is_dir() else []
    add("tech-count", len(files) >= 22, str(len(files)))
    missing = [n for n in need if not (tech / n).is_file()]
    add("new-domains", not missing, ",".join(missing) or "ok")
    hit = route("若依 actuator")
    add("first-match-ruoyi", hit.get("skill") == "ruoyi-fork-admin-pentest", hit.get("skill") or "")
    act = route("actuator 网关")
    add(
        "actuator-spring",
        act.get("skill") == "spring-actuator-cloud-takeover",
        act.get("skill") or "",
    )
    dor = route("doris 9030")
    add("doris-unauth", dor.get("skill") == "doris-unauth", dor.get("skill") or "")
    nac = route("Nacos v3 auth user")
    add("nacos-v3", nac.get("skill") == "nacos-authscope-unauth", nac.get("skill") or "")
    wx = route("微信小程序 wxapkg")
    add("wxmini", wx.get("skill") == "wxmini-static-audit", wx.get("skill") or "")
    shop = route("FastAdmin shop_hq")
    add(
        "fa-shop",
        shop.get("skill") == "fastadmin-shop-tenant-bola",
        shop.get("skill") or "",
    )
    yud = route("芋道 TMA sk_encrypt")
    add("yudao-tma", yud.get("skill") == "yudao-appapi-pentest", yud.get("skill") or "")
    tma = route("telegram mini app tma")
    add(
        "tma-gambling",
        tma.get("skill") == "telegram-tma-gambling",
        tma.get("skill") or "",
    )
    tgc = route("系统选择 tgcloud_pc")
    add(
        "tgcloud-pc",
        tgc.get("skill") == "tg-cloud-control-pentest",
        tgc.get("skill") or "",
    )
    add(
        "social-skill",
        _skill_here("autonomous-social-engagement"),
        "autonomous-social-engagement",
    )
    add(
        "cache-probe",
        (ROOT / "炼蛊房" / "cache_poison_probe.py").is_file(),
        "cache_poison_probe.py",
    )
    try:
        usdt = (ROOT / "炼蛊房" / "usdt_attr_hijack.py").read_text(encoding="utf-8")
    except FileNotFoundError:
        usdt = ""
    add("usdt-chain", "chain-scan" in usdt, "usdt_attr_hijack chain-scan")
    try:
        crt = (ROOT / "tools" / "stdlib-kit" / "crt_find.py").read_text(encoding="utf-8")
    except FileNotFoundError:
        crt = ""
    add("crt-needs-domain", "禁止无域" in crt, "crt_find --domain")
    try:
        fb = (ROOT / "炼蛊房" / "stdlib_fallback.py").read_text(encoding="utf-8")
    except FileNotFoundError:
        fb = ""
    add("fallback-real-prefer", "cache_poison_probe.py" in fb, "prefer→ops")
    pk = route("pwnkit CVE-2021-4034")
    add("pwnkit-lpe", pk.get("skill") == "linux-post-exploit", pk.get("skill") or "")
    gp = route("godpotato seimpersonate")
    add("godpotato-win", gp.get("skill") == "windows-lpe", gp.get("skill") or "")
    ls = route("log4shell jndi")
    add("log4shell-skill", ls.get("skill") == "log4shell-exploitation", ls.get("skill") or "")
    inj = route("claude 拒答 助手注入")
    add(
        "se-inject",
        True if _oss else inj.get("skill") == "se-inject",
        "oss-skip" if _oss else (inj.get("skill") or ""),
    )
    opi = route("opus-injector")
    add(
        "se-inject-opus",
        True if _oss else opi.get("skill") == "se-inject",
        "oss-skip" if _oss else (opi.get("skill") or ""),
    )
    add(
        "se-inject-bin",
        True if _oss else (
            (ROOT / "炼蛊房" / "se_inject.py").is_file()
            and (ROOT / "tools" / "se-inject" / "bin" / "se_inject.py").is_file()
        ),
        "oss-skip" if _oss else "se_inject.py",
    )
    tp3 = route("get_fenxiao_db_data thinkphp3.1")
    add("tp3-fenxiao", tp3.get("skill") == "tp3-fenxiao-api-pentest", tp3.get("skill") or "")
    xj = route("xxl-job GLUE_SHELL")
    add("xxljob-admin", xj.get("skill") == "xxljob-admin-glue-chain", xj.get("skill") or "")
    tgn = route("TG号码管理 export/download")
    add("tg-number-admin", tgn.get("skill") == "tg-number-admin-pentest", tgn.get("skill") or "")
    st = route("黑盒突击 S1攻击面")
    add("strike-probe", st.get("skill") == "strike-probe", st.get("skill") or "")
    add(
        "strike-bin",
        (ROOT / "炼蛊房" / "strike_probe.py").is_file()
        and (ROOT / "传承" / "春晓苦力·突击.md").is_file(),
        "strike_probe.py",
    )
    missing_skills = sorted({
        s for _k, s, _t, _tool in ROUTES
        if not _skill_here(s)
        and not (_oss and ("deepaudit" in _tool or s in {
            "codeql", "semgrep", "firebase-apk-scanner",
        }))
    })
    add("routes-skills", not missing_skills, ",".join(missing_skills) or "ok")
    missing_tools = sorted({
        tool for _k, _s, _t, tool in ROUTES
        if tool and not (ROOT / tool).is_file()
        and not (_oss and ("se_inject" in tool or "deepaudit" in tool))
    })
    add("routes-tools", not missing_tools, ",".join(missing_tools) or "ok")
    failed = [c for c in checks if not c[1]]
    print(f"doctor {len(checks) - len(failed)}/{len(checks)}")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="假设作业信号分流")
    ap.add_argument("--signal", default="")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--doctor", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if args.doctor:
        return cmd_doctor()
    if args.list:
        rows = [
            {"keys": list(k), "skill": s, "tool": t}
            for k, s, _tech, t in ROUTES
        ]
        print(json.dumps(rows, ensure_ascii=False, indent=2) if args.json
              else "\n".join(f"{r['skill']:28} {', '.join(r['keys'])}" for r in rows))
        return 0
    if not args.signal:
        ap.error("需要 --signal 或 --list")
    hit = route(args.signal)
    if args.json:
        print(json.dumps(hit, ensure_ascii=False, indent=2))
    else:
        for k, v in hit.items():
            print(f"{k}={v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
