#!/usr/bin/env python3
"""N-day / 1day 作业路由：指纹 → 已验证专卡命令（授权范围内）。

不替代 nuclei；先钉组件再决定跑哪张卡，避免广谱扫完无接管。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

OPS = Path(__file__).resolve().parent
ROOT = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-nday-route"

# 命中后切已打穿/已封装的专链，而不是再开无关广谱
ROUTES: list[dict[str, Any]] = [
    {
        "id": "actuator",
        "playbook": "传承/春府·关窍.md",
        "cmd": "python3 炼蛊房/actuator_probe.py --base {base} --out {out}/vulns/actuator && python3 炼蛊房/heap_cred_scan.py from-probe --probe {out}/vulns/actuator/probe.json --dump-dir {out}/案卷/heapdump --out {out}/接管/heap_creds --case {case}",
        "note": "禁止只扫 health；heapdump 分桶后立刻蓝鸟拆",
        "body": ("actuator", "spring-boot", "/actuator/"),
        "headers": ("x-application-context",),
        "probe": "/actuator/health",
        "probe_needles": ("status", "UP", "DOWN"),
    },
    {
        "id": "thinkphp",
        "playbook": "传承/幻页·认族.md",
        "cmd": "python3 炼蛊房/thinkphp_surface_probe.py -u {base} --out {out}/vulns/thinkphp.json --case {case}",
        "note": "invoker 走专卡；README/ApiXxx 再跑 tp3_fenxiao_probe",
        "body": ("thinkphp", "think\\app"),
        "headers": (),
        "header_needles": ("thinkphp",),
    },
    {
        "id": "tp3-fenxiao",
        "playbook": "传承/幻三·分销.md",
        "cmd": "python3 炼蛊房/tp3_fenxiao_probe.py -u {base} --case {case} --out {out}/vulns/tp3_fenxiao.json",
        "note": "TP3 魔改分销；禁止 message_delete OR；test_pay 先问",
        "body": ("apiuserfenxiao", "get_fenxiao_db_data", "common_get_author_list", "thinkphp3.1"),
        "probe": "/ThinkPHP/README.md",
        "probe_needles": ("ThinkPHP3", "ThinkPHP 3", "thinkphp3.1", "魔改"),
        "probe_json": False,
    },
    {
        "id": "xxljob",
        "playbook": "传承/差事府·无门.md",
        "cmd": "python3 炼蛊房/xxljob_admin_probe.py --base {base} --case {case} --out {out}/vulns/xxljob.json",
        "note": "默认口+列执行器；GLUE /run 先问。登录认 Cookie/302/JSON",
        "body": ("xxl-job-admin", "xxl-job", "分布式任务调度"),
        "probes": ("/xxl-job-admin/toLogin", "/xxl-job-admin/", "/toLogin"),
        "probe_needles": ("XXL-JOB", "xxl-job-admin", "分布式任务调度"),
        "probe_json": False,
    },
    {
        "id": "tg-number-admin",
        "playbook": "传承/飞鸽·号册主府.md",
        "cmd": "python3 炼蛊房/tg_number_admin_probe.py --base {base} --case {case}",
        "note": "弱口+settings/export 只读头；禁止改原密、禁止百万拖号",
        "body": ("tg号码管理", "tg号码", "phone_numbers", "export_items"),
    },
    {
        "id": "shiro",
        "playbook": "传承/记忆蛊.md",
        "cmd": "python3 炼蛊房/java_web_surface_probe.py -u {base} --out {out}/vulns/java_web_surface.json",
        "note": "deleteMe → 弱密钥碰撞",
        "cookie": "rememberme",
        "body": ("shiro",),
    },
    {
        "id": "ruoyi",
        "playbook": "传承/若依四海杀伤链.md",
        "cmd": "python3 炼蛊房/java_web_surface_probe.py -u {base} --out {out}/vulns/java_web_surface.json --case {case}",
        "note": "captchaImage + Redis 旁路",
        "body": ("ruoyi", "若依", "captchaimage"),
        "probe": "/captchaImage",
        "probe_needles": ("uuid", "img", "captcha"),
    },
    {
        "id": "cn-oa",
        "playbook": "传承/官衙·用友致远.md",
        "cmd": "python3 炼蛊房/java_web_surface_probe.py -u {base} --case {case} --stack cnoa && python3 tools/1day-kit/od_kit.py nuclei --url {base} --case {case} -t tools/1day-kit/custom-templates/yonyou-seeyon-oa-surface.yaml",
        "note": "只指纹；通达/泛微/用友/致远长文 中原骨架.md",
        "body": ("seeyon", "致远", "yonyou", "用友", "nccloud", "tongda", "通达", "logincheck.php", "weaver", "泛微"),
    },
    {
        "id": "harbor",
        "playbook": "智道藏书/智道推演/techniques/器物谱.md",
        "cmd": "python3 炼蛊房/middleware_unauth_probe.py --host {base} --case {case}",
        "note": "Harbor/Portainer 指纹后读 器物谱.md；默认口令先问改密",
        "body": ("goharbor", "harbor", "/api/v2.0/systeminfo", "portainer"),
    },
    {
        "id": "gva",
        "playbook": "传承/锦府·静默.md",
        "cmd": "python3 炼蛊房/ginvue_admin_probe.py recon --base {base} --case {case}",
        "note": "开放注册 / getSystemConfig；勿改原 admin 密",
        "body": ("gin-vue-admin", "ginvue", "gva"),
    },
    {
        "id": "jeecg",
        "playbook": "传承/济世·无门.md",
        "cmd": "python3 炼蛊房/java_web_surface_probe.py -u {base} --out {out}/vulns/java_web_surface.json",
        "body": ("jeecg", "jeecg-boot", "window._config"),
    },
    {
        "id": "panel",
        "playbook": "传承/宝塔台.md",
        "cmd": "python3 炼蛊房/panel_surface_probe.py -u {base} --out {out}/vulns/panel.json",
        "body": ("宝塔", "aapanel", "phpmyadmin", "bt-panel"),
    },
    {
        "id": "pocketbase",
        "playbook": "传承/口袋库.md",
        "cmd": "见 Skill pocketbase-horizons-recovery",
        "body": ("pocketbase", "/_/", "/api/collections"),
    },
    {
        "id": "langflow",
        "playbook": "传承/流语·开天.md",
        "cmd": "python3 炼蛊房/langflow_probe.py detect -u {base} --case {case}",
        "note": "9198 auto_login + 3248 无票 validate + %0a WAF 差分；破坏性 exec 先问",
        "body": ("langflow",),
        "probe": "/api/v1/version",
        "probe_needles": ("langflow",),
    },
    {
        "id": "flowise",
        "playbook": "传承/流思·内额.md",
        "cmd": "python3 炼蛊房/flowise_probe.py detect -u {base} --case {case}",
        "note": "L2 只测 x-request-from:internal 密钥泄露；NodeVM 逃逸不默认发",
        "body": ("flowise",),
        "probe": "/api/v1/version",
        "probe_needles": ("flowise",),
    },
    {
        "id": "ray",
        "playbook": "传承/光台·无门.md",
        "cmd": "python3 炼蛊房/nday_family_probe.py --family ray --base {base} --case {case}",
        "note": "CVE-2025-62593；本库探针列 /api/jobs；提交 job 授权内直接做",
        "body": ("ray dashboard", "ray_version", "ray-dashboard", "/api/jobs"),
        "probe": "/api/version",
        "probe_needles": ("ray_version", "ray"),
    },
    {
        "id": "mlflow",
        "playbook": "传承/流实验·游方.md",
        "cmd": "python3 炼蛊房/nday_family_probe.py --family mlflow --base {base} --case {case}",
        "note": "CVE-2026-64849；本库探针打 /api/2.0/mlflow/webhooks；禁止默认 IMDS",
        "body": ("/ajax-api/2.0/mlflow", "mlflow tracking", "<title>mlflow"),
        "probe": "/api/2.0/mlflow/webhooks",
        "probe_needles": ("webhooks",),
    },
    {
        "id": "owncloud-webdav-presign",
        "playbook": "传承/私云·预签.md",
        "cmd": "python3 炼蛊房/nday_family_probe.py --family owncloud --base {base} --case {case}",
        "note": "CVE-2023-49105；本库探针认版本窗；授权内伪造 OC-Signature 读文件",
        "body": ("owncloud", '"productname":"owncloud"', "/status.php", "/remote.php/dav"),
        "probe": "/status.php",
        "probe_needles": ("owncloud", "versionstring", "productname"),
        "probe_json": True,
    },
    {
        "id": "gitea-diffpatch-rce",
        "playbook": "传承/房睇长·耳报-08-28.md",
        "cmd": "python3 炼蛊房/nday_family_probe.py --family gitea --base {base} --case {case}",
        "note": "CVE-2026-60004；本库探针认版本窗 <1.27.1。禁止 POST 恶意 diff/hook",
        "body": ("gitea", "go-gitea", "/api/v1/version", "Gitea API"),
        "probe": "/api/v1/version",
        "probe_needles": ("version",),
        "probe_json": True,
    },
    {
        "id": "weblogic-proxy-rce",
        "playbook": "传承/房睇长·耳报-08-28.md",
        "cmd": "python3 炼蛊房/nday_family_probe.py --family weblogic --base {base} --case {case}",
        "note": "CVE-2026-21962；本库探针打控制台/WSAT。无完整 PoC 只指纹",
        "body": ("weblogic server", "oracle weblogic", "oracle-application-server"),
        "probe": "/console/login/LoginForm.jsp",
        "probe_needles": ("weblogic", "oracle"),
        "probe_json": False,
    },
    {
        "id": "zimbra",
        "playbook": "传承/信巢·闻管.md",
        "cmd": "python3 炼蛊房/nday_family_probe.py --family zimbra --base {base} --case {case}",
        "note": "CVE-2026-73570；本库探针认 Zimbra Web。禁止自造 SMTP payload",
        "body": ("zimbrawebclient", "zimbracollaboration", "zimbralogin", "/zimbra/js"),
        "probe": "/zimbra/",
        "probe_needles": ("zimbra", "zimbrawebclient"),
        "probe_json": False,
    },
    {
        "id": "icecoder",
        "playbook": "传承/冰码·开天.md",
        "cmd": "python3 炼蛊房/icecoder_surface_probe.py --base {base} --case {case}",
        "note": "CVE-2026-63722；只 GET。命中「no command received」才算终端面，禁止 POST command",
        "body": ("icecoder", "terminal-xhr.php", "ice-coder"),
        "probes": ("/lib/terminal-xhr.php", "/icecoder/lib/terminal-xhr.php"),
        "probe_needles": ("no command received", "sorry, no command", "can't use this terminal"),
        "probe_json": False,
    },
    {
        "id": "jetengine",
        "playbook": "传承/坞·喷机.md",
        "cmd": "python3 炼蛊房/jetengine_surface_probe.py --base {base} --case {case}",
        "note": "CVE-2026-66613；只读 readme，≤3.8.14 才算；禁止自造 SSTI",
        "body": ("jet-engine", "jetengine"),
        "probe": "/wp-content/plugins/jet-engine/readme.txt",
        "probe_needles": ("stable tag",),
        "probe_json": False,
    },
    {
        "id": "ollama",
        "playbook": "传承/羊驼·无门.md",
        "cmd": "python3 炼蛊房/ollama_unauth_probe.py --base {base} --case {case}",
        "note": "HITCON ZD-2026-00572；只 GET /api/version /api/tags，禁止 generate/pull",
        "body": ("ollama",),
        "probe": "/api/version",
        "probe_needles": ("version",),
    },
    {
        "id": "php-cgi-4577",
        "playbook": "传承/门廊·开天.md",
        "cmd": "python3 炼蛊房/php_cgi_4577_probe.py --base {base} --case {case}",
        "note": "CVE-2024-4577；只指纹 Windows+PHP，禁止 %AD RCE 查询串",
        "body": ("php-cgi", "cve-2024-4577"),
        "header_needles": ("php-cgi",),
    },
    {
        "id": "trusted-ip",
        "playbook": "传承/信头·踪.md",
        "cmd": "python3 炼蛊房/trusted_ip_header_probe.py --base {base} --case {case}",
        "note": "XFF/X-Real-IP；403→200 才算。加款走 cfip 专卡",
        "body": ("x-real-ip", "true-client-ip"),
        "probes": ("/admin", "/admin/"),
        "probe_needles": ("login", "admin", "403", "forbidden"),
        "probe_json": False,
    },
    {
        "id": "client-state",
        "playbook": "传承/客器·跳步.md",
        "cmd": "python3 炼蛊房/client_state_skip_probe.py --base {base} --case {case}",
        "note": "HITCON 00974 同类；翻 verified/paid，禁止耗余额",
        "body": ("ispaid", "isverified", "canride", "is_paid", "is_verified"),
    },
    {
        "id": "reset-token",
        "playbook": "传承/夺舍·短票.md",
        "cmd": "python3 炼蛊房/reset_token_surface_probe.py --base {base} --case {case}",
        "note": "不提交邮箱；短 token / 追踪页才算 L2",
        "body": ("forgot-password", "lostpassword", "reset-password", "忘记密码", "忘記密碼"),
        "probes": ("/forgot-password", "/wp-login.php?action=lostpassword"),
        "probe_needles": ("password", "forgot", "reset"),
        "probe_json": False,
    },
    {
        "id": "wp-xmlrpc",
        "playbook": "传承/坞·旧令.md",
        "cmd": "python3 炼蛊房/wp_xmlrpc_probe.py --base {base} --case {case}",
        "note": "只 listMethods；禁止 multicall 爆破与 pingback 内网",
        "body": ("xml-rpc server accepts post", "xmlrpc.php"),
        "probes": ("/xmlrpc.php", "/wp/xmlrpc.php"),
        "probe_needles": ("xml-rpc", "xmlrpc"),
        "probe_json": False,
    },
    {
        "id": "open-redirect",
        "playbook": "传承/暗渡陈仓·2.md",
        "cmd": "python3 炼蛊房/open_redirect_surface_probe.py --base {base} --case {case}",
        "note": "HITCON returnUrl；L2=Location 指 example.com，不跟随外域",
        "body": ("returnurl", "return_url", "redirect_uri"),
        "probes": ("/login", "/signin"),
        "probe_needles": ("password", "login", "sign in"),
        "probe_json": False,
    },
    {
        "id": "trueconf",
        "playbook": "传承/话巢·脚本.md",
        "cmd": "python3 炼蛊房/nday_family_probe.py --family trueconf --base {base} --case {case}",
        "note": "CVE-2026-72529/72530；本库探针只指纹 Web/版本窗，不调未文档函数",
        "body": ("trueconf server",),
    },
    {
        "id": "proxmox",
        "playbook": "传承/虚机府·免密.md",
        "cmd": "python3 炼蛊房/nday_family_probe.py --family proxmox --base {base} --case {case}",
        "note": "CVE-2023-54391；本库探针打 PVE Web + tfa-challenge。出票即 L3，票脱敏",
        "body": ("proxmox virtual environment", "pve.username", "proxmox"),
        "probe": "/api2/json/version",
        "probe_needles": ("release", "version", "pve"),
        "probe_json": True,
    },
    {
        "id": "geetest",
        "playbook": "传承/滑块·破禁.md",
        "cmd": "python3 炼蛊房/captcha_auto.py solve --url {base} --case {case} --probe-api",
        "note": "有头滑块或打码 Key；过闸会话写入 接管/session/",
        "body": ("initgeetest", "gcaptcha4", "geetest.com", "geetest_slider", "geevisit.com", "vccgeetest.com", "gsensebot.com"),
    },
    {
        "id": "cognito-s3",
        "playbook": "传承/客池·仓格.md",
        "cmd": "python3 炼蛊房/cognito_s3_probe.py extract --path <apk或前端> --case {case}",
        "note": "IdentityPoolId → chain；Cognito/S3 不扩 targets；默认只列，写只用 marker",
        "body": ("identitypoolid", "cognitoidentity", "aws-amplify", "cognito-identity", "awsconfiguration"),
    },
    {
        "id": "litellm",
        "playbook": "传承/灯笼·破印.md",
        "cmd": "python3 炼蛊房/litellm_badhost.py probe --base {base} --case {case}",
        "body": ("litellm",),
        "probe": "/v1/models",
        "probe_needles": ("data", "object"),
    },
    {
        "id": "gitlab",
        "playbook": "传承/文山·无门.md",
        "cmd": "python3 炼蛊房/nday_family_probe.py --family gitlab --base {base} --case {case}",
        "note": "CVE-2026-19478；本库探针 GraphQL metadata。改删授权内直接做",
        "body": ("gon.gitlab", "js-gitlab", "about.gitlab.com", "sign in · gitlab"),
        "headers": ("x-gitlab-meta",),
        "probe": "/users/sign_in",
        "probe_needles": ("gitlab", "gon.gitlab"),
        "probe_json": False,
    },
    {
        "id": "graphql",
        "playbook": "传承/李代桃僵·星念.md",
        "cmd": "python3 炼蛊房/jwt_gql_probe.py -u {base} --out {out}/vulns/jwt_gql.json",
        "body": ("graphql", "graphiql", "__schema"),
    },
    {
        "id": "nacos",
        "playbook": "传承/春府·关窍.md",
        "cmd": "见 Playbook nacos_config_chain",
        "note": "ENC( 与 Nacos 须在授权 targets",
        "body": ("nacos", "/nacos/"),
    },
    {
        "id": "epay",
        "playbook": "传承/秦百胜·假契.md",
        "cmd": "见 Skill payment-callback-forgery",
        "body": ("epay", "/pay/notify", "易支付", "rainbow"),
    },
    {
        "id": "upsnap",
        "playbook": "传承/资产册·开天.md",
        "cmd": "python3 炼蛊房/nday_family_probe.py --family upsnap --base {base} --case {case}",
        "note": "CVE-2026-49819；本库探针认 init-superuser 面。已有超管转弱口",
        "body": ("upsnap", "wake on lan", "/api/upsnap/"),
    },
    {
        "id": "mrbs",
        "playbook": "传承/议室·游方.md",
        "cmd": "python3 炼蛊房/nday_family_probe.py --family mrbs --base {base} --case {case}",
        "note": "CVE-2026-46382；本库探针认 edit_entry。先协作域",
        "body": ("meeting room booking", "mrbs", "mrbs.css"),
    },
    {
        "id": "etcd",
        "playbook": "传承/契柜·无门·2.md",
        "cmd": "python3 炼蛊房/etcd_probe.py -u {base} --case {case} --deep",
        "note": "CVE-2026-73499；73500 DoS 默认不做",
        "body": ("etcd", '"etcdserver"', "/v2/keys", "/v3/"),
        "probe": "/version",
        "probe_needles": ("etcdserver", "etcdcluster"),
    },
    {
        "id": "doris",
        "playbook": "传承/仓算无门.md",
        "cmd": "python3 炼蛊房/doris_probe.py --host {base} --case {case}",
        "note": "9030 空口令 + 8030 HTTP 翻库；OUTFILE 先问",
        "body": (
            "apache doris",
            "default_cluster",
            "palo fe",
            "starrocks",
            "/api/v1/catalogs",
        ),
        "probe": "/rest/v1/system",
        "probe_needles": ("frontend", "doris", "backend"),
    },
    {
        "id": "tg-cloud-panel",
        "playbook": "传承/飞鸽·云府.md",
        "cmd": "python3 炼蛊房/tg_cloud_panel_probe.py -u {base} --case {case}",
        "note": "弱口+session/Fernet；成功=可登录 session",
        "body": (
            "sticker",
            "telegram",
            "tg panel",
            "pyrogram",
            "telethon",
            "auto sender",
            "forwarder",
            "云控",
            "session_string",
            "goencrypt",
            "godecrypt",
            "main.wasm",
            "taskprotocolrecovery",
        ),
    },
    {
        "id": "vite-fs",
        "playbook": "传承/快读·开卷.md",
        "cmd": "python3 炼蛊房/vite_fs_probe.py -u {base} --case {case}",
        "note": "/@fs 任意读 → .env → fernet",
        "body": ("/@vite/client", "vite/dist", "__vite_ping", "@fs/"),
    },
    {
        "id": "wolfstack",
        "playbook": "传承/狼栈·死契.md",
        "cmd": "python3 炼蛊房/wolfstack_probe.py -u {base} --case {case}",
        "note": "CVE-2026-73519 默认 X-WolfStack-Secret",
        "body": ("wolfstack", "x-wolfstack", "wolf software"),
    },
    {
        "id": "geoserver",
        "playbook": "传承/地图府·吞库.md",
        "cmd": "python3 炼蛊房/nday_family_probe.py --family geoserver --base {base} --case {case}",
        "note": "jsonArrayContains；本库探针认 WFS Capabilities。不做 COPY TO PROGRAM",
        "body": ("geoserver", "geotools", "/geoserver/", "jsonarraycontains"),
        "probe": "/geoserver/web/",
        "probe_needles": ("geoserver", "geotools"),
        "probe_json": False,
    },
    {
        "id": "freepbx",
        "playbook": "传承/话巢·开天.md",
        "cmd": "python3 炼蛊房/nday_family_probe.py --family freepbx --base {base} --case {case}",
        "note": "CVE-2026-73665；本库探针认 /admin/config.php",
        "body": ("freepbx", "asterisk", "/admin/config.php", "user control panel"),
    },
    {
        "id": "sharepoint",
        "playbook": "传承/窗府·化形.md",
        "cmd": "python3 炼蛊房/nday_family_probe.py --family sharepoint --base {base} --case {case}",
        "note": "CVE-2026-50522；本库探针认 _layouts/_api/web。aspx 上传走专档",
        "body": ("sharepoint", "_layouts/", "_vti_bin", "microsoftsharepoint"),
        "headers": (
            "microsoftsharepointteamservices",
            "sprequestguid",
            "x-sharepointhealthscore",
        ),
    },
    {
        "id": "nextjs",
        "playbook": "传承/次骨·猎面.md",
        "cmd": "python3 炼蛊房/nextjs_surface_probe.py --base {base} --case {case}",
        "note": "NEXTAUTH/Kyber 先 tg_nextauth_takeover。image 400 不是 SSRF",
        "body": ("__next_data__", "/_next/static", "next-action"),
        "headers": ("x-nextjs-cache", "x-nextjs-matched-path"),
        "header_needles": ("next.js",),
        "probes": ("/_next/static/",),
        "probe_needles": ("webpack", "buildid", "next.js"),
        "probe_json": False,
    },
    {
        "id": "aspnet-viewstate",
        "playbook": "传承/残网·猎面.md",
        "cmd": "python3 炼蛊房/aspnet_surface_probe.py --base {base} --case {case}",
        "note": "SharePoint 仍走 sharepoint 专卡；禁止默认 gadget",
        "body": ("__viewstate", "__viewstateencrypted", "elmah.axd"),
        "headers": ("x-aspnet-version", "x-aspnetmvc-version"),
        "header_needles": ("asp.net",),
    },
    {
        "id": "grpc",
        "playbook": "传承/沉声·猎面.md",
        "cmd": "python3 炼蛊房/grpc_surface_probe.py --base {base} --case {case}",
        "note": "禁止 Rapid Reset；Unimplemented 只证明传输",
        "body": ("grpc-status", "application/grpc", "serverreflection"),
    },
    {
        "id": "sslvpn",
        "playbook": "传承/雾门·辨.md",
        "cmd": "python3 炼蛊房/sslvpn_surface_probe.py --base {base} --case {case}",
        "note": "网站案降权。FortiGate 交接 FortiOS 专卡",
        "body": ("anyconnect", "globalprotect", "fortigate", "webvpn=", "svpncookie", "citrix gateway"),
        "probes": (),
        "probe_needles": (),
        "probe_json": False,
    },
    {
        "id": "yudao-appapi",
        "playbook": "传承/芋府·微域.md",
        "cmd": "python3 炼蛊房/yudao_appapi_probe.py -u {base} --case {case}",
        "note": "TMA PLATFORM_ID / sk_encrypt；Qzino 不要套芋道信封",
        "body": ("platform_id", "/app-api/", "sk_encrypt", "yudao", "芋道", "app-config.js"),
    },
    {
        "id": "yudao-daifu-mock",
        "playbook": "传承/芋府·假面开天.md",
        "cmd": "python3 炼蛊房/yudao_daifu_probe.py recon --base {base} --case {case} --insecure",
        "note": "mock-enable / file-config / df-user；勿与 TMA 卡、FastAdmin 代付混",
        "body": (
            "/admin-api",
            "mock-enable",
            "file-config",
            "df-user",
            "stopQueryOrderJob",
            "ruoyi-vue-pro",
            "yudao.security",
        ),
    },
    {
        "id": "qzino",
        "playbook": "传承/商心慈·白标.md",
        "cmd": "python3 炼蛊房/yudao_appapi_probe.py -u {base} --case {case}",
        "note": "Qzino /api.html → telegram-tma-gambling",
        "body": ("qzino", "/api.html", "vue/config.js"),
    },
    {
        "id": "wp-plugin-unauth-20260815",
        "playbook": "传承/坞·接管.md",
        "cmd": "python3 炼蛊房/wp_plugin_unauth_probe.py -u {base} --case {case}",
        "note": "CVE-2026-15341/15303 ATO；14484/15965 文件面；8840/12128 假付。授权内打 L2，勿改原超管密",
        "body": (
            "user-session-synchronizer",
            "ussync-key",
            "6storage",
            "six_storage",
            "rapisafe",
            "rsmfcf7vars",
            "maxupload",
            "dopbsp",
            "object-sync-for-salesforce",
        ),
        # 官网 slug；禁止 tuxedo-big-file-uploads / invisible-recaptcha（同名不同插件）
        "probes": (
            "/wp-content/plugins/user-session-synchronizer/readme.txt",
            "/wp-content/plugins/6storage-rentals/readme.txt",
            "/wp-content/plugins/rapisafe-multi-file-cf7/readme.txt",
            "/wp-content/plugins/maxupload-upload-larger-files-easily/readme.txt",
            "/wp-content/plugins/booking-calendar/readme.txt",
            "/wp-content/plugins/booking-system/readme.txt",
            "/wp-content/plugins/object-sync-for-salesforce/readme.txt",
        ),
        "probe_needles": ("stable tag",),
        "probe_json": False,
    },
]


def _probe_paths(route: dict[str, Any]) -> list[str]:
    if route.get("probes"):
        return [str(p) for p in route["probes"]]
    p = route.get("probe")
    return [str(p)] if p else []


def probe_matches(
    *,
    status: int,
    body: str,
    content_type: str,
    needles: tuple[str, ...] | list[str],
    require_json: bool,
) -> bool:
    """API 探针默认要 JSON；readme/HTML 设 probe_json=False，且必须 200。"""
    if not needles or status >= 500:
        return False
    pb = (body or "")[:2000]
    if not any(n.lower() in pb.lower() for n in needles):
        return False
    if require_json:
        ctype = (content_type or "").lower()
        return "json" in ctype or pb.strip().startswith("{")
    return status == 200


def _get(sess: requests.Session, url: str) -> requests.Response | None:
    try:
        return sess.get(url, timeout=10, verify=False, allow_redirects=True)
    except Exception:
        return None


def run(base_url: str, case: str, out: Path | None) -> dict[str, Any]:
    host = host_of(base_url)
    if host and not in_scope(host):
        print(f"[!] 不在 scope：{host}", file=sys.stderr)
        sys.exit(2)
    base = base_url.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    home = _get(sess, base + "/")
    body = (home.text[:12000] if home is not None else "").lower()
    headers = {k.lower(): v.lower() for k, v in (home.headers.items() if home else [])}
    cookie = headers.get("set-cookie", "")
    xpb = headers.get("x-powered-by", "")
    server = headers.get("server", "")
    blob = body + " " + xpb + " " + server + " " + cookie

    hits: list[dict[str, Any]] = []
    if case:
        out_ph = str(ROOT / "案卷" / case / "测绘")
    elif out:
        out_base = out.parent if out.suffix else out
        if out_base.name == "vulns":
            out_base = out_base.parent
        out_ph = str(out_base)
    else:
        out_ph = "测绘"
    for route in ROUTES:
        why = []
        for w in route.get("body") or []:
            if w.lower() in blob:
                why.append(f"body:{w}")
        for h in route.get("headers") or []:
            if h in headers:
                why.append(f"hdr:{h}")
        for n in route.get("header_needles") or []:
            if n in xpb or n in server:
                why.append(f"hdr-needle:{n}")
        ck = route.get("cookie")
        if ck and ck in cookie:
            why.append(f"cookie:{ck}")
        needles = tuple(route.get("probe_needles") or ())
        require_json = bool(route.get("probe_json", True))
        for probe in _probe_paths(route):
            pr = _get(sess, urljoin(base + "/", probe.lstrip("/")))
            if pr is None:
                continue
            if probe_matches(
                status=pr.status_code,
                body=pr.text,
                content_type=pr.headers.get("Content-Type") or "",
                needles=needles,
                require_json=require_json,
            ):
                why.append(f"probe:{probe}:{pr.status_code}")
                break
        if not why:
            continue
        cmd = route["cmd"].format(base=base_url, out=out_ph, case=case or "CASE")
        row = {
            "id": route["id"],
            "why": why,
            "playbook": route["playbook"],
            "cmd": cmd,
            "note": route.get("note", ""),
        }
        hits.append(row)
        print(f"  → {route['id']}: {route['playbook']}")
        print(f"     {cmd}")

    fallback = {
        "id": "1day-nuclei",
        "playbook": "传承/补丁对照.md",
        "cmd": f"python3 tools/1day-kit/od_kit.py nuclei --url {base_url} --case {case or 'CASE'}",
        "note": "无专卡指纹时再跑 custom-templates；命中后仍要切专卡",
    }
    report = {
        "target": base_url,
        "ts": datetime.now(UTC).isoformat(),
        "title": "",
        "server": server,
        "hits": hits,
        "fallback": fallback,
        "playbook": "传承/补丁对照.md",
        "next": "先跑 hits[].cmd；不要只拿 CVE 编号盲打",
    }
    if home is not None:
        m = re.search(r"<title[^>]*>([^<]{1,120})</title>", home.text, re.I)
        if m:
            report["title"] = m.group(1).strip()
    out_path = write_probe_json(
        report, case=case, out=out, case_subdir="nday", filename="route.json",
    )
    print(json.dumps({"hits": [h["id"] for h in hits], "out": str(out_path)}, ensure_ascii=False))
    print(f"[+] wrote {out_path}", file=sys.stderr)
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="N-day 指纹→专卡路由")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    run(args.url, args.case, args.out)


if __name__ == "__main__":
    main()
