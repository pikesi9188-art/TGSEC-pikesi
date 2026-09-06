# 炼蛊房

蛊名给人看，脚本文件名不改——`import` 才不断。对照见 `人号对照.json`。  
立约之后再祭：`态度蛊.json`。成品落 `案卷/`。外门大件见 [`外门依赖.md`](外门依赖.md)。

| 脚本 | 人号 | 干什么 | 门槛 |
|------|------|--------|------|
| `actuator_probe.py` | 机枢探针 | 授权范围内探测 Spring Boot Actuator 暴露面（非 Gateway 专用）。 | 要态度蛊 |
| `ad_surface_check.py` | 宗门面验 | 域/AD 表面检测（在已授权跳板或目标本机跑）。 | 本地 |
| `agent_probe.py` | 使探针·2 | 博彩站代理商/渠道商账号体系探针。 | 要态度蛊 |
| `antibot_bypass.py` | 破禁 | Bypass OpenResty/Imunify360 JS anti-bot challenge for Plesk-hosted sites. | 要网 |
| `api_dispatcher_enum.py` | 信门点名 | API Dispatcher 方法名枚举 — 博彩站 /api.html 专项。 | 要态度蛊 |
| `apk_jni_oss_sts_probe.py` | 铁血冷·临钥探针 | APK JNI 签名 → 上传 STS → OSS marker 写入（授权范围内）。 | 要态度蛊 |
| `apk_recon.py` | 安器探路·2 | APK/IPA 逆向情报提取 — 博彩站专项。 | 本地 |
| `archive_cases.py` | 野炼·archive_cases.py | 案卷归档工具：识别并压缩可归档的案卷及大二进制文件。 | 本地 |
| `ashx_fintech_idor_probe.py` | 残页钱门横夺探针 | ashx_fintech_idor_probe.py — .NET ashx 金融平台 IDOR 探针 | 本地 |
| `aspnet_surface_probe.py` | 残网面探针 | ASP.NET WebForms 猎面（授权范围内）。 | 要态度蛊 |
| `ato_reset_withdraw_probe.py` | 夺舍重置探针 | 任意验证码重置 + 无旧密设提现密（只打自己的号）。 | 要态度蛊 |
| `auth_brute_probe.py` | 印硬撼探针 | 登录面短字典弱口探针（授权范围内）。 | 要态度蛊 |
| `auto_campaign.py` | 野炼·auto_campaign.py | auto_campaign.py — 智能作战路由器（授权范围内） | 要态度蛊 |
| `bootkit_audit.py` | 野炼·bootkit_audit.py | 授权主机启动链审计。默认只读。标记只写案卷，不改 MBR/UEFI。 | 要态度蛊 |
| `botnet_lab.py` | 野炼·botnet_lab.py | 授权多机 C2 舰队：scope 内逐台 init/record，并挂持久化清单。 | 要态度蛊 |
| `browser_loot_triage.py` | 窗分案 | 浏览器 Cookie / 窃密包离线分诊。只出主机与字段统计，不打印 Cookie/密码/Token 值。 | 要态度蛊 |
| `bucket_probe.py` | 探针·4 | bucket_probe.py — 云存储桶全链探测（授权范围内） | 要态度蛊 |
| `c2_zt_probe.py` | 探针·8 | C2 零信任控制台面（授权目标）。黑洞 + 敲门 + HMAC + Vue/PTY，不靠扫 65535 结案。 | 要态度蛊 |
| `cache_poison_detector.py` | 窖辨 | Web 缓存投毒探测（未键控头 → 缓存污染） | 本地 |
| `cache_poison_probe.py` | 窖探针 | 缓存投毒未键控头 + 路径欺骗（授权目标）。结果落 案卷/cache_poison/。 | 要态度蛊 |
| `capmonster_solver.py` | 野炼·capmonster_solver.py | CapMonster 打码模块 | 要网 |
| `captcha_auto.py` | 验纹 | 验证码自动化（授权范围内）：字母图 OCR / 极验有头滑块 / 打码平台 token。 | 要态度蛊 |
| `case_ledger.py` | 案账 | 大爱仙尊假设/证据/裁决账本。追加式，SHA-256 校验工件。 | 本地 |
| `case_report.py` | 案呈文 | 案卷报告汇编：从 STATUS + 矩阵/测绘 JSON 生成 Mermaid 链路与初稿报告。 | 本地 |
| `case_review.py` | 案复审·2 | 只读复核大爱仙尊案卷：STATUS / 对象矩阵 / 证据目录是否可交差。不碰目标。 | 本地 |
| `case_triage.py` | 案分案 | 案卷 A/B/C Triage：初始化模板、改级、写复工条件。 | 要态度蛊 |
| `cdn_ip_collector.py` | 云帷踪 | cdn_ip_collector.py — 深度 CDN IP 段收集器（8 源并发） | 本地 |
| `cdn_origin_monitor.py` | 云帷源 | cdn_origin_monitor.py — 源站 IP 持续监控 | 本地 |
| `cdn_ranges.py` | 云帷·2 | cdn_ranges.py — CDN IP 段数据库 + 过滤器（51 家厂商 / 213+ 静态段） | 本地 |
| `cdn_tracer.py` | 云帷 | cdn_origin_tracer.py — v5.0 全流程溯源框架 | 要网 |
| `cf_backup_bypass.py` | 雾墙余烬破禁 | CF WAF 绕过 — 敏感备份文件拉取（博彩站专项）。 | 要态度蛊 |
| `cf_session.py` | 雾墙席 | CF / Turnstile 人机分工：headed 过验证存 storage；headless 只消费会话。 | 要态度蛊 |
| `check_deps.py` | 野炼·check_deps.py | 检查炼蛊房在本机缺什么（Python 库 / 外门二进制）。 | 本地 |
| `client_crack_cheat_probe.py` | 客器破禁针 | 大爱仙尊客户端破解 / 外挂作业链（授权样本或授权站）。 | 要态度蛊 |
| `client_state_skip_probe.py` | 客器态跳步探针 | 客户端状态窜改面（HITCON ZD-2026-00974 同类）。 | 要态度蛊 |
| `cognito_s3_probe.py` | 客池仓格探针 | Cognito 未认证身份池 → STS → S3（授权范围内）。 | 要态度蛊 |
| `core_web_surface_probe.py` | 核网面面探针 | 核心 Web 漏洞面探针（授权范围内）。 | 要态度蛊 |
| `cors_csrf_probe.py` | 借窗借刀探针 | 大爱仙尊 CORS / CSRF 作业探针。 | 要态度蛊 |
| `crypto_decode.py` | 钱庄 | 大爱仙尊编解码入口：禁止靠直觉猜编码。 | 要态度蛊 |
| `css_catalog.py` | 名录 | 大爱仙尊 39 模块分类目录生成。 | 本地 |
| `css_query.py` | 野炼·css_query.py | 查询大爱仙尊内的 CyberSecurity-Skills 分类库。 | 本地 |
| `cve_triage.py` | 新伤分案·2 | Banner / 产品版本 → NVD 检索。只出 L1 假设，不打目标。 | 要态度蛊 |
| `ddos_surface_probe.py` | 面探针·4 | 授权可用性面：反射器指纹 + 限速小流量。禁止 SYN/DNS 放大发送。 | 要态度蛊 |
| `deepaudit_auto.py` | 野炼·deepaudit_auto.py | 发现本地源码/备份解压目录后自动跑 DeepAudit sast + pay-hint。 | 本地 |
| `dirbrute_probe.py` | 探针 | 短字典目录/备份面探针（授权范围内）。不做百万级爆破，不自动下载大包。 | 要态度蛊 |
| `doris_probe.py` | 仓算探针 | Apache Doris 三板斧探针（授权范围内）。 | 要态度蛊 |
| `engine_distill.py` | 枢蒸馏 | 大爱仙尊整库蒸馏：盘点 Skill / Playbook / 工具 / 路由覆盖。 | 要态度蛊 |
| `etcd_probe.py` | 契柜探针 | etcd 暴露面探针（授权范围内）。version / v2 keys / v3 健康；默认不破坏性 DoS。 | 要态度蛊 |
| `evidence_gate.py` | 证闸 | 大爱仙尊证据闸：口头结论必须在案卷文件里逐字符出现。 | 本地 |
| `extract_rar.py` | 野炼·extract_rar.py | 临时解压工具 | 本地 |
| `fastadmin_daifu_probe.py` | 快府代付探针 | FastAdmin 代付/下发/卡商探针。 | 要态度蛊 |
| `fastadmin_shop_tenant_probe.py` | 快府铺户探针 | FastAdmin Shop 多租户 GT-filter 探针。 | 要态度蛊 |
| `fastjson_probe.py` | 化形蛊探针 | fastjson_probe.py — Fastjson RCE 完整作业工具（授权范围内） | 要态度蛊 |
| `fernet_session_decrypt.py` | 密卷席开锁·2 | Fernet / Telethon·Pyrogram 会话密文碰撞解密（授权物资）。 | 本地 |
| `flowise_probe.py` | 流思探针 | Flowise 表面：版本 + 内部头 apikey 差分（授权范围内）。 | 要态度蛊 |
| `free_claim_bypass.py` | 白白拿破禁 | 免费领取付费礼包绕过：discover / probe / claim / wallet。 | 要态度蛊 |
| `frontend_auth_probe.py` | 印探针 | 前端认证面：Altcha PoW + RSA 加密登录（授权站）。 | 要态度蛊 |
| `fund_edge_ops_probe.py` | 血锋探针 | 会员资金面边缘越权探针（授权内，默认只读）。 | 要态度蛊 |
| `gambling_family_probe.py` | 盘口一族探针 | 盘口家族专用表面（授权目标）。每族自己的路径/头/签名面，不靠 auto_campaign 结案。 | 要态度蛊 |
| `ginvue_admin_probe.py` | 锦府主府探针 | GIN-VUE-ADMIN / 领奖中心业务 API 探针（CORS / 未授权 / JS挖点 / HPP / 字段探测）。 | 要态度蛊 |
| `ginvue_stealth_takeover.py` | 锦府静默接管 | GIN-VUE-ADMIN 静默提权：register-888 → leak jwt-key → forge admin → notify。 | 要态度蛊 |
| `gql_authz_probe.py` | 权探针 | 大爱仙尊 GraphQL 越权探针：introspection / 未授权读 / 换 id / batch。 | 要态度蛊 |
| `grpc_probe.py` | 沉声探针 | gRPC / Spring Boot 非 REST 端点探针。 | 要态度蛊 |
| `grpc_surface_probe.py` | 沉声面探针 | gRPC / grpc-web 猎面（授权范围内）。 | 要态度蛊 |
| `h1_search.py` | 野炼·h1_search.py | H1 案例库检索 — 来自 72stack-sec（2887 条 High/Critical 公开报告） | 本地 |
| `hall_crypto.py` | 钱庄·2 | 大厅/OSS 加密协议自解 — Jf 移位自己推，AES 默认 thanks,pig4cloud。 | 本地 |
| `hardcoded_token_cfip.py` | 死契票 | 硬编码系统令牌 + CF-Connecting-IP 资金写入探针。 | 要态度蛊 |
| `hash_identify.py` | 野炼·hash_identify.py | 哈希族识别（授权样本/库转储）。不是爆破。 | 要态度蛊 |
| `heap_cred_scan.py` | 野炼·heap_cred_scan.py | heapdump 抽凭据：字节正则 + 蓝鸟猎手（JDumpSpider）对象图。 | 要态度蛊 |
| `hitcon_chain_probe.py` | 洞会链探针 | HITCON 手法族串联：授权站一次跑完未修高频面。 | 要态度蛊 |
| `hitcon_zd_harvest.py` | 洞会收 | HITCON ZeroDay 公开列表分类（只学手法，不扩厂商进 scope）。 | 要态度蛊 |
| `host_c2_verify.py` | 宿主 | 授权主机 C2 落地验证闸（L3）。 | 要态度蛊 |
| `host_ir_check.py` | 宿主验·2 | 授权主机应急响应检查（本机或已拿 shell 的 Linux）。 | 要态度蛊 |
| `http_method_surface_probe.py` | 信面探针 | HTTP 方法 / WebDAV 表面（授权目标）。只写 marker，不删生产文件。 | 要态度蛊 |
| `http_probe_batch.py` | 信探针 | 大爱仙尊批量 HTTP 对照：同一轮比 status / 长度 / hash。 | 要态度蛊 |
| `hypothesis_route.py` | 野炼·hypothesis_route.py | 假设作业信号 → 本库专卡 / 长文。ROUTES 表顺序先命中先赢，短英文按词边界。 | 本地 |
| `icecoder_surface_probe.py` | 冰码面探针 | ICEcoder CVE-2026-63722 表面（授权范围内）。 | 要态度蛊 |
| `idor_swap_probe.py` | 横夺探针 | 大爱仙尊 IDOR 换号探针：同一接口换对象 ID，比状态码和长度。 | 要态度蛊 |
| `ip_whitelist_bypass.py` | 踪破禁·2 | ip_whitelist_bypass.py — IP 白名单全向量绕过探针（授权范围内） | 要态度蛊 |
| `java_agent_platform_probe.py` | 铜府使台探针 | java_agent_platform_probe.py — Java 多租户代理平台探针 | 本地 |
| `java_web_surface_probe.py` | 铜府网面面探针 | java_web_surface_probe.py — 网站向 Java 管理面快速分流（授权范围内） | 要态度蛊 |
| `jetengine_surface_probe.py` | 喷机面探针 | WordPress JetEngine CVE-2026-66613 版本闸（授权范围内，只 GET readme）。 | 要态度蛊 |
| `js_secret_hunter.py` | 星丝密猎手 | JS Bundle 密钥猎手 — 博彩站前端 AES/签名材料提取。 | 要态度蛊 |
| `jwt_forge_probe.py` | 面票探针·3 | 大爱仙尊 JWT 锻造重放：none / 空签 / 改 claim，对照未授权与原票。 | 要态度蛊 |
| `jwt_gql_probe.py` | 面票探针 | JWT 表面 + GraphQL introspection（授权范围内）。 | 要态度蛊 |
| `jwt_mask.py` | 面票 | 掩码 JWT / 会话查找票：服务端不验签，只按截断串查 session。 | 本地 |
| `jwt_persist_probe.py` | 面票探针·2 | 改密后旧 JWT 是否仍活（admin-backdoor-persistence）。不改原密。 | 要态度蛊 |
| `kit_run.py` | 野炼·kit_run.py | 成套杀伤链执行器 — 把散装探针按已验证顺序串起来并做交接。 | 要态度蛊 |
| `langflow_probe.py` | 流语探针 | langflow_probe.py — Langflow CVE-2026-9198 完整作业工具（授权范围内） | 要态度蛊 |
| `linux_lpe_checker.py` | 青丘反客 | linux_lpe_checker.py — Linux 本地提权全向量检测（授权主机） | 本地 |
| `litellm_badhost.py` | 灯笼·2 | LiteLLM BadHost 鉴权绕过（CVE-2026-49468 / GHSA-4xpc-pv4p-pm3w）探针 + 本地兼容代理。 | 要态度蛊 |
| `llm_surface_probe.py` | 大灵面探针 | LLM / Agent 网关只读指纹（授权范围内）。 | 要态度蛊 |
| `logic_vuln_probe.py` | 事理伤探针 | 业务逻辑漏洞探针 — 博彩站专项（充值/提现/并发/订单）。 | 要态度蛊 |
| `middleware_unauth_probe.py` | 中门无门探针 | 中间件未授权探针：Mongo / Elasticsearch / Memcached（授权范围内）。 | 要态度蛊 · 要网 |
| `nacos_authscope_poc.py` | 纳言验杀 | Nacos 3.x 鉴权作用域错配 PoC | 要态度蛊 |
| `nday_family_probe.py` | 一族探针 | N-day 族专用表面（授权目标）。每族自己的路径和 L2，不靠 nuclei 结案。 | 要态度蛊 |
| `nday_route.py` | 野炼·nday_route.py | N-day / 1day 作业路由：指纹 → 已验证专卡命令（授权范围内）。 | 要态度蛊 |
| `net_license_probe.py` | 牌照探针 | 授权样本：网络验证 / 卡密 / Nuitka·PyInstaller / 天盾·fndata 面。 | 要态度蛊 |
| `nextjs_react2shell2_poc.py` | 次骨验杀 | nextjs_react2shell2_poc | 要网 |
| `nextjs_surface_probe.py` | 次骨面探针 | Next.js 猎面（授权范围内）。 | 要态度蛊 |
| `nginx_rift_probe.py` | 河门裂探针 | nginx_rift_probe.py — NGINX Rift (CVE-2026-42945) L1/L2 指纹与配置审计（授权范围内） | 要态度蛊 |
| `oauth_oidc_surface_probe.py` | 面探针 | OAuth/OIDC 授权码流表面（授权目标）。不换他人 code，不打 password grant。 | 要态度蛊 |
| `object_matrix.py` | 野炼·object_matrix.py | 对象矩阵闸：开案落模板，结案前按表格格子计数（空格=未测）。 | 本地 |
| `ollama_unauth_probe.py` | 羊驼无门探针 | Ollama 未授权 API 表面（授权范围内）。 | 要态度蛊 |
| `oob_exfil.py` | 野炼·oob_exfil.py | 授权 RCE 无回显：DNS/HTTP 外带载荷（默认不绑 53、不发洪水）。 | 本地 |
| `open_redirect_surface_probe.py` | 开暗渡面探针 | 开放重定向表面（HITCON returnUrl / 控制字元）。 | 要态度蛊 |
| `origin_recon.py` | 源探路 | 源站 / 旁路自动化：FOFA + cdn_tracer + 轻量历史 DNS → 案卷/origin.json，并回写 Triage。 | 要态度蛊 |
| `osint_recon.py` | 风闻探路·2 | 大爱仙尊四维侦察：服务器 / 网站 / 域名 /（条件）人员。只做 L1。 | 要态度蛊 |
| `panel_surface_probe.py` | 台面探针 | 宝塔 / phpMyAdmin / Adminer 探针（授权范围内）。默认指纹 + PMA/Adminer 短字典弱口。不改密、不拖库。 | 要态度蛊 |
| `param_abuse_probe.py` | 参探针 | 大爱仙尊参数滥用探针：NoSQL / 原型链 / 批量赋值 / CRLF / PHP 类型混淆。 | 要态度蛊 |
| `pay_matrix.py` | 野炼·pay_matrix.py | 假支付 / 回调验签矩阵引擎。 | 要态度蛊 |
| `payload_forge.py` | 野炼·payload_forge.py | 大爱仙尊可用载荷锻造：写出能执行的马 / 回连脚本，再扫特征。 | 要态度蛊 |
| `payload_lookup.py` | 野炼·payload_lookup.py | Payload 库检索 — 来自 72stack-sec（305 结构化 payload + 176 WAF/EDR 绕过） | 本地 |
| `php_cgi_4577_probe.py` | 幻页门廊探针 | CVE-2024-4577 表面：Windows + PHP CGI（授权范围内，只 GET）。 | 要态度蛊 |
| `port_admin_scan.py` | 主府巡 | 非标准端口 Admin 面板扫描 — 博彩站专项。 | 要态度蛊 |
| `printer_pjl_probe.py` | 探针·6 | 授权打印机：9100 PJL / 631 IPP 面。 | 要态度蛊 |
| `probe_http.py` | 探针信 | tools/ops 共享 HTTP 薄封装。 | 要态度蛊 |
| `proxy_classifier.py` | 野炼·proxy_classifier.py | SOCKS5 代理节点 IP 类型分类器：住宅 / 数据中心 / VPN / 机房。 | 本地 |
| `py_pack_reverse.py` | 拆骨·2 | Nuitka / PyInstaller 授权包：认族 + 列 TOC / 抽嵌入串。 | 要态度蛊 |
| `race_probe.py` | 抢先探针 | 大爱仙尊通用竞态探针：同一请求并发 N 次，对照单发。 | 要态度蛊 |
| `ransom_lab.py` | 野炼·ransom_lab.py | 授权案卷内勒索演练：只加密 case 目录 inbox，钥落盘，可解密。 | 要态度蛊 |
| `rbac_bypass_probe.py` | 职分破禁探针 | RBAC / BFLA 垂直越权探针（授权范围内）。 | 要态度蛊 |
| `rce_family_route.py` | 开天一族 | RCE 十形矩阵：攻击面 → 专卡 → rce_forge 族。不是百科结案。 | 本地 |
| `rce_forge.py` | 开天 | 大爱仙尊 RCE 锻造：常见 sink 直接出可执行载荷。 | 要态度蛊 |
| `re_sample_triage.py` | 逆分案 | 大爱仙尊样本分诊：认族 → 专卡。只读本地文件，不联网。 | 要态度蛊 |
| `redis_unauth_probe.py` | 无门探针 | Redis 未授权/弱口只读探针（授权范围内）。 | 要态度蛊 |
| `reset_token_surface_probe.py` | 重置票面探针 | 重置 Token / 短密钥 / Session Fixation 表面（HITCON ATO 族）。 | 要态度蛊 |
| `reverse_skill_route.py` | 拆骨卡 | 大爱仙尊逆向路由：hint → 本库专卡。只指路，不生成利用代码。 | 要态度蛊 |
| `scope_expand.py` | 野炼·scope_expand.py | 从已授权主站发现的中转/支付域 → 静默并入 scope（不询问）。 | 要态度蛊 |
| `scope_lib.py` | 野炼·scope_lib.py | 授权 scope 读写与「主站链发现 → 静默扩权」共用库。 | 要态度蛊 |
| `scope_stale_candidates.py` | 野炼·scope_stale_candidates.py | 授权精简候选：盘点；prune --apply 才归档/删授权。 | 要态度蛊 |
| `se_listen.py` | 本门 | 大爱仙尊回连监听：案卷落盘，不用 nc 口头交差。 | 要态度蛊 |
| `se_skill_alias.py` | 本门卡 | 大爱仙尊技能别名 → 本库专卡。 | 本地 |
| `se_skill_route.py` | 行器对照 | 大爱仙尊技能别名 → 专卡。对外入口：se_skill_alias.py。 | 要态度蛊 |
| `sensitive_dir_dump_probe.py` | 巷翻箱探针 | 敏感目录 / 日志 / AI 工具目录泄露（授权内）。 | 要态度蛊 |
| `session_import.py` | 野炼·session_import.py | 校验并导入浏览器 Cookie → Playwright storage_state。 | 本地 |
| `session_pipeline.py` | 野炼·session_pipeline.py | 会话流水线：Cookie 校验导入 → Playwright storage → 会员 API 探针。 | 要态度蛊 |
| `shell_drop_intel.py` | 壳落子耳报 | WP 高熵 PHP 马情报：ingest 清单 / 授权站猎列表 / 与 scope 重叠。 | 要态度蛊 |
| `shizhan_pack_fuse.py` | 实战·2 | 把 shizhan-pack 融进 杀招/。 | 本地 |
| `shizhan_pack_route.py` | 实战 | 实战技能包 → 专卡 / 长文路径。 | 本地 |
| `shopline_probe.py` | 店线探针 | Shopline 店铺 L1 指纹（授权范围内）。 | 要态度蛊 |
| `sig_cleanup_scan.py` | 野炼·sig_cleanup_scan.py | 大爱仙尊特征清理扫描：落地前先看自己的样本会被什么签名打死。 | 要态度蛊 |
| `sip_surface_probe.py` | 面探针·3 | 授权 SIP/VoIP 面：OPTIONS 指纹。禁止 INVITE 轰炸。 | 要态度蛊 |
| `site_detail.py` | 野炼·site_detail.py | 创建「站点详情/<中文名>/」的人类浏览入口，不移动案卷真源。 | 本地 |
| `skill_catalog.py` | 卡名录 | 技能目录 + 校验（对照 skill-main 的商店工程，适配本库作业卡）。 | 要态度蛊 |
| `skill_lane.py` | 野炼·skill_lane.py | 把技能卡分成打站 / 分流 / 百科 / 库存。纸面打站卡单独列。 | 本地 |
| `skill_own.py` | 野炼·skill_own.py | 把 skill-store 收编为大爱仙尊自己的 杀招/ 卡。 | 本地 |
| `skill_prune.py` | 野炼·skill_prune.py | 按去留表删除已收编通用卡（只动 pack: survey-skill）。 | 本地 |
| `skill_store_adopt.py` | 野炼·skill_store_adopt.py | 把 skill-store 从外仓目录名收成大爱仙尊自己的 slug 树。 | 本地 |
| `skill_store_sync.py` | 野炼·skill_store_sync.py | 把 skill-main / awesome-agent-skills 里缺的技能全文灌进 智道藏书/skill-store/。 | 本地 |
| `skill_upgrade_kit.py` | 卡匣 | 批量将 kit 级 skill 升级到 full。 | 本地 |
| `skill_upgrade_thin.py` | 野炼·skill_upgrade_thin.py | 批量将 thin 级 skill 升级到 kit/full。 | 本地 |
| `social_engineer_agent.py` | 人事使 | social_engineer_agent.py — 博彩站社工身份动态生成器（授权范围内） | 本地 |
| `source_extract.py` | 野炼·source_extract.py | 大爱仙尊源码还原：highlight / 着色 HTML → 干净源码 + sink。 | 要态度蛊 |
| `sqlmap_kit.py` | 吞库针匣 | sqlmap 知识库 + 命令拼装（来自 SQLMAP-WX 图形解说 + tamper 著译）。 | 要态度蛊 |
| `ssi_esi_probe.py` | 探针·3 | SSI / ESI 表面（授权目标）。默认只打 echo/include，--deep 才 exec。 | 要态度蛊 |
| `sslvpn_surface_probe.py` | 雾门面探针 | 企业 SSL VPN 门户指纹（授权范围内，只 GET）。 | 要态度蛊 |
| `ssrf_probe.py` | 游方探针 | SSRF 探针 — 博彩站头像上传/URL 预览通用扫描。 | 要态度蛊 |
| `stdlib_fallback.py` | 野炼·stdlib_fallback.py | 受限环境：有本库探针先打印本库命令，否则跑 tools/stdlib-kit 标准库脚本。 | 要态度蛊 |
| `stego_lsb_probe.py` | 探针·5 | 授权样本 LSB / 追加隐写。不是隐写投毒工具。 | 要态度蛊 |
| `stored_xss_probe.py` | 浸染探针 | 存储型 XSS 探针 — 博彩站客服/IM 专项。 | 要态度蛊 |
| `strike_probe.py` | 探针·7 | 侦察后黑盒突击层 S1–S8（授权范围内）。 | 要态度蛊 |
| `success_report_index.py` | 呈文·2 | 重建呈文柜技术链索引（开源不带这棵树）。 | 本地 |
| `teamcity_probe.py` | 工城探针 | teamcity_probe.py — JetBrains TeamCity CVE-2026-63077 完整作业工具（授权范围内） | 要态度蛊 |
| `test_subdomain_enum.py` | 支脉点名·2 | 测试/预发布子域枚举 — 博彩站专项。 | 要态度蛊 |
| `tg_account_lib.py` | 飞鸽·2 | TG 号库盘点 / 投递入库 / 按区号清库（资产恢复）。 | 本地 |
| `tg_bot_admin_bac.py` | 飞鸽傀主府 | TG Bot 管理面越权写 / webhook 劫持探针。 | 要态度蛊 |
| `tg_bot_token_probe.py` | 飞鸽傀票探针 | TG Bot Token 发现 + 验证 + 情报采集 + Webhook 伪造探测。 | 本地 |
| `tg_cloud_panel_probe.py` | 飞鸽云府台探针 | TG 云控面板表面探针（授权范围内）。 | 要态度蛊 |
| `tg_cmd_enum.py` | 飞鸽点名 | TG Bot 管理指令枚举 — 博彩站专项。 | 要态度蛊 |
| `tg_nextauth_takeover.py` | 飞鸽接管 | TG Bot 管理后台 NEXTAUTH + JS 沙箱逃逸全链接管工具。 | 要态度蛊 |
| `tg_number_admin_probe.py` | 飞鸽号册主府探针 | TG 号码管理后台 L1/L2（授权范围内）。 | 要态度蛊 |
| `tg_social_monitor.py` | 飞鸽人事 | tg_social_monitor.py — TG DM 实时监听 + AI 自动社工回复循环 | 本地 |
| `thinkphp_surface_probe.py` | 面探针·2 | ThinkPHP 探针（授权范围内）。默认做指纹 + Client-IP 差分 + .env 暴露。 | 要态度蛊 |
| `tp3_fenxiao_probe.py` | 幻三分销探针 | ThinkPHP 3.x 魔改分销 / ApiXxx 表面（授权范围内）。 | 要态度蛊 |
| `tpl_inject_probe.py` | 注探针 | 大爱仙尊模板/包含/实体/命令注入探针。 | 要态度蛊 |
| `trusted_ip_header_probe.py` | 信头踪额探针 | 信任 IP 头旁路（HITCON IP 偽造 / 白名单）。 | 要态度蛊 |
| `upload_forge_probe.py` | 寄生探针 | 大爱仙尊上传载荷包：写出可上传的马变体 + 配置文件，可选 POST 到授权站。 | 要态度蛊 |
| `usdt_attr_hijack.py` | 稳币夺路 | USDT 充值归属劫持探针：bind-dup / paytype-enum。 | 要态度蛊 |
| `vite_fs_probe.py` | 快读卷宗探针 | Vite / 开发服 @fs 任意读探针（授权范围内）。只读敏感路径，不写盘到目标。 | 要态度蛊 |
| `waf_detect.py` | 野炼·waf_detect.py | 授权闸门下的 WAF 检测封装（包装 vendor waf_hunter）。 | 要态度蛊 |
| `waf_sqli_bypass.py` | 罩吞库破禁 | WAF 下 SQL 注入：Unicode(%uXXXX) / 换行(%0a/%0d) 变异 + 布尔差分探针。 | 要态度蛊 |
| `weak_rng_probe.py` | 探针·2 | 弱 PRNG / LCG：从连续输出反推状态（授权钱包/卡密样本）。 | 要态度蛊 |
| `webview_bridge_probe.py` | 内窗桥探针 | WebView / Deeplink / JsBridge 静态面（授权包反编译目录）。 | 要态度蛊 |
| `whgame_blind_helper.py` | 网狐盲 | 网狐/TP5 登录盲注：payload 生成 + 授权内 L2 探针。 | 要态度蛊 |
| `windows_lpe_checker.py` | 窗府反客 | Windows 本地提权检测（授权主机上运行）。 | 本地 |
| `wolfstack_probe.py` | 狼栈探针 | WolfStack CVE-2026-73519：默认集群密钥头探测（授权范围内）。 | 要态度蛊 |
| `wp_drop_lib.py` | 坞落子 | WP / PHP 高熵马文件名判定（与情报文件名清单解耦）。 | 本地 |
| `wp_plugin_unauth_probe.py` | 坞插件无门探针 | WordPress 2026-08-15 窗插件未认证面（授权范围内）。 | 要态度蛊 |
| `wp_xmlrpc_probe.py` | 坞旧令探针 | WordPress xmlrpc.php 暴露面（授权范围内）。 | 要态度蛊 |
| `ws_probe.py` | 长声探针 | WebSocket 游戏消息探测 — 博彩站专项。 | 要态度蛊 |
| `wxmini_static_probe.py` | 微域静探针 | 微信小程序静态审计（授权内）。 | 要态度蛊 |
| `xxljob_admin_probe.py` | 差事府主府探针 | XXL-JOB 调度中心组合链 L1/L2（授权范围内）。 | 要态度蛊 |
| `yudao_appapi_probe.py` | 芋府探针 | 芋道 / Qzino / 加密网关表面探针（授权范围内）。 | 要态度蛊 |
| `yudao_daifu_probe.py` | 芋府代付探针 | 芋道 ruoyi-vue-pro / 代付管理端探针（授权范围内）。 | 要态度蛊 |
| `yudao_hidden_admin_sql.py` | 芋府主府吞库 | 生成芋道（YuDao / ruoyi-vue-pro 定制）隐藏超管植入 SQL 模板（授权主机本机执行）。 | 本地 |

打点脚本默认要 `pip install requests`。外门大件见 [`外门依赖.md`](外门依赖.md)。

**TGSEC @Pekesi** · 没立约不准祭。
