---
name: 棋道纵横
description: >-
  新目标 URL/域名的作战计划入口。触发：新目标、开始测试、怎么打、
  先从哪里入手、计划一下、作战计划、全扫一遍、kit_run、auto_campaign。
  已像网站/Java/PHP/盘口时用 kit_run，不知道栈时用 auto_campaign plan。
---

> **方源**
> 人是万物之灵，蛊是天地真精。
> 今朝剑指叠云处，炼蛊炼人还炼天！

# Campaign Router — 智能作战路由器

## 触发条件

用户给出一个新目标（URL/域名），且需要决定"用哪些工具/怎么打"时使用。
关键词：新目标、开始测试、怎么打、先从哪里入手、计划一下、作战计划、全扫一遍。

**成套入口**（散装探针的顺序+交接）：

```
炼蛊房/kit_run.py
```

```bash
python3 炼蛊房/kit_run.py list
python3 炼蛊房/kit_run.py run --kit web -u https://授权站 --case <案卷>
```

`auto_campaign.py` 仍是指纹菜单；已经像网站/Java/PHP/盘口时用 kit，不要 31 个工具平铺。

## 核心工具（菜单）

```
炼蛊房/auto_campaign.py
```

**菜单**（指纹 → 并列工具，不交接）。不知道栈时用。已经像网站/Java/PHP/盘口时改用上面的 kit_run。

## 立即执行步骤

### 第 1 步：生成作战计划（只读，1-5 秒）

```bash
python3 炼蛊房/auto_campaign.py plan -d <目标域名>
```

可选参数：
- `--admin <URL>`：已知后台地址（跳过猜测）
- `--case <案卷名>`：输出到 案卷/<案卷名>/

输出：
- 5 个阶段的工具列表（Phase 0 侦察 → 1 绕过 → 2 漏洞 → 3 接管 → 4 社工）
- 每个工具的触发原因 + 完整命令
- 目标指纹摘要（CDN/WAF/技术栈/功能模块）

### 第 2 步：执行（可选，自动运行全链）

```bash
# 全部执行
python3 炼蛊房/auto_campaign.py run -d <目标域名>

# 只执行侦察阶段
python3 炼蛊房/auto_campaign.py run -d <目标域名> --phases 0

# 执行侦察+绕过
python3 炼蛊房/auto_campaign.py run -d <目标域名> --phases 0,1

# 先预览再执行（dry-run）
python3 炼蛊房/auto_campaign.py run -d <目标域名> --dry-run

# 绑定现有案卷
python3 炼蛊房/auto_campaign.py run -d <目标域名> --case wldzylbot_20260810
```

## 工具激活规则（指纹 → 工具）

| 指纹特征 | 激活工具 |
|---------------------|--------------------------------------------------------------|
| 任何目标 | osint_recon + test_subdomain_enum + js_secret_hunter + dirbrute_probe + nday_route + jwt_gql_probe + 1day_nuclei |
| Cloudflare/CDN | origin_recon + cf_backup_bypass + ip_whitelist_bypass |
| 后台 403/IP 白名单 | ip_whitelist_bypass（全 7 个向量） |
| 博彩站 | yudao_appapi_probe + port_admin_scan + tg_cmd_enum + api_dispatcher + logic_vuln + ws_probe + stored_xss + agent_probe + social_engineer |
| Java/Spring | actuator_probe + fastjson_probe + java_web_surface_probe（含 cnoa 国产 OA 指纹）；heapdump 可达或已有 hprof → **立刻** heap_cred_scan（蓝鸟蜘蛛） |
| 通达/泛微/用友/致远 | java_web `--stack cnoa` + Playbook `传承/官衙·用友致远.md` |
| CF/CDN 缓存头 | `cache_poison_probe.py` → `web-cache-poisoning` |
| 支付且像 USDT | `usdt_attr_hijack.py chain-scan`（只读）并行 bind-dup |
| 盘口 IDOR 阴 | `ato_reset_withdraw_probe.py`（任意 code 重置 + 无旧密提现密，只打自己） |
| TG 云控 `main.wasm` / 掩码票 | `tg_cloud_panel_probe` 第四族 + `jwt_gql_probe --token 掩码票` |
| 案卷有 Chrome.rar / cookies.sqlite / fingerprint.json | `has_browser_loot` → `from-case --url`（分诊 + 整包回放授权 URL）；活会话再 `session_import` |
| 点名 PwnKit / GodPotato / Log4Shell / ADCS ESC / shell.zip 手法 | `hypothesis_route.py --signal` → `红衣·壳.md`（不部署 opus-injector） |
| Claude/Codex 拒答、助手没身份、要部署 CLAUDE.md | `开源版不带助手注入`（官方通道；禁止外部注入器） |
| Harbor / 容器仓库 | `nday_route`（指纹 `has_harbor`） |
| Jeecg/Shiro/Druid | java_web_surface_probe → 对应手法卡（Shiro 默认做 L2 弱密钥碰撞） |
| ThinkPHP / PHP | thinkphp_surface_probe（默认 Client-IP 差分 + `.env`；`--no-probe-ip-header` 才关） |
| TP3 README / `ApiUserFenxiao` / `chk_update` / 剪贴板劫持 | `tp3_fenxiao_probe.py`（禁止 message_delete OR；WAF 拦 TP5 不算结案） |
| XXL-JOB / `:9997` / `GLUE_SHELL` | `xxljob_admin_probe.py`（登录认 Cookie/302/JSON；授权内 GLUE 直接做） |
| 标题「TG号码管理」/ `/export/download/` | `tg_number_admin_probe.py`（弱口+只读头；改密/百万拖号先问） |
| 宝塔/PMA / 博彩 PHP | panel_surface_probe + port_admin_scan |
| Java 旁注 Redis | redis_unauth_probe（INFO + captcha 键名） |
| NGINX/OpenResty | nginx_rift_probe（CVE-2026-42945 版本/改写面；默认不打 RCE） |
| 有支付功能 | `pay_matrix`；PHP/`composer.json` 先 `sensitive_dir_dump` 抽商户钥 |
| `/dj.svg` `use_balance` | 交接 `dujiao-next-1yuan-pay`（勿 acg-faka） |
| `acg.js` / `shared_id` | `acg_probe` |
| `dujiaoka` / `detail-order-sn` | `faka-card-shop-pentest` + 假支付合法签 |
| 有代理体系 | agent_probe（BOLA + JWT 提权）+ social_engineer_agent |
| 有上传/URL预览 | ssrf_probe |
| CDN/OSS | bucket_probe |
| WAF | waf_sqli_bypass |
| LiteLLM / Langflow / `/v1/models` | llm_surface_probe → LiteLLM/Langflow 专卡（不做越狱） |

上表文件名对应本库路径（蒸馏认 `炼蛊房/*.py`）：

```bash
python3 炼蛊房/test_subdomain_enum.py --help
python3 炼蛊房/dirbrute_probe.py --help
python3 炼蛊房/fastjson_probe.py --help
python3 炼蛊房/redis_unauth_probe.py --help
python3 炼蛊房/bucket_probe.py --help
python3 炼蛊房/ip_whitelist_bypass.py --help
python3 炼蛊房/waf_sqli_bypass.py --help
```

## 重要说明

- `auto_campaign.py plan` 是**只读操作**，不会发送任何攻击性请求
- 只有 `run` 命令才真正调用子工具
- 指纹识别约需 3-8 秒（HTTP 探测），之后立即输出计划
- 每个阶段可独立执行（`--phases 0,1,2` 等）
- 所有工具输出都写入 `案卷/<domain>_auto/`

## 与其他 Skill 的关系

- 业务站/后台/API 分流总卡 → `传承/凤九歌·天地歌.md`（设备洞降权）
- 只丢工具名/手法名 → `传承/凤金煌·分音.md`
- 无专用栈 → **先** `strike_probe.py`（S1–S8）再 `薄青·岁岁索命.md` + `authz-probe`
- 发现 `/actuator` → 切换到 `spring-actuator-cloud-takeover` Skill
- 发现 `/actuator/heapdump` 或案卷 `.hprof` → **立刻** `heapdump-lanniao-hunter` / `heap_cred_scan.py`（不问蓝鸟）
- 发现支付回调 → 切换到 `payment-callback-forgery` Skill 
- 收工 / 写结案 → `evidence_gate.py --from-status` + `object_matrix check`（口头结论对测绘原文，禁止 STATUS 自证）
- 需要社工 → `tg-account-library` + `social_engineer_agent.py`（技术面穷尽 + 入场券）
- 号库/session 投递 → `tg-account-library`
- 博彩站/赌博台 → 先 `传承/凤九歌·认族.md`，细链 `商燕飞·盘口.md`
- 白标/芋道 TMA/`sk_encrypt`/Qzino → `yudao_appapi_probe.py` + `商心慈·白标.md`
- IP 白名单挡住 → `传承/踪·破禁.md`
