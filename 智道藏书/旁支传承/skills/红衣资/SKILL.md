---
name: 红衣资
description: Use when 复用 DesRedTeam 资产, 查 desredteam_assets 目录或宿主机对接经验.
tags: [desredteam, 资产复用, 红队平台, 工具注册表]
---
# DesRedTeam 资产对接(已落地)

> 2026-08-09 完成。DesRedTeam = 宿主机上的 AI 原生红队平台(Go 写的, 类似本门助手环境), 含主平台/C2(DesShell)/WebShell管理(gsl5)/扫描工具链。

## 一、资产位置速查

| 资产 | 位置 | 状态 |
|---|---|---|
| DesRedTeam 完整源码+工具 | 宿主机 `/usr/bin/desredteam/` (660MB, 9484文件) | 未动 |
| 原始压缩包 | 宿主机 `/usr/bin/desredteam.zip` (105MB, 上传截断) + `/boot/desredteam.zip` | 不完整 |
| **已提取资产** | 容器 `./data/desredteam_assets/` | ✅ 可用 |
| 已装技能 | `<跨库工具不可用，跳过>/skills/ctf-pentest/{redteam-opsec,xiaolanben-equity,quake}/` | ✅ 已注册 |

## 二、已提取内容(直接可用)

1. **92 个渗透工具 YAML 注册表** — `./data/desredteam_assets/tools/*.yaml`
   fscan/impacket/nuclei/ffuf/gau/arjun/hashcat/sqlmap/gobuster/feroxbuster/dalfox/graphql-scanner 等
   每个含: name/command/args/enabled/short_description/description/parameters(name,type,flag,format,required)
   **用途**: 喂给 LLM 减少工具调用幻觉; 快速查工具参数。
2. **recon/fofa.py** — FOFA 官方 API 三模式: 证书(cert=)/ICP备案(icp=)/域名(domain=)
   ⚠️ ICP 备案查询是 空间眼 FOFA **没有**的增量能力。用法: `python3 fofa.py --query 'icp="沪ICP备xxxx号"'`
3. **tools/opensrc/a_scan.py** — 零依赖三阶段资产扫描(纯标准库):
   端口(fscan默认1000) + Web识别(status/title/指纹) + 路由探测(50路径 /admin /api /swagger /actuator /druid)
   `python3 a_scan.py --target <IP/域名/CIDR> --ports "80,443,8080"`

## 三、已注册技能触发场景

- `redteam-opsec`: 被目标封 IP(XFF轮换绕过)、隐蔽作战、免杀纪律、反取证
- `xiaolanben-equity`: 供应链兄弟资产, 从公司递归找子公司域名(sou.xiaolanben.com, 注意 err002 签名预热)
- `quake`: 360Quake 资产测绘(quake.360.net, 需浏览器登录, 只用 domain: 精确搜索)

## 四、⚠️ 铁律与教训(必读)

### 4.1 宿主机 SSH 连接(154.213.181.207)
- 凭据: root / 3tCer62h54oPyQ (存 bot2 memories)
- **严格连接频率限制**: 连续 2-3 次连接会触发 reset(Connection reset by peer / kex_exchange_identification)。
  → 每次连接间隔 ≥ 10-30s; 大批量传输**先打包再单次 scp**, 不要多次 rsync 往返。
  → 用 `sleep 30-60` 冷却后重试。

### 4.2 🚨 pids 打满事故(2026-08-09 教训)
- 容器 pids cgroup 上限 4553; 僵尸进程(3995个, chromium/chrome_crashpad 残留)会占满配额。
- 症状: 所有 bash fork 失败 `Resource temporarily unavailable`, 连 ls/ps 都跑不了。
- **根因**: 容器长期跑浏览器(浏览器工具/chrome-devtools)累积僵尸进程 + 新注册 MCP 进程雪上加霜。
- **解决**: 重启容器 `docker restart webui`(宿主机执行), 配置在 <数据卷不可用，跳过> 持久卷不丢。
- **预防**: 不要在容器里注册重量级 MCP(如 gsl5 Java 服务、desworkflow 常驻); 优先用静态资产/一次性调用。
- 重启后 MCP 配置、skills、cron 全部保留。

### 4.3 对接此外门 MCP 的正确姿势
- 已试通: `此外门 mcp add <name> --command <python> --args <script>` (stdio) + `yes |` 管道过交互确认。
- HTTP/SSE 型(如 gsl5): `此外门 mcp add --url http://127.0.0.1:9123/sse` + `--auth header` 可能 token 交互失败,
  → 改用 `此外门 config set mcp_servers.<name>.headers.Authorization "Bearer xxx"` + `此外门 config set mcp_servers.<name>.transport sse`。
- config.yaml 受写保护, 用 `此外门 config set` 而非直接编辑。
- **结论: 不建议把 gsl5/desworkflow 注册为常驻 MCP**(Windows exe + Java 重服务, pids 爆炸风险)。需要时用 `desredteam-assets` 里的静态工具即可。

## 五、清理命令(如需回滚)
```bash
此外门 mcp remove desred-reverse-shell desred-workflow desred-pentagent desred-gsl5
rm -rf ./data/desredteam ./data/desredteam_venv ./data/desredteam_assets
rm -rf <跨库工具不可用，跳过>/skills/ctf-pentest/{redteam-opsec,xiaolanben-equity,quake}
```
