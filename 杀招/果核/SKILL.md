---
name: 果核
description: >-
 学习并执行 Node.js + .node 原生模块 + 自定义 BPP 二进制协议的十步利用链：
 JS密钥提取 → 弱口令/JWT → 二阶SQL/跨库 → 发现.node → 抽ELF → BPP逆向 →
 发BPP → 整数溢出崩溃 → ASLR泄露 → ROP读flag。仅在授权目标且技术栈匹配时使用。
---

# Node/.node/BPP 十步利用手法

仅在 **已授权** 且目标具备下列画像时启用本手法，勿套用到普通 PHP 发卡站（如独角数卡/Dcat）。

## 目标画像（缺一则降级/换手法）

- 前端或管理端 JS 含共享密钥 / AES-GCM 封装
- 后台可弱口令或拿到 **JWT**
- 存在 SQL 注入（尤指 **二阶注入**）并可跨库
- 库中或文件表出现 **`.node` 原生扩展** / `remote_fs` / `system_files` 类记录
- 存在自定义二进制协议（本链：**BPP**，magic=`0x42505001`）
- 支付或内部通道能投递 `payment:bpp_raw` 类原始帧

## 标准十步（按序，每步留证据）

| 步骤 | 动作 | 关键产出（示例口径） |
|------|------|----------------------|
| ① | JS 密钥提取 | 搜 `shared-secret` / AES-GCM / WebCrypto；导出密钥名与用法 |
| ② | 弱密码登录 | 撞后台；拿到 **JWT** 并验证接口 |
| ③ | SQL 注入 | 优先二阶；枚举库表；跨库列出可读库 |
| ④ | 发现 `.node` | 查 `system_files` / 上传表 / 路径含 `.node` |
| ⑤ | 提取二进制 | 导出 `.node`/内嵌 ELF；确认 arch（如 x86-64）与体积 |
| ⑥ | BPP 协议逆向 | 定 magic、TLV：如 `STRING=0x10` `BLOB=0x11` |
| ⑦ | 发送 BPP 数据 | 走业务路由（如 `payment:bpp_raw`）投合法/半合法帧 |
| ⑧ | 整数溢出 | `BLOB len=0xFFFFFFFF` 等 → 触发 **CRASH** 证明可控 |
| ⑨ | ASLR 泄露 | 从崩溃/回显整理 `libc` / `pie` / `stack` 基址 |
| ⑩ | ROP → 读 flag | 定位后门/读文件路径；ROP 链触发条件调试至稳定 |

用户若给出逐步状态表，**照表执行并补齐缺步**，不要跳过证据固化。

## 每步操作要点

### ① JS 密钥提取
- 搜：`AES-GCM`、`crypto.subtle`、`shared-secret`、`websks`、硬编码 key/iv
- 产出：密钥字符串、算法、哪些请求用该密钥加解密
- 证据：`js_secrets.json` + 关键 snippet

### ② 弱密码 → JWT
- 管理端字典 + 默认口令；登录响应抓 `Authorization` / cookie JWT
- 解码 payload（不验签也先看 `role`/`exp`）；试越权 API
- 证据：`auth_jwt.txt`（脱敏存储按项目规范）

### ③ SQL 注入（二阶 + 跨库）
- 一阶：报错/布尔/时间；二阶：写入后在另一接口触发
- 跨库：`information_schema` → 库名列表 → 敏感表
- 目标表关键词：`system_files`、`remote_fs`、`files`、`plugins`、`native`
- 证据：`sqli_dbs.json`、关键查询与回显

### ④ 发现 `.node`
- SQL/文件枚举找 `*.node`；或管理上传/插件目录
- 记录：路径、大小、所属库表主键
- 证据：文件路径列表

### ⑤ 提取二进制
- 经注入读文件、文件下载接口或备份包取出
- `file` 确认 ELF；记下 PIE、NX、Canary、架构
- 证据：原始 `.node`/`elf` + `file`/`readelf` 摘要（**不**默认可执行未知样本）

### ⑥ BPP 协议逆向
- 从 `.node`/配套 JS 找 magic `0x42505001`（ASCII 相关 `BPP\x01`）
- 解析帧：长度字段端序、类型枚举（`0x10` STRING、`0x11` BLOB）
- 产出：可手写 pack/unpack 的脚本
- 证据：`bpp_spec.md` + `bpp_codec.py`

### ⑦ 发送 BPP
- 定位路由：`payment:bpp_raw` / 同类 raw 通道（常需 JWT + ① 的加密封装）
- 先发合法小帧确认「受理」；再发异常帧
- 证据：请求/响应完整包

### ⑧ 整数溢出
- 对 BLOB 长度写 `0xFFFFFFFF`（或 `len > alloc`）
- 成功标志：**稳定 CRASH**（进程重启、502、断开）
- 证据：崩溃日志/响应时序

### ⑨ ASLR 泄露
- 利用崩溃回显、部分覆写、infoleak 原语收集：
 - `libc` base
 - `pie` base
 - `stack` 地址
- 证据：`aslr_leak.json`

### ⑩ ROP → `/flag`（或业务等价敏感文件）
- 用泄露地址编 ROP；或触发已定位后门路径
- 「后门路径已定位、触发条件待调试」时：只改触发条件，不重做 ①–⑨
- 证据：读出内容哈希/截断样例 + 可复现脚本

## 与发卡站十二步的关系

| 本手法 | 发卡站十二步 |
|--------|----------------|
| 面向 Node + native + 自定义协议 | 面向 WP/独角/易支付 |
| 终点常为 RCE/读 flag | 终点常为后台/假回调/出卡 |
| **不要**在 tgzhanghao 类站点空转 BPP/ROP | 密钥/弱口令/SQLi 步骤可复用思路 |

授权站点若 **不是** 本画像：报告「栈不匹配」，改走对应站型剧本。

## 输出模板

每个授权目标目录写入 `BPP_CHAIN_STATUS.md`：

```markdown
| 步骤 | 状态 | 关键产出 |
| ① JS密钥 | ✅/❌/⏭ | ... |
| ... | ... | ... |
| ⑩ ROP | 🔄 | 阻塞点：... |
```

状态约定：`✅` 完成 · `❌` 失败 · `⏭` 跳过（无前置）· `🔄` 进行中。

## 安全约束

- 必须已有 scope 授权；第三方支付域名仅作支付流附属探测，不横向未授权主机
- 不主动对非授权网段传播 exploit；本地只分析已提取的样本
- 不落地完整 weaponized exploit 到未授权环境；授权恢复场景以读凭证/flag/配置为限

## 真源

- 手法：`传承/商燕飞·盘口.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
