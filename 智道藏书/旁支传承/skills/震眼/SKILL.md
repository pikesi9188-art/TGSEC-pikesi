---
name: 震眼
description: 360Quake 网络空间测绘 — Chrome MCP 导航/JS fetch API/数据导出/精度分级
metadata:
  type: skill
---
# quake — 360Quake 资产测绘 Skill

> ⭐ **前置条件：** Edge/Chrome 浏览器已登录 [quake.360.net](https://quake.360.net/)
> ⭐ **核心工具：** Chrome MCP（导航 + chrome_javascript + credentials:'include'）
> ⭐ **铁律：** 绝不用 `chrome_network_request` / 绝不用硬编码 `Authorization` / 绝不轮询分批 `start`
> ⭐ **精度分级：** 只有 `domain:"xxx.com"` 搜索结果可信，body 搜索不可信
---
## 一、精度分级（已验证，不可违背）

| 级别 | 搜索方式 | data[] 返回 | 可信度 |
|:----:|---------|:-----------:|:------:|
| **A** | `domain:"xxx.com"` | ✅ IP 列表 | 🟢 **可信** ~0% 误报 |
| **B** | `"精确短名"` | ⚠️ 部分返回 | 🟡 部分可信 |
| **C** | `"精确公司全名"`（聚合） | ❌ data[] 空 | 🟡 知有资产但拿不到 IP |
| **D** | `body:"关键词"` / 无引号搜索 | ✅ 能返回 | 🔴 **不可信** 70-99% 误报 |

### 1.1 重要例外：中小企业/特有产品名

**实战发现：** 对体量小、品牌名独特的公司，body 搜索反而比 `domain:` 更准：

| 情况 | domain 搜索 | body 搜索 |
|:----|:-----------|:---------|
| 大公司（如百胜） | ✅ 几千条 | ❌ 大量误报无关IP |
| 中小企业/特有产品 | ❌ 0 条（Quake 没收录 DNS） | ✅ 能命中真实服务 |

**判断标准：**
```
搜索命中的 IP 数 ≤ 10 且 页面标题全部指向目标 → body 结果可信 ✅
搜索命中的 IP 数 > 50 且 标题混杂无关内容     → body 结果误报 ❌
```
---
## 二、API 硬限制（2026-07-19 实测验证）

| 限制 | 值 | 说明 |
|:----|:---|:-----|
| 单次最大返回 | **100 条** | `size>100` 返回空。网页查询报错 `"网页查询最大允许查询100条数据"` |
| 分页支持 | ⚠️ **有限分页** | `start=0/30/60` 有效；`start+size>100` 返回空（例如 start=90,size=30 报错） |
| 推荐 size | `100`（API 调用） | API 实测 size=100 拿满 100 条可用 |
| 数据总上限 | **严格 100 条/每查询** | API 后端硬限制，无论 total 显示多大，最多只能拿到 100 条 |
| `quake_host` 索引 | **对中文无效** | `quake_host` 对中文/中文公司名搜索返回空 |
| 聚合接口 | ✅ 可用 | 返回 uniqueIP 计数但无 data[] |
| API 只返回 HTTP/HTTPS | **非 HTTP 端口漏掉** | Redis/MongoDB/SSH/自定义端口只有导航页能看到 |

> ⚠️ **关键：** 当 `total > 100` 时，单次搜主域名只能拿到前 100 条。
> **解决方案：** 见下方"突破 100 条上限的细分拼凑策略"，通过子域名/IP段分散查询拼凑全量。
---
## 三、三种操作方式

### ⭐ 方式 A：导航到搜索结果页（推荐，数据最全）

```python
# 优点：能看到所有端口服务（HTTP + 非 HTTP 如 Redis/MongoDB/SSH）
#       不需要处理 credentials/CORS，稳定可靠
# 缺点：不是结构化 JSON，需要解析页面文本
chrome_navigate(url="https://quake.360.net/quake/#/searchResult?searchVal=<URL编码查询>&selectIndex=quake_service&latest=true&size=30")
```

**URL 参数：**

| 参数 | 说明 | 推荐值 |
|:----|:-----|:------|
| `searchVal` | 搜索词（URL 编码） | 如 `domain%3A%22xxx.com%22` |
| `selectIndex` | 索引类型 | `quake_service` |
| `latest` | 仅最新数据 | `true` |
| `size` | 每页条数（API 最大 100，导航页推荐 30） | `30`（导航）/ `100`（API） |

**从页面文本解析资产的规则：**
```
头部统计行：
  "共X条 , 含Y个独立IP , 用时Z秒" → total=X, uniqueIP=Y

每条记录格式（换行可能拆散字段，需逐行扫描）：
  [hostname] [精度标签] [IP] [更新时间] [端口] [协议] [组织]
  [自治域编号] [运营商] [IP归属]
  [网站服务器/编程语言/路径/主机名]
  [HTTP响应头片段]
  [页面标题 / 技术栈特征]
```

### ⭐ 方式 B：页面内 JS fetch API（备用，获取结构化 JSON）

**🔴 铁律：** 必须在 Quake 页面内通过 `chrome_javascript` 执行，传 `credentials: 'include'` 继承 Cookie。
**绝不能用 `chrome_network_request`，绝不能用硬编码 `Authorization`。**

```javascript
// ⭐ 在 Quake 页面内执行（chrome_javascript + credentials: 'include'）
// 返回结构化 JSON，但只包含 HTTP/HTTPS 服务（非 HTTP 端口丢失）
async function quakeSearch(query, size = 30) {
  const res = await fetch('https://quake.360.net/api/search/query_string/quake_service', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    credentials: 'include',          // 🔴 必须！继承浏览器 Cookie
    body: JSON.stringify({
      query: query,
      latest: "true",
      start: 0,
      size: size                      // 推荐 100，最大 100。不支持分页到 start+size>100
    })
  });
  const data = await res.json();
  const records = Array.isArray(data.data) ? data.data : [];
  return {
    total: data?.meta?.pagination?.total || 0,
    uniqueIP: new Set(records.map(r => r.ip)).size,
    count: records.length,
    records: records.slice(0, size).map(r => ({
      ip: r.ip,
      port: r.port,
      hostname: r.hostname || '',
      title: (r.service?.http?.title || '').substring(0, 80),
      service: r.service?.name || '',
      protocol: r.service?.http?.scheme || ''
    }))
  };
}
// 调用示例：
// return await quakeSearch('domain:"xxx.com"');
// return await quakeSearch('domain:"kfc.com.cn"', 100);  // 实测 size=100 可用
```

### ⭐ 方式 C：聚合查询（确认资产存在，但拿不到具体 IP）

适用于 `"精确公司全名"` 搜索——确认目标在 Quake 中有资产，但 API 不返回具体 IP。

```javascript
// 在 Quake 页面内执行（credentials: 'include'）
async function quakeAggCount(queries) {
  async function count(q) {
    const res = await fetch('https://quake.360.net/api/aggregations/quake_service', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      credentials: 'include',
      body: JSON.stringify({
        query: q,
        latest: true,
        start: 0, size: 1,
        aggregation_list: ["unique_ip", "port", "service_and_version"]
      })
    });
    const d = await res.json();
    return {
      query: q,
      uniqueIP: d?.data?.unique_ip?.value || 0,
      ports: (d?.data?.port || []).map(p => p.key + '(' + p.doc_count + ')').join(', '),
      services: (d?.data?.service_and_version || []).map(s => s.key + '(' + s.doc_count + ')').join(', ')
    };
  }
  var results = [];
  for (var i = 0; i < queries.length; i++) {
    results.push(await count(queries[i]));
  }
  return results;
}
// 调用示例：
// return await quakeAggCount(['"龙羊峡发电分公司"', '"黄河鑫业"']);
```
---
## 四、完整工作流

```
Phase 0: 前置准备（🔴 必须先做）
  ├─ get_windows_and_tabs → 找已有 Quake 标签页
  ├─ 无 → chrome_navigate("https://quake.360.net")
  ├─ 确认已登录（检查页面是否含"检索"或搜索框）
  └─ 未登录 → 提示用户手动登录

Phase 1: 导航搜 IP/域名（⭐ 主方案）
  ├─ 构造 URL：searchVal=domain%3A%22xxx.com%22&size=100
  ├─ chrome_navigate → chrome_get_web_content 读文本
  ├─ 从文本提取：IP/端口/服务/标题/地理位置 + 完整子域名列表
  ├─ 注意区分 HTTP 和非 HTTP 服务（Redis/MongoDB/SSH/自定义端口）
  └─ 如果 total > 100（API 硬限制）→ 走策略 A：子域名细分拼凑（见六）

Phase 2: JS fetch API 补充（备选）
  ├─ 导航方案拿不到结构化数据时使用
  ├─ 只在 Quake 页面内 chrome_javascript + credentials:'include'
  └─ 注意：只返回 HTTP/HTTPS 服务

Phase 3: 精确短名聚合（知有资产但拿不到 IP）
  ├─ 对子公司/系统名逐个查聚合
  ├─ 记录 uniqueIP 数、端口分布、服务分布
  └─ 标记"聚合确认有资产但无法拉取 IP"

Phase 4: 证书扩散（cert 反查，发现内部系统）
  ├─ cert:"xxx.com" 搜索关联证书资产
  ├─ cert 搜索通常能发现大量内部系统（域控/VPN/日志/SSO）
  └─ 实战案例：百胜中国 cert:"kfc.com.cn" → 209 uniqueIP

Phase 5: 数据输出
  ├─ 可信资产 → 表格输出（IP/端口/服务/标题/来源）
  ├─ 聚合值 → 标注"待手工提取"
  └─ ⚠️ 绝不用 body 搜索/无引号搜索的 IP 混入可信集
```
---
## 五、常用搜索语法

| 目标 | 语法 | 说明 |
|:----|:-----|:-----|
| 主域名资产 | `domain:"xxx.com"` | A 级可信 |
| 精确短名 | `"系统名/品牌名"` | B 级部分可信 |
| 精确公司全名 | `"公司全名"` | C 级聚合有值但 data[] 空 |
| 证书反查 | `cert:"xxx.com"` | 发现内部系统（SSO/域控/日志）⭐ |
| IP 搜索 | `ip:"1.2.3.4"` | 单 IP 查询 |
| 标题搜索 | `title:"后台管理"` | 标题包含关键词 |
| Body 搜索 | `body:"关键词"` | ❌ 70-99% 误报 |
| 无引号搜索 | `关键词` | ❌ 不可信 |
| 端口搜索 | 在 URL 参数中 | 非搜索语法 |
---
## 六、突破 100 条上限的细分拼凑策略 ⭐

> **核心问题：** API 硬限制单次最多返回 100 条记录。当 total=811 时，一次搜主域名只能拿 100 条。
> **解题思路：** 拆成多个不重叠的细分查询，每个 <100 条，分别拉满后合并去重。

### 6.1 ⭐ 策略 A：按子域名逐个查（最推荐）

**原理：** 先拿第 1 次搜索结果中的 hostname/IP 推断子域名列表，然后对每个子域名单独查。

**总记录 ≈ 每个子域名记录数之和，远超 100 条。**

**实战验证数据（百胜中国/kfc.com.cn）：**

| 子域名 | API total | 能否单次拿满 | 说明 |
|:-------|:--------:|:-----------:|:-----|
| `domain:"kfc.com.cn"`（全站） | 811 | ❌ 只能拿 100 | 需要细分 |
| `domain:"order.kfc.com.cn"` | 119 | ⚠️ 119 > 100 | 仍需进一步细分 |
| `domain:"www.kfc.com.cn"` | 2 | ✅ 一步拿满 | |
| `domain:"login.kfc.com.cn"` | ✅ | ✅ 一步拿满 | |
| `domain:"resmkt.kfc.com.cn"` | ✅ | ✅ 一步拿满 | |
| `domain:"tmall.kfc.com.cn"` | ✅ | ✅ 一步拿满 | |
| `domain:"pin.kfc.com.cn"` | ✅ | ✅ 一步拿满 | |
| `domain:"mobilepostx.kfc.com.cn"` | ✅ | ✅ 一步拿满 | |
| `domain:"flashsalenew.kfc.com.cn"` | ✅ | ✅ 一步拿满 | |
| `domain:"drivethrough.kfc.com.cn"` | ✅ | ✅ 一步拿满 | |
| `domain:"appcoffee.kfc.com.cn"` | ✅ | ✅ 一步拿满 | |
| `domain:"kmusic.kfc.com.cn"` | ✅ | ✅ 一步拿满 | |
| `domain:"tracking.kfc.com.cn"` | ✅ | ✅ 一步拿满 | |
| `domain:"uatcpos.kfc.com.cn"` | ✅ | ✅ 一步拿满 | |
| `domain:"mobileposjs.kfc.com.cn"` | ✅ | ✅ 一步拿满 | |
| `domain:"patrol-yumc3-rnorder.kfc.com.cn"` | ✅ | ✅ 一步拿满 | |
| `domain:"patrol-yumc2-rnorder.kfc.com.cn"` | ✅ | ✅ 一步拿满 | |
| `domain:"patrol-yumc1-rnorder.kfc.com.cn"` | ✅ | ✅ 一步拿满 | |

**执行模板（在 Quake 页面内执行）：**

```javascript
// Step 1: 先查主域名拿前100条，从中提取已知子域名
async function getSubdomains(mainDomain) {
  const res = await fetch('https://quake.360.net/api/search/query_string/quake_service', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    credentials: 'include',
    body: JSON.stringify({ query: `domain:"${mainDomain}"`, latest: true, start: 0, size: 100 })
  });
  const d = await res.json();
  const records = Array.isArray(d.data) ? d.data : [];
  // 提取 hostname（虽然大部分空）和 IP，结合导航页提取域名列表
  const hosts = [...new Set(records.filter(r => r.hostname).map(r => r.hostname))];
  return { total: d?.meta?.pagination?.total || 0, hosts, ipCount: [...new Set(records.map(r => r.ip))].length };
}
// 调用: return await getSubdomains('kfc.com.cn');

// Step 2: 如果有已知子域名列表，逐个搜并合并
async function batchSubSearch(domain, subdomains) {
  let allRecords = [];
  for (const sub of subdomains) {
    const fqdn = sub.includes('.') ? sub : `${sub}.${domain}`;
    const res = await fetch('https://quake.360.net/api/search/query_string/quake_service', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      credentials: 'include',
      body: JSON.stringify({ query: `domain:"${fqdn}"`, latest: true, start: 0, size: 100 })
    });
    const d = await res.json();
    const records = Array.isArray(d.data) ? d.data : [];
    allRecords.push({ sub: fqdn, total: d?.meta?.pagination?.total || 0, count: records.length });
  }
  return allRecords;
}
// 调用示例：用从 Step1/导航页 提取到的子域名列表
// return await batchSubSearch('kfc.com.cn', ['order', 'login', 'www', 'resmkt', 'pin']);
```

> **注意：** 先导航到搜索页用 `chrome_get_web_content` 提取完整的子域名列表（导航页显示 hostname），然后用这个列表逐个 JS fetch 拉数据。

### 6.2 ⭐ 策略 C：按 IP 段/CIDR 细分（cert反查的补充）

**原理：** 从 cert 反查获得的 IP 列表，按 C 段分组，然后逐个段查询。

**cert 搜索得到大量 IP → 分组为 /24 段 → 每个段内 IP 少，容易拿满。**

**实战验证（百胜中国 14.103.x.x 段）：**

| IP 段 | 归属 | 预期记录数 | 能否拿满 |
|:------|:-----|:--------:|:--------:|
| `14.103.0.0/24` | 火山引擎（订单集群） | ⚠️ 可能超 100 | 需进一步切分 |
| `14.103.2.0/24` | 火山引擎（小肥羊/内网） | ✅ 少量 | ✅ |
| `14.103.3.0/24` | 火山引擎（内网/SSO） | ✅ 少量 | ✅ |
| `139.196.0.0/16` | 阿里云（KFC服务） | ⚠️ 大段 | 切小段 |
| `47.103.0.0/16` | 阿里云（KFC服务） | ⚠️ 大段 | 切小段 |

**执行模板：**

```javascript
// 按 C 段查
async function ipSegmentSearch(cidr) {
  const res = await fetch('https://quake.360.net/api/search/query_string/quake_service', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    credentials: 'include',
    body: JSON.stringify({ query: `ip:"${cidr}"`, latest: true, start: 0, size: 1 })
  });
  const d = await res.json();
  return { cidr, total: d?.meta?.pagination?.total || 0 };
}
// 调用：先测各段总数
// const segs = ['14.103.0.0/24','14.103.2.0/24','14.103.3.0/24','139.196.0.0/16'];
// for (const s of segs) { const r = await ipSegmentSearch(s); ... }
```

> **注意：** `ip:"1.2.3.0/24"` 语法已验证可用。先聚合查询确认每个段的 total，如果段太大（>100）再继续切细（如 `/25`、`/26` 或单 IP）。

### 6.3 合并去重

所有细分查询的结果用 `quake_export.py --merge` 一键合并：

```bash
python quake_export.py \
  --merge order_raw.json login_raw.json www_raw.json cert_raw.json \
  --target "目标名" \
  --output "quake_report.xlsx"
```

**合并去重规则（由 quake_export.py 自动处理）：**
- `domains`：按 domain 去重
- `ips`：按 IP 去重
- `urls`：按 `ip:port` 去重
- `systems`：按 system 名去重
---
## 七、数据导出管线（2026-07-19 实战验证 ✅）

> ⚠️ **注意：** 以下导出的数据仅为单次搜索返回的 ≤100 条记录。
> 如需全量，先走策略 A/C（见六）收集多个细分查询的 JSON 文件，再用 `--merge` 合并导出。

### 7.1 完整流程

```
JS fetch API（方式 B）          导航搜索页（方式 A）
  ├─ 结构化 JSON                  ├─ 含 hostname/证书详情
  ├─ 不含 hostname                ├─ 可见非 HTTP 端口
  └─ 方便程序处理                  └─ 需人工解析文本
        ↓                               ↓
  保存为 JSON 文件（quake_export.py 自动处理）
        ↓
  python quake_export.py --input quake_raw.json --target "目标名" --output report.xlsx
        ↓
  桌面 → report.xlsx（6 个 sheet）
```

### 7.2 一键导出工具：quake_export.py

本 skill 目录下的 `quake_export.py` 提供完整的 Quake 数据 → xlsx 管线：

```bash
# 【推荐】合并多个搜索词（domain + cert）再导出
cd skills/quake
python quake_export.py \
  --merge domain_raw.json cert_raw.json \
  --target "目标名" \
  --output "quake_report.xlsx"

# 单文件直接导
python quake_export.py \
  --input quake_raw.json \
  --target "目标名" \
  --output report.xlsx
```

**单次搜索导出（≤100条）：**
```
domain:"kfc.com.cn" + cert:"kfc.com.cn" (size=100)
  → 导出: 30 IPs, 32 URLs, 18 系统
  → xlsx 文件: 13KB ✅
```

**全量导出（用策略 A 子域名细分）：**
```
逐个查 17 个子域名 + cert 反查 → 合并去重
  → 预期可覆盖 811 条记录中的绝大部分
  → 见 六、突破 100 条上限的细分拼凑策略
```

### 7.3 JS fetch → JSON 导出模板

在 Quake 页面执行 `chrome_javascript`，保存返回的 JSON：

```javascript
// 1. domain 搜索（size=100 已验证可用）
let res = await fetch('https://quake.360.net/api/search/query_string/quake_service', {
  method: 'POST', headers: {'Content-Type': 'application/json'},
  credentials: 'include',
  body: JSON.stringify({ query: 'domain:"目标.com"', latest: "true", start: 0, size: 100 })
});
let d = await res.json();
let records = Array.isArray(d.data) ? d.data : [];
let exportData = records.map(r => ({
  ip: r.ip||'', port: r.port||0, hostname: r.hostname||'',
  title: (r.service?.http?.title||'').trim().substring(0,100),
  service: r.service?.name||'',
  location: [r.location?.country_cn,r.location?.province_cn,r.location?.city_cn].filter(Boolean).join(' '),
  isp: r.autonomous_system?.org||'',
  status: r.service?.http?.response_code||0
}));
// return JSON.stringify(exportData);  // 复制保存为 JSON 文件

// 2. cert 反查（可合并导出，发现更多资产）
// 把 query 改成 cert:"目标.com" 重复上述代码
```

**⚠️ 注意：** JS fetch 返回的 `hostname` 字段通常是空的（Quake API 不返回域名）。
如需完整 hostname 信息，请用方式 A（导航到搜索页读渲染文本）。
影响：xlsx 的 `domains` sheet 会为空，但 `ips`/`urls`/`systems` sheet 正常。

### 7.4 两种数据源对比

| 维度 | 方式 A：导航页 | 方式 B：JS fetch API |
|:----|:--------------|:-------------------|
| hostname | ✅ 完整 | ❌ 空 |
| 非HTTP端口(Redis/MongoDB/SSH) | ✅ 可见 | ❌ 不可见 |
| 结构化程度 | ❌ 需解析文本 | ✅ 结构化 JSON |
| 导出处理 | 需 AI 解析文本 → 手动整理 | 直接 pipe 到 export 脚本 |
| 适用场景 | 需要完整 hostname + 非 HTTP 端口发现 | 批量导出到 xlsx 报告 |

### 7.5 body 搜索质检工具

```bash
# 判断 body 搜索结果是否可信
python recon/infogather_quake.py check quake_records.json "目标名"
# → 输出 confidence: high/medium/low + IP 数 + 标题匹配率
```

### 7.6 JSON 字段映射表（xlsx 6 个 sheet）

| sheet | JSON key | 字段 |
|:------|:---------|:-----|
| 域名资产 | `domains` | domain, unit, ip, source, note |
| IP 资产 | `ips` | ip, domain, location, isp, type, source |
| URL 资产 | `urls` | url, system, accessible, ip, source, note |
| 系统资产 | `systems` | system, tech, unit, ports, source |
| 社工线索 | `social` | type, content, belong, source |
| 待办列表 | `todos` | priority, action |
---
## 八、实战案例速查

### KFC/百胜中国（2026-07-18）

| 搜索方式 | 结果 | 说明 |
|:---------|:-----|:-----|
| `domain:"kfc.com.cn"` | 811 条 / 17 子域名 / **123 uniqueIP** | ✅ A 级可信 |
| `domain:"yumchina.com"` | 0 条 | ❌ Quake 没收录该域名 DNS |
| `cert:"kfc.com.cn"` | 209 uniqueIP | ✅ 发现大量内部系统 |
| `cert:"百胜咨询（上海）有限公司"` | 2,706 条 | ✅ 证书组织反查（数据最全） |
| `domain:"huangjihuang.com"` | 33 条 | ✅ 发现后台管理系统 |
| `"黄记煌后台管理系统"` | ⚠️ 少量 | 在导航页中看到具体记录 |

### 热付通/辽宁北软（2026-07-17）

| 搜索方式 | 结果 | 说明 |
|:---------|:-----|:-----|
| `domain:"heatingpay.cn"` | 0 条 | ❌ 域名太小没收录 |
| `body:"heatingpay"` | 168 条 / **124.95.129.105** | ✅ 中小企业特例：body 有效 |
---
## 九、⛔ 坑点与铁律清单

| # | 坑点 | 说明 |
|:-:|:-----|:-----|
| 1 | **size 上限 100** | `size>100` 返回空。推荐 API 调用用 50-100，导航页推荐 30 |
| 2 | **分页有限支持** | `start=0/30/60` 有效，但 `start≥90` 返回空。数据总窗口约 90 条 |
| 3 | **JS fetch API 只返回 HTTP/HTTPS** | 看不到 Redis/MongoDB/SSH 等非 HTTP 服务 |
| 4 | **导航方案能看到所有端口** | ✅ 读页面文本能看到所有端口（包含非 HTTP） |
| 5 | **精确全名 data[] 空** | 聚合有值但 data API 返回 0，不是 bug 是索引设计 |
| 6 | **body 搜索不可信** | 大公司 body 搜索误报率 70-99% |
| 7 | **中小企业 body 搜索例外** | 品牌名独特的公司 body 可能比 domain 更准 |
| 8 | **`quake_host` 索引对中文无效** | 不要浪费时间 |
| 9 | ❌ **不用 `chrome_network_request`** | 不带 Cookie，返回空 |
| 10 | ❌ **不用硬编码 `Authorization`** | 每个会话 token 不同，写死必失败 |
| 11 | ✅ **导航最稳** | 什么都不依赖，页面渲染什么就能读什么 |
| 12 | ✅ **先找已有标签页** | `get_windows_and_tabs` 查是否有 Quake 页面，避免重复打开 |
| 13 | ✅ **`credentials: 'include'`** | JS fetch 必须带此选项继承浏览器 Cookie |
| 14 | ✅ **body 搜索质检后再用** | 用 `infogather_quake.py check` 判断 confidence 再决定是否列入资产 |
| 15 | 🚨 **100 条硬上限** | 单次查询最多返回 100 条。total>100 时用"策略 A 子域名细分"或"策略 C IP段细分"拼凑全量 |
| 16 | ✅ **策略 A：子域名分段** | 导航页提取 hostname 列表 → 逐个 `domain:"sub.xxx.com"` size=100 查 → merge 去重，可覆盖全量 811 条 |
| 17 | ✅ **策略 C：IP段分段** | cert 搜索拿到 IP 列表 → 按 C段分组 → 逐个 `ip:"x.x.x.0/24"` 查 → merge 去重 |
---
## 十、相关技能与工具

| 工具/技能 | 说明 |
|:----------|:-----|
| `fofa-api` | FOFA 高级会员 API 调用（200 次/日配额） |
| `hunter-qianxin` | 奇安信鹰图平台（Hunter）资产测绘 |
| `infogather` | 被动信息收集综合技能（含 Quake 子流程） |
| `infogather_quake.py` | Quake 原始记录 → xlsx 转换工具 |
| `infogather_report.py` | 多源数据合并 xlsx 报告生成器 |
| `quake-api-precision-tiers` | 精度分级记忆文件 |

### 三款测绘工具选择对照

| 维度 | Quake | FOFA | Hunter |
|:-----|:------|:-----|:-------|
| 方式 | Chrome MCP 导航/JS fetch | Python API | Chrome MCP 导航 |
| 认证 | 浏览器 Cookie（自动） | API Key（日卡） | 浏览器登录态 |
| 限制 | 无次数限制 | 200 次/日 | 500 积分/天 |
| 数据全量 | 最大 60 条/次 | 最大 10000 条/次 | 页面查看不限 |
| 特色 | cert 反查数据全 | 可全量导出 | ICP 备案信息 |
| 非 HTTP 端口 | ✅ 导航可见 | ❌ | ❌ |
| 推荐顺序 | ⭐ 先跑 | 补充 | 交叉验证 |
