---
name: 爬丝
description: >-
 Scrapling 高效爬虫框架集成（授权范围内）：反爬绕过（Cloudflare Turnstile）、
 JS渲染、并发Spider、MCP直接抓页、全站路由发现、XHR捕获、会话管理。
 
 官方完整 API 参考：tools/scrapling/Scrapling-Official-Skill/Scrapling-Skill/SKILL.md
---

# Scrapling — 大爱仙尊集成

**前提**：目标必须在 `授权范围` 或 `授权范围/`。 
`scrapling_fetch.py` / `scrapling_spider.py` 会自动门控，未授权直接拒绝。

有头本机 Chrome / CDP 9222 → Skill **`chrome-automation`**（接到本卡，不另装 `~/.claude`）。
会员 Cookie → `session_pipeline.py`。滑块 → `captcha_auto.py`。桌面 IDA → `browser-automation`。

> 官方完整 API 文档（含所有参数）见： 
> `tools/scrapling/Scrapling-Official-Skill/Scrapling-Skill/SKILL.md` 
> `tools/scrapling/Scrapling-Official-Skill/Scrapling-Skill/references/`

## 安装（一次性）

```bash
pip install "scrapling[all]"
scrapling install # 下载浏览器依赖（Playwright Chromium）
# Docker 替代（无需本地 Python）：
docker pull pyd4vinci/scrapling
```

## 抓取工具速查

| 场景 | 工具/命令 |
|------|-----------|
| 快速抓静态页 | `scrapling_fetch.py <url> --mode http` |
| JS 渲染页面 | `scrapling_fetch.py <url> --mode browser` |
| Cloudflare 绕过 | `scrapling_fetch.py <url> --mode stealthy --solve-cf` |
| 提取特定元素 | `scrapling_fetch.py <url> --css '.selector'` |
| 全站路由爬取 | `scrapling_spider.py <domain> --depth 2` |
| CLI 直接抓 | `scrapling extract get <url> content.md` |
| CLI 隐身抓 | `scrapling extract stealthy-fetch <url> out.html --solve-cloudflare` |
| MCP 抓页 | 直接在 Cursor 对话调用（`ScraplingServer`） |

## 三步工作流

### 1. 确认授权
```bash
# 目标在 scope.company.json 就直接跑，不在先 scope_expand
python3 tools/scrapling/bin/scrapling_fetch.py https://target.com
```

### 2. 按防护等级选择 Fetcher

```
无防护/低防护 → --mode http（最快）
JS渲染/SPA → --mode browser
Cloudflare → --mode stealthy --solve-cf
```

### 3. 输出落盘，更新 STATUS

```bash
python3 tools/scrapling/bin/scrapling_fetch.py https://target.com/admin \
 --mode stealthy --solve-cf \
 --css '#content' \
 --out 案卷/<case>/scrapling/admin.md
```

## MCP 工具（Cursor 对话直接调用）

`ScraplingServer` 提供以下工具，注册在 `.cursor/mcp.json`：

| 工具 | 用途 |
|------|------|
| `get` | 快速 HTTP，TLS 指纹仿冒 |
| `bulk_get` | 并发 HTTP（多 URL） |
| `fetch` | Playwright Chromium，JS 渲染 |
| `bulk_fetch` | 并发浏览器 |
| `stealthy_fetch` | 反爬（`solve_cloudflare=true`） |
| `bulk_stealthy_fetch` | 并发隐身 |
| `open_session` | 创建持久 session（避免反复开浏览器） |
| `close_session` | 关闭 session |
| `screenshot` | 页面截图（返回图片 + URL） |

### MCP 使用示例

```
# 快速抓一个页面（无 JS）
→ 工具: get url="https://target.com/login" css_selector="#content"

# CF 绕过
→ 工具: stealthy_fetch url="https://cf-protected.com" solve_cloudflare=true

# 持久 session 多页抓取（会员区）
→ 工具: open_session session_type="stealthy" session_id="member_session"
→ 工具: stealthy_fetch url="https://target.com/member" session_id="member_session"
→ 工具: stealthy_fetch url="https://target.com/member/orders" session_id="member_session"
→ 工具: close_session session_id="member_session"

# 页面截图（存证）
→ 工具: open_session session_type="dynamic" session_id="ss"
→ 工具: screenshot url="https://target.com/dashboard" session_id="ss" full_page=true
```

**重要**：MCP `css_selector` 先裁剪再传给 AI，大幅减少 token 用量。优先设置。

## Python 代码片段（快速参考）

```python
from scrapling.fetchers import Fetcher, StealthyFetcher, DynamicFetcher

# HTTP（快速）
page = Fetcher.get('https://target.com', stealthy_headers=True)
links = page.css('a::attr(href)').getall()
text = page.get_all_text(separator='\n')

# CF绕过
page = StealthyFetcher.fetch('https://target.com', headless=True, solve_cloudflare=True)

# JS渲染 + XHR捕获（抓隐藏 API）
page = DynamicFetcher.fetch('https://target.com', capture_xhr='api/', network_idle=True)
xhr_data = page.captured_xhr # 捕获到的 XHR 响应列表

# 会话持久化（登录态爬取）
from scrapling.fetchers import FetcherSession
with FetcherSession(impersonate='chrome') as sess:
 login = sess.post('https://target.com/login', data={'user': 'x', 'pass': 'y'})
 dashboard = sess.get('https://target.com/dashboard')
 data = dashboard.css('.order-list').getall()

# Spider（全站爬取）
from scrapling.spiders import Spider, Response
class TargetSpider(Spider):
 name = "target"
 start_urls = ["https://target.com/"]
 concurrent_requests = 8
 async def parse(self, response: Response):
 for item in response.css('.product'):
 yield {"title": item.css('h2::text').get(), "url": response.url}
 for link in response.css('a[href]'):
 yield response.follow(link.attrib['href'])
result = TargetSpider().start()
result.items.to_json("products.json")
```

## 与现有工具衔接

| 发现 | 下一步 |
|------|--------|
| 登录页 / 会员区 | → `session_import.py` 导入 Cookie + Scrapling 持久 session 深爬 |
| 支付/回调路径 | → `payment-callback-forgery` Skill |
| JS 文件中的 AK/密钥 | → `deepaudit-code-audit` Skill（白盒） |
| Cloudflare 绕过后暴露 API | → 直接 `scrapling_fetch` + `actuator_probe` |
| 全站路由 → 发现 /actuator | → `spring-actuator-cloud-takeover` Skill |
| 需要页面截图存证 | → MCP `screenshot` 工具 |

## CLI 速查

```bash
# 抓取内容到文件（不写代码）
scrapling extract get 'https://target.com' content.md
scrapling extract get 'https://target.com' content.txt --css-selector '#main'
scrapling extract stealthy-fetch 'https://cf.target.com' out.html --solve-cloudflare

# 交互式 shell（调试用）
scrapling shell
```

## 禁止

- 对 scope 外目标运行（`scrapling_fetch.py` 已门控，禁止用 `--force` 绕过）
- 把抓到的第三方用户数据/个人信息写进可公开同步的文档
- 高频爬取导致目标业务中断（先用 `--depth 1` 测，再加深度）

## 真源

- 工具：`tools/scrapling/`
- 官方 Skill：`tools/scrapling/Scrapling-Official-Skill/Scrapling-Skill/`
- MCP 参考：`tools/scrapling/Scrapling-Official-Skill/Scrapling-Skill/references/mcp-server.md`
- 上游：https://github.com/D4Vinci/Scrapling
- Docker：`docker pull pyd4vinci/scrapling`
- 报告目录：`案卷/<site>/scrapling/`
- 手法：`传承/凤九歌·天地歌.md`
