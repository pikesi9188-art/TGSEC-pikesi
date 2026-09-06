---
name: 窗·使桥
description: "Drive frx-director MCP (firefox-reverse) browser from CLI."
version: 1.0.0
created_by: agent
---
# browser-reverse-mcp — frx-director (firefox-reverse) 浏览器逆向驱动

用户环境有 firefox-reverse 逆向浏览器（Marionette 2828）+ frx-director-mcp 桥接服务。**用户期望浏览器逆向/页面抓包优先用它**（曾两次追问"frx-director MCP 调用这个了吗"）。MCP 只挂在 bot4 profile，default 会话没挂载 → 用 stdio JSON-RPC 客户端直连。

## 环境

- MCP server: `./data/frx/frx-director-mcp/dist/index.js`（node 启动，stdio 协议）
- 浏览器: `./data/frx/firefox/firefox`（-marionette -remote-allow-system-access，profile `./data/frx/profile`）
- Xvfb :99 需在跑；Marionette 127.0.0.1:2828；worker provider=deepseek 已配 key
- 启动前置: `Xvfb :99 -screen 0 1280x800x24 &`（若 xdpyinfo 不通）；frx-director-launcher.sh 一键拉起
- 21 个 MCP 工具（frx_status / agent_start / agent_tools / agent_call_tool / frx_env_* / frx_page_automation_scan…），agent_call_tool 直调引擎 38 工具

## 驱动方式（会话未挂载 MCP 时）

```bash
# 客户端脚本（本 skill 的 scripts/）:
python3 scripts/frx_mcp_client.py            # 通用 stdio 客户端 (McpClient)
python3 scripts/mcp_call.py <tool> '<json>'  # 一键调用 agent_call_tool
python3 scripts/mcp_call.py frx_status '{}'
python3 scripts/mcp_call.py agent_tools '{}'
python3 scripts/mcp_call.py agent_call_tool '{"name":"page_navigate","args":{"url":"https://target"}}'
```

流程: `initialize`(protocolVersion 2024-11-05) → `notifications/initialized` → `tools/call {name, arguments}`。每个工具调用约 1-2s 建立连接，多次调用可复用同一 McpClient 实例。

## 核心工具工作流（agent_call_tool → name/args）

| 场景 | 工具 | 要点 |
|---|---|---|
| 自检 | frx_status | 开跑前确认浏览器连上 |
| 打开页面 | page_navigate {url} | CF 保护的站用这个，别用 curl |
| 抓包 | net_capture {action:"start", urlPattern:"gc"} | **必须先在触发请求前 start**（initiatorStack 只在请求发起时抓） |
| 列请求 | net_list {limit} | 拿 id |
| 请求详情 | net_get {requestId, includeBody:true} | 完整请求头/响应/发起栈 |
| 页面 JS | page_eval {expression} | 任意 JS；首选非 JSVMP 站的签名 I/O 观察 |
| 点/填 | page_click {selector|text} / page_type | 见 React 坑 |
| 脚本清单 | scripts_list {} | 拿懒加载 chunk URL |
| 截图 | page_screenshot {fullPage} | 输出保存位置在 MCP 工作目录 |

## Pitfalls（实测）

- **CF 409/空响应**：curl 直连 CF 后的目标概率性 409/空 body（TLS 指纹）。浏览器通道 fetch 稳定；但浏览器页面内 fetch 自定义 c 参数时注意**全 URL 编码** `encodeURIComponent`（base64 的 `+` `/` 裸传会被服务端/CF 改坏 → "json unmarshal error" 或空响应）。
- **React 受控输入**：`el.value=x + dispatchEvent(input)` 不更新 React state（按钮保持 disabled）。用 native setter: `Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value").set.call(el,v)` 再派发 input 事件；或 page_type。
- **page_eval 长响应被截断**：结果有 totalLength/returnedLength 上限。长数据先存 `window.__x=...` 再分段读，或 `t.slice(0,N)` 控制长度。
- **懒加载 chunk**：umi/webpack 页面业务代码在 `.async.js` chunk 里，主 bundle 只有路由。`scripts_list` 拿 URL → curl 下载 chunk → grep `request\("/xxx"` 提取真实 API 路径（如 `/transaction/recharge_order`）。
- **WS 加密与 HTTP 同 key**：该家族 WS(wss://ws.uptest.top) 与 HTTP API 共用同一 AES-ECB key；WS 消息是 protobuf(Package 4B头 + Message) 包装，明文 JSON 直接断连，别裸发。
- **Agent 会话互斥**：agent_call_tool 与 worker agent(agent_start) 同浏览器互斥；有 worker 在跑先 agent_stop。
