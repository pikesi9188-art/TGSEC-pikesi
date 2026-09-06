---
name: 使桥
description: Use when needing chrome-devtools or jshook MCP tools.
---
# MCP 工具箱按需调用规则（4 机器人通用）

本机器 4 个 profile（default/bot2/bot3/bot4）**已统一部署** 2 个 MCP 服务器，
工具名前缀分别为 `mcp_chrome_devtools_*`、`mcp_jshook_*`。
**遇到对应场景必须直接调用对应 MCP 工具，不要说自己没有浏览器/没有 Hook 工具。**

## 1. chrome-devtools（ChromeDevTools/mcp）— 浏览器自动化与调试

- 启动: `/usr/local/bin/node <chrome-devtools-mcp 不可用，改用手动方案> --executablePath /usr/bin/chromium --chrome-arg=--no-sandbox --headless`
- 运行时: 独立拉起 headless Chromium（复用系统 /usr/bin/chromium），通过 CDP 全权控制
- **触发场景（按需调用）**:
  - 需要真实浏览器打开页面、点击、填表、截图、下载文件
  - 页面 JS 执行、console 调试、DOM 检查
  - 网络请求/响应监听、性能分析（Performance/Lighthouse）
  - 前端自动化测试、爬虫、动态渲染页面取数
  - **替代 Burp 抓包**：需要看请求/响应时用网络监听工具，或终端 curl
- 工具形态示例: `mcp_chrome_devtools_*`（导航、点击、截图、evaluate 等 29 个工具）
- 注意: 工具调用前先在本地看是否有 `browser_navigate` 等内置浏览器工具；**当内置浏览器不够（无头/无法注入 CDP 调试/需要真实浏览器指纹）时切 chrome-devtools**。

## 2. jshook（jshookmcp）— JS 逆向 / Hook / 代码分析

- 启动: `node ./data/mcp/jshookmcp/dist/index.mjs`（env `MCP_TOOL_PROFILE=search`，轻量档 ~3K tokens）
- 档位: `search`(默认) / `workflow` / `full`，需要完整 600+ 工具时改 env 并重启
- **触发场景（按需调用）**:
  - 前端 JS 逆向：签名定位、加密参数分析、混淆/反混淆
  - JS Hook（函数 hook、XHR/fetch 拦截）、CDP 调试挂到已有页面
  - 浏览器网络拦截、Source Map 重建、AST 变换
  - 与 `js-reverse` 技能联动：js-reverse 定位签名 → jshook 挂 Hook 验证
- 工具形态示例: `mcp_jshook_*`（bundle 搜索、hook 管理、CDP 调试等）

## 路由优先级（本机 Web/逆向能力选择）

```
1. 纯终端/curl/nuclei 能做的 → 直接终端做，不浪费 MCP
2. 需要浏览器交互 → chrome-devtools（真实 Chromium）；内置 browser_* 能用就先用内置
3. 需要 JS 逆向/Hook/混淆分析 → jshook
4. 需要抓包/看请求响应 → chrome-devtools 网络监听或 curl，不依赖 Burp
```

## 部署验证（管理员用）

```bash
<跨库工具不可用，跳过> -p <profile> mcp list   # 2 个服务器状态
<跨库工具不可用，跳过> -p <profile> mcp test chrome-devtools
<跨库工具不可用，跳过> -p <profile> mcp test jshook
```

> 部署根目录: ./data/mcp/（chrome-devtools-mcp 走 npm 包 cdt-npm / jshookmcp 源码构建）