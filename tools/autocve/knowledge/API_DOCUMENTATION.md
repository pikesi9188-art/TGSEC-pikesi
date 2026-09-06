# AutoCVE 接口文档

## 目录

- [1. 基本信息](#1-基本信息)
- [2. 认证](#2-认证)
- [3. 项目管理](#3-项目管理)
- [4. 审计任务](#4-审计任务)
- [5. Agent 审计任务](#5-agent-审计任务)
- [6. 审计会话](#6-审计会话)
- [7. Agent 直接审计](#7-agent-直接审计)
- [8. 漏洞管理](#8-漏洞管理)
- [9. 系统配置](#9-系统配置)
- [10. Skills 管理](#10-skills-管理)
- [11. 一键 CVE](#11-一键-cve)

## 1. 基本信息

### 1.1 服务地址

本地 Docker 部署默认地址：

```text
前端：http://localhost:3000
后端：http://localhost:8000
API 前缀：http://localhost:8000/api/v1
Swagger UI：http://localhost:8000/docs
OpenAPI JSON：http://localhost:8000/api/v1/openapi.json
```

健康检查：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/health` | 后端健康检查，返回 `{"status":"ok"}` |
| `GET` | `/` | 根路径，返回欢迎信息和演示账户提示 |

### 1.2 认证方式

登录接口返回 JWT Token。除公开接口外，请求头需要携带：

```http
Authorization: Bearer <access_token>
```

登录接口使用 OAuth2 Password Form，`Content-Type` 为 `application/x-www-form-urlencoded`：

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=demo@example.com&password=demo123"
```

其他 JSON 接口一般使用：

```http
Content-Type: application/json
Authorization: Bearer <access_token>
```

上传文件接口使用：

```http
Content-Type: multipart/form-data
Authorization: Bearer <access_token>
```

### 1.3 响应格式

多数接口直接返回对象或数组。错误响应由 FastAPI 统一返回：

```json
{
  "detail": "错误说明"
}
```

时间字段通常为 ISO 格式字符串，例如：

```text
2026-06-11T10:20:30.000000
```

### 1.4 常用枚举

Agent 相关状态值以数据库模型和运行时为准，常见取值包括：

| 类型 | 常见值 |
| --- | --- |
| 任务状态 | `pending`、`running`、`completed`、`failed`、`cancelled` |
| Agent 阶段 | `orchestrator`、`recon`、`scan`、`triage`、`finding`、`verification` |
| 漏洞严重性 | `critical`、`high`、`medium`、`low`、`info` |
| Finding Runtime Stack | `runtime` |
| 审计会话消息角色 | `system`、`user`、`assistant`、`tool_use`、`tool_result`、`handoff` |

## 2. 认证

### 2.1 认证接口

基础路径：`/api/v1/auth`

| 方法 | 路径 | 认证 | 说明 |
| --- | --- | --- | --- |
| `POST` | `/login` | 否 | 用户登录，返回 JWT Token |
| `POST` | `/register` | 否 | 注册用户；第一个注册用户会成为管理员 |

#### POST `/auth/login`

请求体为表单：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `username` | string | 是 | 用户邮箱 |
| `password` | string | 是 | 用户密码 |

响应：

```json
{
  "access_token": "jwt-token",
  "token_type": "bearer"
}
```

#### POST `/auth/register`

请求体：

```json
{
  "email": "user@example.com",
  "password": "password123",
  "full_name": "User Name"
}
```

响应字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 用户 ID |
| `email` | string | 邮箱 |
| `full_name` | string | 用户名 |
| `is_active` | boolean | 是否启用 |
| `is_superuser` | boolean | 是否管理员 |
| `role` | string | 角色 |
| `created_at` | datetime | 创建时间 |

### 2.2 用户接口

基础路径：`/api/v1/users`

| 方法 | 路径 | 认证 | 说明 |
| --- | --- | --- | --- |
| `GET` | `/` | 是 | 用户列表 |
| `POST` | `/` | 是 | 创建用户 |
| `GET` | `/me` | 是 | 当前用户信息 |
| `PUT` | `/me` | 是 | 更新当前用户信息 |
| `GET` | `/{user_id}` | 是 | 获取指定用户 |
| `PUT` | `/{user_id}` | 是 | 更新指定用户 |
| `DELETE` | `/{user_id}` | 是 | 删除用户 |
| `POST` | `/{user_id}/toggle-status` | 是 | 启用/禁用用户 |

用户创建字段：

```json
{
  "email": "user@example.com",
  "password": "password123",
  "full_name": "User Name",
  "role": "member",
  "phone": "",
  "github_username": "",
  "gitlab_username": ""
}
```

## 3. 项目管理

基础路径：`/api/v1/projects`

项目接口负责创建、导入、查看、更新、删除、恢复项目，并提供项目文件浏览、文件内容读取、ZIP 管理、分支查询和项目扫描入口。

### 3.1 项目接口总览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/managed-local-directories` | 获取后端托管的本地目录列表 |
| `POST` | `/` | 创建项目 |
| `GET` | `/` | 获取项目列表 |
| `GET` | `/deleted` | 获取回收站项目列表 |
| `GET` | `/stats` | 获取项目统计 |
| `POST` | `/repository-branches` | 查询远程仓库分支 |
| `GET` | `/{id}` | 获取项目详情 |
| `PUT` | `/{id}` | 更新项目 |
| `DELETE` | `/{id}` | 软删除项目 |
| `POST` | `/{id}/restore` | 恢复软删除项目 |
| `DELETE` | `/{id}/permanent` | 永久删除项目 |
| `GET` | `/{id}/files` | 获取项目文件树 |
| `GET` | `/{id}/file-content` | 获取指定文件内容 |
| `POST` | `/{id}/scan` | 基于项目创建普通扫描任务 |
| `GET` | `/{id}/zip` | 查看项目 ZIP 文件信息 |
| `POST` | `/{id}/zip` | 上传或替换项目 ZIP |
| `DELETE` | `/{id}/zip` | 删除项目 ZIP |
| `POST` | `/{id}/source-artifacts/delete` | 删除 ZIP 或持久化源码产物 |
| `GET` | `/{id}/branches` | 获取项目仓库分支 |

### 3.2 创建项目

`POST /api/v1/projects/`

请求体：

```json
{
  "name": "demo-project",
  "source_type": "repository",
  "repository_url": "https://github.com/example/demo.git",
  "repository_type": "github",
  "local_path": null,
  "workspace_mode": null,
  "description": "测试项目",
  "default_branch": "main",
  "programming_languages": ["python", "javascript"]
}
```

字段说明：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `name` | string | 是 | 项目名称 |
| `source_type` | string | 否 | `repository`、`zip` 或本地目录模式 |
| `repository_url` | string | 否 | Git 仓库地址 |
| `repository_type` | string | 否 | `github`、`gitlab`、`other` |
| `local_path` | string | 否 | 本地路径 |
| `workspace_mode` | string | 否 | 工作区模式 |
| `description` | string | 否 | 项目描述 |
| `default_branch` | string | 否 | 默认分支 |
| `programming_languages` | string[] | 否 | 项目语言 |

响应核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 项目 ID |
| `name` | string | 项目名称 |
| `source_type` | string | 来源类型 |
| `repository_url` | string | 仓库地址 |
| `local_path` | string | 本地路径 |
| `default_branch` | string | 默认分支 |
| `programming_languages` | string[] | 语言 |
| `is_active` | boolean | 是否启用 |
| `created_at` | datetime | 创建时间 |
| `owner` | object | 项目所有者 |

### 3.3 读取文件内容

`GET /api/v1/projects/{id}/file-content?path=<relative_path>`

响应：

```json
{
  "path": "src/app.py",
  "content": "file content",
  "size": 1024,
  "truncated": false
}
```

### 3.4 上传项目 ZIP

`POST /api/v1/projects/{id}/zip`

请求类型：`multipart/form-data`

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `file` | file | 是 | ZIP 文件 |

响应为 ZIP 元信息：

```json
{
  "has_file": true,
  "original_filename": "demo.zip",
  "file_size": 123456,
  "uploaded_at": "2026-06-11T10:00:00",
  "has_persistent_source": true,
  "persistent_source_path": "...",
  "persistent_source_updated_at": "2026-06-11T10:00:00"
}
```

### 3.5 查询仓库分支

`POST /api/v1/projects/repository-branches`

```json
{
  "repository_url": "https://github.com/example/demo.git",
  "repository_type": "github"
}
```

响应：

```json
{
  "branches": ["main", "develop"],
  "default_branch": "main",
  "error": null
}
```

## 4. 审计任务

基础路径：`/api/v1/tasks`

该组接口面向普通扫描任务和历史任务记录。Agent 化审计任务使用 `/agent-tasks`。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/` | 获取任务列表 |
| `GET` | `/{id}` | 获取任务详情 |
| `POST` | `/{id}/cancel` | 取消任务 |
| `GET` | `/{id}/issues` | 获取任务发现的问题 |
| `PATCH` | `/{task_id}/issues/{issue_id}` | 更新问题状态 |
| `GET` | `/{id}/report/pdf` | 导出任务 PDF 报告 |

问题更新请求：

```json
{
  "status": "resolved",
  "is_false_positive": false
}
```

## 5. Agent 审计任务

基础路径：`/api/v1/agent-tasks`

Agent 任务是 AutoCVE 的核心审计入口。它会启动 Orchestrator，并按工作流执行 Recon、Scan、Triage、Finding、Verification 等节点。

### 5.1 Agent 任务接口总览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/` | 创建 Agent 审计任务 |
| `GET` | `/` | 获取 Agent 任务列表 |
| `GET` | `/debug-tasks` | 获取调试任务列表 |
| `GET` | `/{task_id}` | 获取任务详情 |
| `GET` | `/{task_id}/debug-trace` | 获取任务调试 Trace |
| `POST` | `/{task_id}/resume` | 恢复任务 |
| `POST` | `/{task_id}/cancel` | 取消任务 |
| `GET` | `/{task_id}/events` | 获取事件流或事件数据 |
| `GET` | `/{task_id}/stream` | SSE 任务实时流 |
| `GET` | `/{task_id}/events/list` | 获取事件列表 |
| `GET` | `/{task_id}/findings` | 获取任务漏洞列表 |
| `GET` | `/{task_id}/findings/{finding_id}` | 获取单个漏洞 |
| `GET` | `/{task_id}/summary` | 获取任务摘要 |
| `PATCH` | `/{task_id}/findings/{finding_id}` | 更新漏洞状态或人工信息 |
| `GET` | `/{task_id}/tree` | 获取 Agent 执行树 |
| `GET` | `/{task_id}/checkpoints` | 获取 Runtime checkpoints |
| `GET` | `/{task_id}/checkpoints/{checkpoint_id}` | 获取 checkpoint 详情 |
| `GET` | `/{task_id}/report` | 获取任务报告 |

### 5.2 创建 Agent 审计任务

`POST /api/v1/agent-tasks/`

请求体：

```json
{
  "project_id": "project-id",
  "name": "demo 版本审计",
  "description": "审计 v1.0.0 版本的认证和文件上传逻辑",
  "audit_scope": {
    "mode": "targeted"
  },
  "target_vulnerabilities": ["RCE", "SQL Injection", "Path Traversal"],
  "verification_level": "sandbox",
  "version_label": "v1.0.0",
  "version_tag": "v1.0.0",
  "branch_name": "main",
  "exclude_patterns": ["node_modules", "__pycache__", ".git", "*.min.js"],
  "target_files": ["src/auth.py", "src/upload.py"],
  "max_iterations": 50,
  "timeout_seconds": 1800,
  "finding_runtime_stack": "runtime"
}
```

字段说明：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `project_id` | string | 是 | 项目 ID |
| `name` | string | 否 | 任务名称 |
| `description` | string | 否 | 任务描述 |
| `audit_scope` | object | 否 | 审计范围配置 |
| `target_vulnerabilities` | string[] | 否 | 重点漏洞类型 |
| `verification_level` | string | 否 | `analysis_only`、`sandbox`、`generate_poc` |
| `version_label` | string | 是 | 用户输入的版本标识 |
| `version_tag` | string | 否 | Git tag |
| `branch_name` | string | 否 | Git 分支 |
| `exclude_patterns` | string[] | 否 | 排除规则 |
| `target_files` | string[] | 否 | 目标文件 |
| `max_iterations` | int | 否 | 最大迭代数，1-200 |
| `timeout_seconds` | int | 否 | 超时时间，60-7200 |
| `finding_runtime_stack` | string | 否 | 当前建议使用 `runtime` |

响应核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 任务 ID |
| `project_id` | string | 项目 ID |
| `status` | string | 任务状态 |
| `current_phase` | string | 当前阶段 |
| `progress_percentage` | number | 进度 |
| `findings_count` | int | 漏洞数量 |
| `verified_count` | int | 已验证数量 |
| `runtime_session_id` | string | Finding Runtime 会话 ID |
| `runtime_completion_mode` | string | Runtime 完成模式 |
| `created_at` | datetime | 创建时间 |

### 5.3 获取事件与实时流

事件列表：

```http
GET /api/v1/agent-tasks/{task_id}/events/list
```

SSE 实时流：

```http
GET /api/v1/agent-tasks/{task_id}/stream
Accept: text/event-stream
```

事件响应核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 事件 ID |
| `task_id` | string | 任务 ID |
| `event_type` | string | 事件类型 |
| `phase` | string | 阶段 |
| `message` | string | 展示消息 |
| `sequence` | int | 序号 |
| `tool_name` | string | 工具名 |
| `tool_input` | object | 工具输入 |
| `tool_output` | object | 工具输出 |
| `metadata` | object | 扩展信息 |

### 5.4 获取漏洞结果

```http
GET /api/v1/agent-tasks/{task_id}/findings
GET /api/v1/agent-tasks/{task_id}/findings/{finding_id}
PATCH /api/v1/agent-tasks/{task_id}/findings/{finding_id}
```

漏洞响应核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | Finding ID |
| `vulnerability_type` | string | 漏洞类型 |
| `severity` | string | 严重性 |
| `title` | string | 标题 |
| `description` | string | 描述 |
| `file_path` | string | 文件路径 |
| `line_start` / `line_end` | int | 起止行 |
| `code_snippet` | string | 代码片段 |
| `is_verified` | boolean | 是否验证 |
| `confidence` | number | 置信度 |
| `status` | string | 状态 |
| `poc` | object | PoC 信息 |
| `exploit_chain` | object[] | 利用链 |
| `impact` | string | 影响 |
| `cve_justification` | string | CVE 价值说明 |

### 5.5 获取任务摘要

`GET /api/v1/agent-tasks/{task_id}/summary`

响应：

```json
{
  "task_id": "task-id",
  "status": "completed",
  "security_score": 78,
  "total_findings": 3,
  "verified_findings": 1,
  "severity_distribution": {
    "critical": 0,
    "high": 1,
    "medium": 2
  },
  "vulnerability_types": {
    "Path Traversal": 1
  },
  "duration_seconds": 300,
  "phases_completed": ["recon", "finding", "verification"]
}
```

## 6. 审计会话

基础路径：`/api/v1/audit-sessions`

审计会话接口用于查看 Runtime 会话中的消息、工具调用、Skill 调用、Memory、Handoff，并支持围绕一次审计继续对话。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/{session_id}` | 获取会话详情 |
| `GET` | `/{session_id}/messages` | 获取会话消息 |
| `GET` | `/{session_id}/tool-calls` | 获取工具调用 |
| `GET` | `/{session_id}/skills` | 获取会话 Skill 列表 |
| `GET` | `/{session_id}/skill-invocations` | 获取 Skill 调用记录 |
| `GET` | `/{session_id}/memories` | 获取 Memory |
| `GET` | `/{session_id}/handoffs` | 获取 Handoff |
| `POST` | `/{session_id}/messages` | 追加用户消息并获取普通响应 |
| `POST` | `/{session_id}/messages/stream` | 追加用户消息并获取流式响应 |

追加消息请求：

```json
{
  "content": "请继续分析这个漏洞是否具备 CVE 提交价值",
  "mode": "chat",
  "selected_skill_refs": ["cve-report-writer"]
}
```

消息响应核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 消息 ID |
| `session_id` | string | 会话 ID |
| `sequence` | int | 序号 |
| `role` | string | 角色 |
| `content` | string | 内容 |
| `metadata` | object | 元数据 |
| `created_at` | datetime | 创建时间 |

## 7. Agent 直接审计

基础路径：`/api/v1/agent-direct-audit`

直接审计接口用于不经过完整 Agent 任务流程，直接创建一个项目绑定的审计会话并与 Agent 对话。适合调试 Finding Runtime、补充人工追问、验证工具调用和生成漏洞报告。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/sessions` | 获取直接审计会话列表 |
| `POST` | `/sessions` | 创建直接审计会话 |
| `POST` | `/sessions/stream` | 创建会话并流式运行 |
| `GET` | `/sessions/{session_id}` | 获取会话详情 |
| `PATCH` | `/sessions/{session_id}/guardrails` | 更新 guardrails 开关 |
| `GET` | `/sessions/{session_id}/messages` | 获取消息 |
| `POST` | `/sessions/{session_id}/messages` | 发送消息 |
| `POST` | `/sessions/{session_id}/messages/stream` | 发送消息并流式响应 |
| `POST` | `/sessions/{session_id}/tool-calls/{tool_call_id}/approve/stream` | 批准工具调用并继续流式执行 |
| `GET` | `/sessions/{session_id}/managed-vulnerabilities` | 获取会话关联漏洞 |
| `POST` | `/sessions/{session_id}/managed-vulnerabilities/sync-latest-report` | 同步最新报告到漏洞管理 |

创建会话请求：

```json
{
  "project_id": "project-id",
  "content": "请重点审计文件上传相关逻辑",
  "guardrails_enabled": false
}
```

工具批准请求：

```json
{
  "scope": "single_use"
}
```

`scope` 可选：

- `single_use`：仅批准本次工具调用。
- `session`：当前会话内批准。

## 8. 漏洞管理

基础路径：`/api/v1/vulnerabilities`

漏洞管理接口面向最终结构化漏洞资产，区别于 `/agent-tasks/{task_id}/findings` 中的任务内 Finding。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/` | 获取漏洞列表 |
| `GET` | `/{vulnerability_id}` | 获取漏洞详情 |
| `PATCH` | `/{vulnerability_id}` | 更新漏洞人工状态、CVE 状态等 |
| `DELETE` | `/{vulnerability_id}` | 删除漏洞 |
| `GET` | `/{vulnerability_id}/reports` | 获取漏洞报告列表 |
| `GET` | `/{vulnerability_id}/reports/{report_kind}` | 获取指定类型报告 |
| `PATCH` | `/{vulnerability_id}/reports/{report_kind}` | 更新报告 Markdown |
| `GET` | `/{vulnerability_id}/reports/{report_kind}/export` | 导出报告 |

漏洞更新请求：

```json
{
  "vulnerability_name": "Path Traversal in file download",
  "vulnerability_type": "Path Traversal",
  "severity": "high",
  "human_review_result": "confirmed",
  "cve_request_status": "drafting",
  "cve_failure_reason": null,
  "cve_id": null
}
```

报告更新请求：

```json
{
  "markdown_content": "# Vulnerability Report\n\n...",
  "source_type": "manual"
}
```

漏洞列表响应核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 漏洞 ID |
| `project_id` | string | 项目 ID |
| `task_id` | string | 来源任务 ID |
| `finding_id` | string | 来源 Finding ID |
| `project_name` | string | 项目名称 |
| `vulnerability_name` | string | 漏洞名称 |
| `vulnerability_type` | string | 漏洞类型 |
| `severity` | string | 严重性 |
| `human_review_result` | string | 人工复核结果 |
| `cve_request_status` | string | CVE 提交状态 |
| `cve_id` | string | CVE 编号 |
| `report_generation_status` | string | 报告生成状态 |

## 9. 系统配置

基础路径：`/api/v1/config`

系统配置接口管理用户级模型配置、不同 Agent 的模型方案、工作流开关、Token、连接测试和资产同步。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/defaults` | 获取默认配置 |
| `GET` | `/me` | 获取当前用户配置 |
| `PUT` | `/me` | 保存当前用户配置 |
| `DELETE` | `/me` | 删除当前用户配置，恢复默认 |
| `POST` | `/test-llm` | 测试模型连接 |
| `POST` | `/test-agent-model` | 测试某个 Agent 的模型配置 |
| `POST` | `/sync-assets` | 同步 Skills 和报告模板资产 |
| `GET` | `/llm-providers` | 获取支持的模型供应商 |

保存配置请求：

```json
{
  "llmConfig": {
    "llmProvider": "openai",
    "llmApiKey": "sk-xxx",
    "llmModel": "gpt-4o-mini",
    "llmBaseUrl": "https://api.openai.com/v1",
    "llmTimeout": 150,
    "llmTemperature": 0.1,
    "llmMaxTokens": 4096,
    "endpointProtocol": "openai",
    "toolMessageFormat": "openai",
    "agentConfigs": {
      "finding": {
        "enabled": true,
        "llmProvider": "deepseek",
        "llmApiKey": "xxx",
        "llmModel": "deepseek-chat",
        "llmBaseUrl": "https://api.deepseek.com/v1",
        "maxIterations": 50
      }
    },
    "modelProfiles": [
      {
        "id": "profile-1",
        "name": "默认方案",
        "isDefault": true,
        "llmProvider": "openai",
        "llmModel": "gpt-4o-mini"
      }
    ]
  },
  "otherConfig": {
    "githubToken": "ghp_xxx",
    "gitlabToken": "glpat_xxx",
    "maxAnalyzeFiles": 0,
    "llmConcurrency": 3,
    "llmGapMs": 2000,
    "outputLanguage": "zh-CN",
    "workflowConfig": {
      "recon": true,
      "scan": true,
      "triage": true,
      "finding": true,
      "verification": true
    }
  }
}
```

测试模型请求：

```json
{
  "provider": "openai",
  "apiKey": "sk-xxx",
  "model": "gpt-4o-mini",
  "baseUrl": "https://api.openai.com/v1",
  "endpointProtocol": "openai",
  "toolMessageFormat": "openai",
  "prompt": "请只回复：模型连接成功。"
}
```

## 10. Skills 管理

基础路径：`/api/v1/skills`

Skills 接口用于导入、创建、编辑、删除 Skill，并为不同 Agent 配置绑定关系。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/` | 获取 Skill 列表 |
| `GET` | `/{skill_id}` | 获取 Skill 详情 |
| `POST` | `/` | 创建 Skill |
| `POST` | `/import-github` | 从 GitHub 导入 Skill |
| `POST` | `/upload-zip` | 上传 ZIP 导入 Skill |
| `PUT` | `/{skill_id}` | 更新 Skill |
| `DELETE` | `/{skill_id}` | 删除 Skill |
| `POST` | `/{skill_id}/bindings` | 为 Agent 创建 Skill 绑定 |
| `PUT` | `/{skill_id}/bindings/{binding_id}` | 更新绑定 |
| `DELETE` | `/{skill_id}/bindings/{binding_id}` | 删除绑定 |
| `POST` | `/resync` | 重新同步 Skill 库 |

创建 Skill 请求：

```json
{
  "name": "Code Audit Finding",
  "slug": "code-audit-finding",
  "description": "面向 Finding Agent 的代码审计 Skill",
  "source_type": "manual",
  "source_url": null,
  "content": "# Skill\n\n...",
  "tags": ["security", "finding"],
  "frontmatter": {},
  "extension_manifest": [],
  "extension_payload": {},
  "is_active": true,
  "is_system": false,
  "bindings": [
    {
      "agent_type": "finding",
      "enabled": true,
      "always_include": false,
      "sort_order": 0,
      "match_keywords": ["RCE", "SQL Injection"],
      "match_config": {}
    }
  ]
}
```

从 GitHub 导入：

```json
{
  "repo_url": "https://github.com/example/audit-skill",
  "agent_type": "finding",
  "bind_to_agent": true,
  "enabled": true,
  "always_include": false,
  "match_keywords": ["cve", "audit"]
}
```

## 11. 一键 CVE

基础路径：`/api/v1/one-click-cve`

一键 CVE 接口用于创建批次任务，自动筛选 GitHub 项目并持续创建 Agent 审计任务，直到找到目标数量的 CVE 候选。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/batches` | 创建一键 CVE 批次 |
| `GET` | `/batches` | 获取批次列表 |
| `GET` | `/batches/{batch_id}` | 获取批次详情 |
| `POST` | `/batches/{batch_id}/cancel` | 取消批次 |

创建批次请求：

```json
{
  "target_count": 3,
  "prefer_security_advisory": true
}
```

响应核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 批次 ID |
| `user_id` | string | 用户 ID |
| `requested_count` | int | 目标数量 |
| `found_count` | int | 已找到数量 |
| `status` | string | 批次状态 |
| `prefer_security_advisory` | boolean | 是否优先安全公告项目 |
| `projects` | object[] | 本批次处理的项目 |

