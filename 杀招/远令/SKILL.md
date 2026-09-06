---
name: 远令
description: >-
  区块链 RPC 节点 txpool 暴露 + MEV 三明治攻击面检测。
  触发：域名含 -mainnet / -rpc / node. / rpc.；响应含 jsonrpc / Geth / Bor / reth /
  Erigon / Nethermind；POST 返回 JSON-RPC；端口 8545/8546/30303；
  web3_clientVersion / txpool / mempool / pending transactions / MEV / sandwich。
  见到区块链 RPC 端点立刻按本卡检测，禁止只测 eth_blockNumber 结案。
---

# 区块链 RPC txpool MEV 攻击面

**来源**: token.im 案 (2026-09-02) — imToken 公开 RPC 暴露 txpool + sendRawTransaction，构成完整 MEV 基础设施。

## 成功口径

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | `web3_clientVersion` 返回节点信息 | 只能 `eth_blockNumber` |
| L2 | `txpool_status` 或 `txpool_content` 可读 | 只有版本信息 |
| L2b | `txpool_content` + `eth_sendRawTransaction` 均可用 = **CRITICAL MEV** | 只有 txpool 无 sendRawTx |
| L3 | 解码出 DEX swap 交易 + 计算 sandwich 利润 | 有 txpool 但无 DEX 交易 |

## 检测流程

### Step 1: 节点指纹

```bash
# 确认 JSON-RPC 可用
curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}'

# 预期: {"result":"Geth/v1.x.x/linux-amd64/go1.x.x"} 或类似
```

常见节点类型:
- `Geth` — go-ethereum（BSC fork / ETH mainnet）
- `Bor` — Polygon
- `reth` — Paradigm Rust 客户端（Base/OP）
- `Erigon` — 高效全节点
- `Nethermind` — .NET 客户端
- `Tenderly` — 模拟/代理（通常无 txpool）

### Step 2: txpool 暴露检测

```bash
# txpool 状态（轻量）
curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"txpool_status","params":[],"id":1}'
# 预期: {"result":{"pending":"0x1a","queued":"0x6ef"}}

# txpool 完整内容（重量级，可能数 MB）
curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}'
```

**关键判断**: 返回 `result` 且含 `pending`/`queued` 字典 = txpool 暴露。返回 `error` "method not found" = 已禁用。

### Step 3: 交易提交检测

```bash
# 发一个格式错误的 tx 测试端点可用性
curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xdead"],"id":1}'
```

**判断**:
- `unmarshal transaction failed` / `rlp: value size exceeds` / `failed to decode` = **端点可用**（CRITICAL）
- `method not found` / `not supported` = 已禁用
- `the method does not exist` = 已移除

### Step 4: 管理接口暴露

```bash
for method in eth_accounts net_peerCount admin_peers admin_nodeInfo \
  debug_traceTransaction txpool_inspect eth_mining eth_coinbase eth_sign; do
  curl -s -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":[],\"id\":1}"
done
```

**高危方法**:
- `admin_peers` / `admin_nodeInfo` → 网络拓扑泄露
- `eth_sign` / `personal_sign` → 可代签交易
- `debug_*` → 执行跟踪、状态读取
- `miner_*` → 挖矿控制

### Step 5: DEX Swap 识别（仅 txpool 暴露时）

已知 DEX Router 地址:

| DEX | 链 | Router 地址 |
|-----|-----|-------------|
| PancakeSwap V2 | BSC | `0x10ed43c718714eb63d5aa57b78b54704e256024e` |
| PancakeSwap V3 | BSC | `0x13f4ea83d0bd40e75c8222255bc855a974568dd4` |
| Uniswap V3 | ETH/Polygon | `0xe592427a0aece92de3edee1f18e0157c05861564` |
| Uniswap Universal | Multi | `0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45` |
| QuickSwap V2 | Polygon | `0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff` |
| SushiSwap | Multi | `0x1b02da8cb0d097eb8d57a175b88c7d8b47997506` |
| Paraswap V5 | Multi | `0xdef171fe48cf0115b1d80b88dc8eab59176fee57` |

Swap Method ID:
- `0x38ed1739` = swapExactTokensForTokens
- `0x7ff36ab5` = swapExactETHForTokens
- `0x18cbafe5` = swapExactTokensForETH
- `0x791ac947` = swapExactTokensForTokensSupportingFee
- `0x414bf389` = exactInputSingle (V3)
- `0x5ae401dc` = multicall

过滤 txpool 中 `to` 匹配 Router + `input` 前 4 字节匹配 Method ID = 可被三明治的 swap。

## 等级判定

| 组合 | 等级 | 说明 |
|------|------|------|
| txpool_content + sendRawTx | **CRITICAL** | 完整 MEV 基础设施，直接资金损失 |
| txpool_content 可读，sendRawTx 禁用 | **HIGH** | 信息泄露（交易隐私、策略泄露） |
| txpool_status 可读 | **MEDIUM** | 统计级泄露 |
| 仅 clientVersion/peerCount | **LOW** | 运维信息泄露 |

## 多链扫描模板

对 Web3 项目，枚举所有链的 RPC 端点（常见命名模式）:
```
{chain}-mainnet.{domain}
{chain}-rpc.{domain}
mainnet-rpc.{domain}
rpc.{domain}
node.{domain}
```

常见 chain: `eth` / `bsc` / `polygon` / `arbitrum` / `optimism` / `base` / `avalanche` / `fantom`

## 三明治攻击利润估算

```
每笔 sandwich 利润 ≈ swap_value × slippage_tolerance × pool_depth_factor
典型范围: swap 金额的 0.1% ~ 0.5%
```

影响因子:
- 池子深度（TVL 越小利润率越高）
- 滑点设置（用户设高滑点 = 更多利润空间）
- 其他 MEV bot 竞争（降低实际利润）
- gas 成本（BSC 极低 ~0.05 Gwei；ETH 主网高）

## 不走这张卡

| 指纹 | 走 |
|------|-----|
| Spring Boot /actuator | `spring-gateway-actuator-killchain` |
| REST API 无认证 | `api-security` 或九阶段全文 |
| GraphQL 暴露 | `graphql` 相关 Skill |
| WebSocket RPC | `websocket-pentest` |

## 真源

- 手法：`传承/凤九歌·天地歌.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
