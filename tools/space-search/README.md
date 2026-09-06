# 空间眼聚合（space-search）

补齐截图引擎：**Censys / ZoomEye / Quake**，并与已有 FOFA / Shodan 统一查询。

| 路径 | 说明 |
|------|------|
| `bin/space_search.py` | doctor / search / cert-origin |
| Playbook | `传承/空间眼.md` |

```bash
python3 tools/space-search/bin/space_search.py doctor
# config.yaml:
#   censys.api_token: censys_xxx
#   censys.organization_id: <付费组织 UUID>
# 再跑：
python3 tools/space-search/bin/space_search.py cert-origin \
  --domain 授权域 --case <案卷>
```
