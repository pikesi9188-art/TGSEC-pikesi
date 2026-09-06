---
name: 器胚·星札
description: >-
  大爱仙尊·二进制/SQLite 被 JSON 转义损坏时恢复数据。触发词：malformed/转义还原。
---

# binary-recovery-json-transcoding（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/recon-and-methodology/binary-recovery-json-transcoding/SKILL.md`
- 手法：`传承/逆骨·认族.md`
- 工具：`python3 炼蛊房/reverse_skill_route.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name binary-recovery-json-transcoding`

---

# 二进制数据从 JSON 转义恢复（任意文件读取场景）

## 场景
任意文件读取接口返回文件内容时经常是 `{"content": "..."}` 形式，二进制（SQLite 等）被转义成混合 unicode 字符串：单字节（\x00-\xff）和 UTF-8 多字节字符混杂。直接 `content.encode('latin-1')` 会因 >255 字符报错；`sqlite3` 打开常报 `database disk image is malformed`。

## 还原方法（能修则修）
```python
d = json.load(open(raw_json))
c = d['content']
out = bytearray()
for ch in c:
    o = ord(ch)
    if o < 256:
        out.append(o)
    else:
        out.extend(ch.encode('utf-8'))  # 多字节字符按 UTF-8 还原
open(out_db, 'wb').write(bytes(out))
```
- 检查 SQLite 头（`SQLite format 3\0` + page_size 4096 正常 ≠ 数据完好）
- 即使头正常，JSON 传输中非 ASCII 字节可能已丢失信息（U+FFFD/替换字符），**这种场景 sqlite3 常仍报 malformed**

## 兜底方案（结构坏了也要拿数据）：strings + 正则
结构损坏无法用 sqlite3 时，直接在原始字节上做文本提取：
```python
data = open(db,'rb').read()
# 找状态标记（UTF-8 字节序列）
marker = '正常号'.encode('utf-8')
pos = 0
while (idx := data.find(marker, pos)) != -1:
    window = data[max(0,idx-500):idx]
    phones = re.findall(rb'\d{10,14}', window)
    tokens = re.findall(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', window)
    # 取窗口内最后一个 phone/token（SQLite 行内字段顺序）
    pos = idx + 1
```
- 中文标记必须用 bytes 正则（`rb'(?:中国|印度|日本)'`），不能直接写中文字面量到 rb'' 里
- 全局计数用 `text.count('正常号')` 快速统计状态分布
- 关联关系靠"字段在行内的位置顺序"，取窗口最后一个匹配通常就是本行的 token/phone

## 实战参考
- okinawa-anne.com：SQLite 经 /api/books/{id}/content JSON 返回，malformed 后用 strings 提取表结构（CREATE TABLE）确认表名
- kongai（107.173.3.43 tgapi app.db）：JSON 转义后 500KB→524KB，sqlite3 malformed，用 bytes 正则提取出 253 个"正常号"记录 + 597 个 UUID token + 3549 个手机号（有效账号统计）
- 注意：从损坏 DB 提取的 token 未必等于运行中进程（如 5553 Web K 代理）读的库——验证有效性要打实际接口，不能只看 DB 提取结果

## 验证技巧
- 提取的账号/token 是否"真实可用"：调实际服务接口验证（如 5553 /a/{token} 返回 200 TG Web = 有效；500 "账号不存在" = 提取的库与运行库不一致），别信提取结果本身
