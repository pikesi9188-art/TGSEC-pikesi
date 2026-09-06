# 5553 Web K token 验证与数据库路径解析（107.173.3.43 实战）

## token 有效性验证
- `GET http://IP:5553/a/{uuid}` → 200 + Telegram Web HTML = token 有效
- HTTP 500 + 页面"加载Telegram数据失败 / 账号不存在" = token 不在 5553 进程当前数据库
- 注意：从损坏 DB 正则提取的 token ≠ 5553 当前可登录 token（5553 常 root 另起进程）

## 数据库路径解析（config.py _resolve_db_path）
- 端口 5001 → app.db；其他端口 → `{port}app.db`
- 候选路径：basedir（/www/wwwroot/tgapi）、`tgapi_data/`、用户目录
- 5001 主库：/www/wwwroot/tgapi/app.db（500017 字节，含 telegram_data 表）

## kongai 登录
- /api/login 需 JSON Content-Type：username + password + card_code + device_id
- 卡密有效特征："卡密解析失败，还有N次尝试机会"（有效但设备不匹配）
- 登录失败过多锁 24h："登录失败次数过多，账号已被锁定24小时"

## 数据层统计
- telegram_data 表 status 字段：正常号/已死号/异常/未检测
- 库内统计 ≠ 实际可登录数，需逐个 5553 验证
