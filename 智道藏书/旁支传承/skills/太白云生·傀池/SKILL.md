---
name: 太白云生·傀池
description: "Use when pentesting TG bot-pool panels or Go pprof recon."
version: 1.0.0
author: bot3-curator
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [telegram, bot-pool, mass-messaging, pprof, proxy, daaixianzun]
    category: daaixianzun
---

> **太白云生**
> 江山如故人未还，一羽千里破云关。
> 师弟二字恩与债，逆流河底鹤难还。

# Telegram Bot-Pool / Mass-Messaging Panel Pentest (TG Share V2 style) + Infra Recon

Use when the operator of a Telegram gambling/wallet/card business runs **bot pools** (水军号/刷粉/mass-DM infra): management panels that hold worker Telegram sessions, bot tokens, proxy pools, targets and send-queues. Also covers the **Go pprof recon** and **SOCKS5 proxy-pool firewall-evasion** techniques that get you into otherwise-firewalled operator boxes. Pairs with `yudao-gambling-tma-pentest` (casino-side protocol) and `telegram-gambling-tma-pentest` (Qzino family).

## 1. Discovery (FOFA)
- `body="Bot池"` — surfaces mass-bot panels whose JS/UI says 水军号/Bot池 (the 世博/快约 operator family: kuaiyue-bot2.pw, 50.114.5.99, 142.111.146.2, 66.42.61.86).
- `title="TG Share"`, `body="水军号"`, `title="管理面板" && body="worker"`.
- Cross-link with the finance panel (公司记账) expense notes: 刷粉平台充值/账号底料/魔云腾盒子 → operator runs this exact infra.
- Brand domains found inside the panel HTML (ad examples, `官网` buttons) reveal the operator's other ventures (e.g. kuaiyue.vip).

## 2. TG Share V2 panel — fingerprint & auth
- Python 3.14 **aiohttp** single-file panel (81KB HTML, all JS inline); default username `admin` pre-filled in the login form.
- Login: `POST /api/login` `{username, password}` → `{"ok":true,"token":...}`; store as `tg_auth_token`.
- Every other API needs header `X-Auth-Token: <token>`; without it → 401 `未授权或登录已过期, 请重新登录`.
- **No login lockout observed** (30k+ rapid attempts OK) → brute-force friendly. Wordlist: operator brand + 公司记账 usernames (dupeng/dupi) + suffixes; the pre-filled `value="admin"` hints the real user is admin.
- Enumerate ALL sibling instances — some hosts run older/weaker builds.

## 3. TG Share V2 — API surface (all auth'd)
- `/api/bots` (list/add/batch/verify, `/api/bots/{id}/verify`, `/api/bots/verify-all`)
- `/api/workers` (list/add, `/api/workers/batch-import`, `/api/workers/connect-all`, `/api/workers/{id}/login` → phone/code/2FA, `/api/workers/assign-bots`, `/api/workers/setup-profiles`)
- `/api/targets` (mass-DM recipients; `/api/targets/all` DELETE), `/api/send/start|stop|status`, `/api/proxies` (+`/auto-assign`, `/batch`), `/api/api-configs` (+`/auto-assign`, `/batch`), `/api/ads`, `/api/avatars/upload`, `/api/config`, `/api/restrictions/reset` ("水军号现在可以使用全部Bot池"), `/api/status`.
- Token = full control of the bot pool: read worker sessions, steal bot tokens, fire mass sends, exfil targets.

## 4. Go pprof recon (exposed /debug/pprof on monitoring agents)
When a host firewalls everything but leaks ONE port (often a Go monitoring agent, e.g. **Hawkeye** / Mobvista `collecter` on :19100):
- `GET /debug/pprof/` → index (means no whitelist); `/metrics` 403 = whitelist middleware exists but pprof slipped out.
- `GET /debug/pprof/goroutine?debug=2` — full stacks incl. args → source layout, package paths (`gitlab.mobvista.com/hawkeye/collecter/...`), binary name via `/debug/pprof/cmdline` (`./bin/hawkeye_agent`).
- `GET /debug/pprof/heap?debug=2` — 2.4MB dump; `strings` it for secrets/tokens/URLs (usually only Go runtime symbols — the config lives in files, not heap; treat as low-yield).
- Value: recon only (read-only). Confirms host role + what else runs there; pairs with FOFA port maps (agent port open while console/MySQL are firewalled = the operator's firewall posture).

## 5. SOCKS5 proxy-pool firewall evasion
- User supplies `IP:port:user:pass` lists (e.g. US pools, 50101). Install `pysocks` via `python3`.
- **Sanity-test each proxy against a known-good target first** (1.1.1.1:443) — then parallel port-scan targets with `ThreadPoolExecutor` (24–30 workers, 4–5s timeouts).
- Lesson: even 10 healthy US proxies may ALL be blocked for specific host:port pairs (operator IP-firewalls broadly). Only ports FOFA sees as "open" that you can actually connect = what leaks. Don't burn an hour re-scanning the same blocked pair.
- r.jina.ai text proxy rescues blocked-by-IP (not blocked-by-geo) hosts; fails when the host itself is down or DNS unresolvable.

## 6. Corrections/notes for the sibling yudao skill
`yudao-gambling-tma-pentest` (same profile, possibly shadowed by a default-profile copy — see Pitfalls): two verified refinements from 2026-08:
1. `checkDepositOrderIntervalTime` cooldown (~10.8h) is **advisory only** — `deposit-order/create` still succeeds while `time>0` (verified with time=48272). Do NOT wait for it.
2. `orderUploadVoucher` **does NOT fetch `urlList` URLs** (httpbin delay timing test flat ~1s) — no SSRF there; don't re-test.

## 7. Pitfalls
- Login-burst IP bans apply to the PHP boxes (公司记账 etc.) — via proxy pool, keep `sleep(0.3–3)`.
- aiohttp panels may 405 non-POST methods on /api/login; path traversal `/../` → 404 (static-serve safe).
- Brute force is slow serial (~0.5s/req) — parallelize 8–10 workers, watch for the 401-only error body (no lockout in this panel).
- skill_manage name resolution prefers the `default` profile: if a same-name skill exists there, writes to the bot3 copy are refused ("switch profiles or use file tools with cross_profile=True"). Keep per-family skills under UNIQUE names per profile to avoid shadowing.

## References
- `references/tg-share-panel-kuaiyue.md`（⚠️本包未含此案例文件，跳过） — session case notes: hosts, API map, auth, wordlist approach, 世博/快约 operator linkage.
