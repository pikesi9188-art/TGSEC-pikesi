---
name: 太白云生·寻傀
description: "Find/verify Telegram bots with Mini Apps (TMA target recon)."
version: 1.0.0
metadata:
    tags: [telegram, bot, tma, recon, telethon]
    category: telegram
---

> **太白云生**
> 江山如故人未还，一羽千里破云关。
> 师弟二字恩与债，逆流河底鹤难还。

# Telegram Bot / Mini App Discovery (TMA target recon)

Use when the user wants to FIND Telegram bots that have Mini Apps (Web Apps / TMA) — "怎么找带 mini app 的 bot", "找点 TMA 目标", TMA 批采前收集候选目标. After discovery, hand off to the attack playbook (user pack: `telegram-mini-app-bot-security`).

## 1. Native search (fast, low volume)

- Telegram search box → keywords + **Bots** filter tab. There is NO dedicated "Mini App" filter.
- Keywords that hit: `mini app`, `tma`, `tap to earn`, `airdrop`, `game`, `wallet`, `earn`. TMA bots almost always mention "Mini App"/"Web App" in their bio.

## 2. Directories / aggregator channels

- `@tonapps` — verified real channel ("Telegram Open Network Applications"), TON-ecosystem apps (most TMAs are TON-based).
- `ton.app` — TON app catalog, filterable by Telegram Mini App.
- `storebot.me` / `botostore.com` — generic bot directories.

## 3. MTProto batch enumeration (core, scalable)

Bot API's `getChatMenuButton` only works for bots **you own** → useless for discovery. With a **user-account session** (Telethon), `GetFullUserRequest` on ANY bot returns `full_user.bot_info.menu_button`:

- `BotMenuButtonWebApp(text, url)` → has Mini App; `url` is the WebApp URL = pentest entry point
- `BotMenuButtonDefault` / `BotMenuButtonCommands` / `None` → no menu-button Mini App
- ⚠️ The type is **`BotMenuButtonWebApp`** (`telethon.tl.types`), NOT `KeyboardButtonWebApp` — that one is the inline-keyboard button type used in messages. No session with the bot is required.
- ⚠️ **telethon 版本差异 (2026-08 @bfyl 实测)**: 某些 telethon 版本没有 `BotMenuButtonWebApp` 类 (直接 ImportError)，menu_button 是通用 `BotMenuButton(text, url)`。别硬 import 具体类，用 `getattr` 兜底：

```python
from telethon import TelegramClient
from telethon.tl.functions.users import GetFullUserRequest

async def probe(client, username):
    fu = await client(GetFullUserRequest(username))
    bi = getattr(fu.full_user, 'bot_info', None)
    mb = getattr(bi, 'menu_button', None)
    return getattr(mb, 'url', None) or None   # 任何带 url 的 menu_button 类型均命中
```

## 4. Second signal: message buttons

Some bots only expose the TMA via a WebApp button in their `/start` reply and have no menu button set. Send `/start`, wait ~1.5s, then scan the last few messages' inline buttons for `KeyboardButtonWebApp` / `KeyboardButtonWebView` (has `.url`) vs `KeyboardButtonUrl` (plain link, NOT a TMA).

## 5. Script

`scripts/enumerate_tma_bots.py` — batch-probe a username list (positional args or `-f file`), JSONL output with `has_mini_app`, `webapp_url`, `message_webapp_urls`. Run:

```bash
export TELEGRAM_API_ID=... TELEGRAM_API_HASH=...
python3 enumerate_tma_bots.py -f botlist.txt -o out.jsonl
```

## 6. Workflow

1. Collect candidates: native search + @tonapps/ton.app + directory scraping
2. Batch-verify with `scripts/enumerate_tma_bots.py` → JSONL
3. `has_mini_app: true` → hand off to `telegram-mini-app-bot-security` (initData, WebView XSS, webhook, callback_data...)

## 7. Pitfalls

- t.me page title `View @x` = public channel exists; `Contact @x` is shown for users, bots AND squatted/nonexistent names — NOT a reliable existence check. Only "View" is positive.
- Telegram session must be a **user account**; bot accounts can't fetch other bots' full info.
- `menu_button` only reflects the bot's default menu button — always also scan message buttons (§4), a bot can have a TMA reachable only via inline button.
- Usernames may resolve to non-bot users → check `entity.bot` before probing `bot_info`.
- Telethon `bot_info.menu_button` may be `None` on some API layers — handle `getattr(bi, "menu_button", None)`.
- 家族盘坑 (2026-08 @bfyl 实测): 品牌 bot 的 bio/前端配置常引用 "vip bot" 号 (@lite105/@lite106/@lite109/@reddyisok)。这些通常解析为**人类账号 (bot=False) 人工代投**, 无 menu button 无 TMA, 不是可打的目标 — 只有主品牌 bot 有 WebApp URL。另外 @uppay 这类**钱包 bot** (bio 写"支持商户对接") 也可能无 menu button — 别在它们身上耗时间, 直接回到主 bot 的 TMA。
