#!/usr/bin/env python3
"""大爱仙尊 39 模块分类目录生成。"""
from __future__ import annotations

import json
import re
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
PACK = ENGINE / "智道藏书" / "三十九门"
INDEX = PACK / "index.json"

# 模块 → 本库真源（Cursor skill / playbook / tool）
MODULE_MAP: dict[int, dict] = {
    1: {
        "status": "有",
        "ours": "Skill `棋道纵横` · `space_search.py` · `origin_recon` · `test_subdomain_enum` · `空间眼.md` · 九阶段 `recon-*`",
    },
    2: {
        "status": "有",
        "ours": "Skill `一日针匣` · `auto_campaign.py` · `nday_route.py` · `pentest-swarm`",
    },
    3: {
        "status": "有且更强",
        "ours": "假支付 / SQLi / XSS / 上传 / SSRF / 认证绕过均有专卡；Metasploit 上游全文在本模块 `skills/`",
    },
    4: {
        "status": "有",
        "ours": "`反客·总诀.md` · `linux_lpe_checker.py` · `windows_lpe_checker.py` · Skill `青丘`",
    },
    5: {
        "status": "有（知识卡已入库）",
        "ours": "`linux-post-exploit` · `ad_surface_check.py` · 本模块 `skills/`（凭证转储 / 远程控制 / 键盘记录知识卡）",
    },
    6: {
        "status": "有",
        "ours": "`纵横天下.md` · `宗门·认族.md` · Skill `内地道` · `ad_surface_check.py`",
    },
    7: {
        "status": "有（知识卡已入库）",
        "ours": "九阶段 `persistence-mechanisms` · 本模块 `skills/`（含 Bootkit 知识卡）",
    },
    8: {
        "status": "有（知识卡已入库）",
        "ours": "`隐鳞·手册.md`（WAF/流量）· 本模块 `skills/`（AMSI/EDR / 进程注入知识卡）",
    },
    9: {
        "status": "有",
        "ours": "案卷 `STATUS.md` / `FULL_REPORT.md` · Skill `春秋蝉`",
    },
    10: {
        "status": "有（Android 强 / iOS 弱）",
        "ours": "Skill `铁血冷·探路` · `apk-reverse` · `mobile-reverse` · `macos-reverse`",
    },
    11: {
        "status": "有知识",
        "ours": "Skill `无线` · `radio-sdr`；网站案默认降权",
    },
    12: {
        "status": "有",
        "ours": "Skill `文审` · `autocve-cve-hunt` · `文审.md`",
    },
    13: {
        "status": "有",
        "ours": "Skill `逆骨` · `ghidra-reverse` · `go-rust-reverse` · `binary-pwn` · `逆骨·认族.md`",
    },
    14: {
        "status": "部分",
        "ours": "等保/架构审计以本模块上游卡为准；云/容器审计交叉 17/33",
    },
    15: {
        "status": "有知识",
        "ours": "九阶段 `incident-response`",
    },
    16: {
        "status": "有",
        "ours": "`大灵.md` · `llm_surface_probe.py` · `灯笼·破印.md`",
    },
    17: {
        "status": "有（阿里云强）",
        "ours": "`云府·临钥.md` · Actuator 堆转云 · `定仙游·云骨.md`",
    },
    18: {
        "status": "部分",
        "ours": "TeamCity 杀伤链 · DeepAudit SAST；IaC/完整 SDLC 用本模块上游卡",
    },
    19: {
        "status": "补齐（原先缺专卡）",
        "ours": "Skill `工控` · 本模块上游全文；网站案默认降权",
    },
    20: {
        "status": "有知识",
        "ours": "九阶段 `web3-dev-services`",
    },
    21: {
        "status": "有知识",
        "ours": "Skill `固胚` · `hardware-security` · 固件/binwalk 网站案降权",
    },
    22: {
        "status": "补齐（原先缺专卡）",
        "ours": "本模块上游全文",
    },
    23: {
        "status": "有且更强",
        "ours": "Skill `tg-social-engage` · `social_engineer_agent.py` · 代理社工杀伤链",
    },
    24: {
        "status": "部分",
        "ours": "授权作业口径；BAS/紫队用本模块上游卡",
    },
    25: {
        "status": "有",
        "ours": "TeamCity · AutoCVE · 九阶段 `supply-chain-attacks`",
    },
    26: {
        "status": "有",
        "ours": "Skill `房睇长·日更` · `1day-nuclei-kit` · `房睇长·耳报.md`",
    },
    27: {
        "status": "部分",
        "ours": "Linux/Windows 提权卡；加固基线用本模块上游卡",
    },
    28: {
        "status": "补齐（原先缺专卡）",
        "ours": "本模块上游全文",
    },
    29: {
        "status": "有",
        "ours": "`cve-daily-intel` · `space_search.py` · cvebase",
    },
    30: {
        "status": "补齐（原先缺专卡）",
        "ours": "Skill `残忆` · `host-ir-check` · `case-review`",
    },
    31: {
        "status": "补齐（原先缺专卡）",
        "ours": "本模块上游全文",
    },
    32: {
        "status": "有",
        "ours": "`托印·越权.md` · `宗门·认族.md` · GVA/JWT 专卡",
    },
    33: {
        "status": "有",
        "ours": "`群瓮·特权.md` · `瓮中逃.md` · WolfStack / etcd",
    },
    34: {
        "status": "有且更强",
        "ours": "`万我·信门.md` · `李代桃僵·星念.md` · 芋道/Qzino 加密 API",
    },
    35: {
        "status": "部分",
        "ours": "JS/AES 签名专卡；PKI/TLS 基线用本模块上游卡",
    },
    36: {
        "status": "有",
        "ours": "`c2-zero-trust-console` · `c2_zt_probe.py` · `行器·敲门.md`",
    },
    37: {
        "status": "补齐（原先缺专卡）",
        "ours": "本模块上游全文",
    },
    38: {
        "status": "补齐（原先缺专卡）",
        "ours": "本模块上游全文",
    },
    39: {
        "status": "补齐（原先缺专卡）",
        "ours": "本模块上游全文",
    },
}

SENSITIVE = {
    "凭证转储与哈希传递",
    "键盘记录与屏幕捕获",
    "AMSI绕过与EDR规避",
    "Bootkit与固件持久化",
    "Metasploit框架利用",
    "钓鱼基础设施搭建",
    "进程注入与代码注入",
    "远程控制与交互式Shell",
}


def _rel_file(mod_path: str, filename: str) -> str:
    name = Path(filename).name
    nested = PACK / mod_path / "skills" / name
    if nested.is_file():
        return f"{mod_path}/skills/{name}"
    return f"{mod_path}/{name}"


def _load_ours() -> str:
    names: list[str] = []
    for root in (
        ENGINE / "杀招",
        ENGINE / "智道藏书" / "九转" / "skills",
        ENGINE / "智道藏书" / "旁支传承" / "skills",
        ENGINE / "传承",
    ):
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if p.suffix.lower() in {".md", ".mdc"} or p.name == "SKILL.md":
                names.append(p.stem.lower())
                names.append(p.parent.name.lower())
    return " ".join(names)


def _hit(name: str, blob: str) -> bool:
    keys = re.findall(r"[\u4e00-\u9fffA-Za-z0-9]{2,}", name)
    keys = [k.lower() for k in keys if k.lower() not in {"md", "与", "的", "和", "安全", "测试"}]
    return any(k in blob for k in keys[:4])


def build() -> dict:
    data = json.loads(INDEX.read_text(encoding="utf-8"))
    blob = _load_ours()
    rows: list[dict] = []
    for mod in data["modules"]:
        mid = int(mod["id"])
        meta = MODULE_MAP.get(mid, {"status": "对照中", "ours": "见本模块上游卡"})
        for i, sk in enumerate(mod["skills"], 1):
            nm = sk["name"]
            have = _hit(nm, blob) or _hit(nm, meta["ours"].lower())
            rows.append(
                {
                    "id": f"{mid:02d}-{i:03d}",
                    "module": mid,
                    "module_cn": mod["name_cn"],
                    "name": nm,
                    "file": _rel_file(mod["path"], sk["file"]),
                    "have": have,
                    "sensitive": nm in SENSITIVE,
                    "module_status": meta["status"],
                    "ours": meta["ours"],
                }
            )
    return {"meta": data["meta"], "modules": data["modules"], "rows": rows}


def write_catalog(pack: dict) -> None:
    lines = [
        "# 大爱仙尊 39 模块分类目录",
        "",
        "> 39 模块 / 195 技能  ",
        "> 本目录：`智道藏书/三十九门/`  ",
        "> 业务专链（假支付 / 芋道 / TG 号库）仍优先 `杀招/`，本包是**分类知识层**。  ",
        "> 查询：`python3 炼蛊房/css_query.py search --keyword 凭证` · `get --id 05-002`",
        "",
        "## 模块对照",
        "",
        "| # | 模块 | 本库 | 作业入口 |",
        "|---|------|------|----------|",
    ]
    seen = set()
    for r in pack["rows"]:
        if r["module"] in seen:
            continue
        seen.add(r["module"])
        lines.append(f"| {r['module']:02d} | {r['module_cn']} | {r['module_status']} | {r['ours']} |")
    lines += [
        "",
        "## 00 大爱仙尊业务（上游没有、本库更强）",
        "",
        "| 主题 | 走 |",
        "|------|-----|",
        "| 假支付 / 彩虹易支付 / USDT 归属 | `payment-callback-forgery` |",
        "| 白标盘口 / 芋道 TMA / Qzino | `gambling-family-router` · `yudao-appapi-pentest` |",
        "| TG 云控 / Fernet / 号库 / 社工 | `tg-cloud-panel` · `tg-account-library` · `tg-social-engage` |",
        "| Spring Actuator / Gateway | `spring-actuator-cloud-takeover` |",
        "| GVA / 发卡 / PocketBase | 对应专用 Skill |",
        "",
        "## 195 张逐条",
        "",
        "| ID | 技能 | 本库 | 文件 |",
        "|----|------|------|------|",
    ]
    for r in pack["rows"]:
        hit = "专卡" if r["have"] else "知识卡"
        lines.append(f"| {r['id']} | {r['name']} | {hit} | `{r['file']}` |")
    (PACK / "CATALOG.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # 每模块 MODULE.md
    by_mod: dict[int, list] = {}
    for r in pack["rows"]:
        by_mod.setdefault(r["module"], []).append(r)
    for mid, items in by_mod.items():
        path = PACK / items[0]["file"].split("/")[0]
        md = [
            f"# {mid:02d} {items[0]['module_cn']}",
            "",
            f"**本库状态**：{items[0]['module_status']}  ",
            f"**作业入口**：{items[0]['ours']}",
            "",
            "| ID | 技能 | 上游全文 |",
            "|----|------|----------|",
        ]
        for it in items:
            md.append(f"| {it['id']} | {it['name']} | `{Path(it['file']).name}` |")
        md += ["", "查全表：[`CATALOG.md`](../CATALOG.md)"]
        (path / "MODULE.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def main() -> None:
    pack = build()
    write_catalog(pack)
    n = len(pack["rows"])
    have = sum(1 for r in pack["rows"] if r["have"])
    print(json.dumps({"skills": n, "name_hit": have, "modules": 39, "out": str(PACK / "CATALOG.md")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
