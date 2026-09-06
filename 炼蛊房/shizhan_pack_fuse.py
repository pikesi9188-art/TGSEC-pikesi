#!/usr/bin/env python3
"""把 shizhan-pack 融进 杀招/。

专卡赢（不覆盖正文）。别名变 stub。缺口落全文卡 + 三件套。
免杀/马/证件伪造只做 stub。
"""
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from shizhan_pack_route import (  # noqa: E402
    PACK,
    PROMOTE,
    ROOT,
    SKIP_PROMOTE,
    TO_OURS,
)

SKILLS = ROOT / "杀招"
MARK = ""
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$")
EMBED_MAX = 1800

DEFAULT_KIT = (
    "传承/薄青·岁岁索命.md",
    "炼蛊房/core_web_surface_probe.py",
)

# 短段必须按 hyphen token 匹配，禁止子串误伤：
# iam⊂authentication · aws⊂flaws · el-⊂panel/laravel/kernel · ad-⊂upload-
KIT_RULES: list[tuple[str, tuple[str, str]]] = [
    ("ad-|kerberos|ntlm|windows-lateral|windows-privilege", (
        "传承/宗门·认族.md", "炼蛊房/ad_surface_check.py")),
    ("linux-|container|kubernetes|k8s", (
        "传承/反客为主.md", "炼蛊房/linux_lpe_checker.py")),
    ("cloud|aws|iam|metadata", (
        "传承/定仙游·云骨.md", "炼蛊房/ssrf_probe.py")),
    ("api-|graphql|bola|idor", (
        "传承/万我·信门.md", "炼蛊房/core_web_surface_probe.py")),
    ("jwt|oauth|saml|oidc|auth|password-attack|credential-access", (
        "传承/黑楼兰·硬撼.md", "炼蛊房/auth_brute_probe.py")),
    ("xss|csp|clickjack|dangling-markup", (
        "传承/薄青·岁岁索命.md", "炼蛊房/core_web_surface_probe.py")),
    ("sql|ldap|xpath|xslt|nosql", (
        "传承/薄青·岁岁索命.md", "炼蛊房/core_web_surface_probe.py")),
    ("ssrf|xxe", (
        "传承/薄青·岁岁索命.md", "炼蛊房/ssrf_probe.py")),
    ("upload|file-|lfi|path-traversal|webshell", (
        "传承/薄青·岁岁索命.md", "炼蛊房/core_web_surface_probe.py")),
    ("waf|ghost-bits|evasion", (
        "传承/隐鳞·手册.md", "炼蛊房/waf_detect.py")),
    ("java|jndi|deserial|el-|spel|ognl", (
        "传承/凤九歌·天地歌.md", "炼蛊房/java_web_surface_probe.py")),
    ("php|type-juggling|zend", (
        "传承/薄青·岁岁索命.md", "炼蛊房/core_web_surface_probe.py")),
    ("pay|faka|dujiao|rainbow|e-commerce|business-logic", (
        "传承/秦百胜·假契.md", "炼蛊房/pay_matrix.py")),
    ("telegram|tg-|tma|mini-app", (
        "传承/乐土·人情.md", "炼蛊房/tg_cloud_panel_probe.py")),
    ("android|apk|ios|mobile|frida", (
        "传承/安器·探路.md", "炼蛊房/apk_recon.py")),
    ("reverse|vm-|bytecode|obfus|symbolic|pwn|heap|kernel|stack-|rop|binary", (
        "传承/逆骨·认族.md", "炼蛊房/reverse_skill_route.py")),
    ("crypto|rsa|hash|lattice|cipher|steganograph", (
        "传承/使证闸.md", "炼蛊房/crypto_decode.py")),
    ("forensic|volatility|incident|malware|traffic|pcap", (
        "传承/自我守护.md", "炼蛊房/host_ir_check.py")),
    ("recon|fofa|subdomain|cdn|osint", (
        "传承/空间眼.md", "炼蛊房/origin_recon.py")),
    ("adcs|kerberos", (
        "传承/宗门·认族.md", "炼蛊房/ad_surface_check.py")),
    ("llm|ai-|prompt", (
        "传承/大灵.md", "炼蛊房/llm_surface_probe.py")),
    ("wifi|wireless|iot|radio", (
        "传承/春秋蝉·分案.md", "炼蛊房/css_query.py")),
    ("wordpress|wp-", (
        "传承/坞壳落子猎.md", "炼蛊房/wp_plugin_unauth_probe.py")),
    ("fastadmin|shop_hq", (
        "传承/快府·横夺.md",
        "炼蛊房/fastadmin_shop_tenant_probe.py")),
    ("yudao", (
        "传承/芋府·微域.md", "炼蛊房/yudao_appapi_probe.py")),
    ("macos", (
        "传承/逆骨·认族.md", "炼蛊房/reverse_skill_route.py")),
    ("ctf|hack", (
        "传承/逆骨·认族.md", "炼蛊房/reverse_skill_route.py")),
    ("pentest|redteam|web-pentest|injection-agent|api-agent|auth-agent|file-agent|business-agent|misc-agent|poc-agent|vuln-", (
        "传承/春秋蝉·分案.md", "炼蛊房/kit_run.py")),
]


_AUTH_TOKENS = {
    "auth",
    "authbypass",
    "authentication",
    "unauthenticated",
    "unauthorized",
}
_TOKEN_ONLY = {"iam", "java", "aws", "cloud"}


def _part_hit(part: str, name: str, toks: set[str]) -> bool:
    if part.endswith("-"):
        return part[:-1] in toks
    if part in _TOKEN_ONLY:
        return part in toks
    if part == "auth":
        return bool(toks & _AUTH_TOKENS)
    return re.search(part, name) is not None


def _rule_hit(pat: str, name: str) -> bool:
    toks = set(name.split("-"))
    return any(_part_hit(p, name, toks) for p in pat.split("|"))


def _kit(name: str) -> tuple[str, str]:
    if name in PROMOTE:
        return PROMOTE[name]
    for pat, kit in KIT_RULES:
        if _rule_hit(pat, name):
            return kit
    return DEFAULT_KIT


def _kit_selfcheck() -> None:
    cases = {
        "authbypass-authentication-flaws": "黑楼兰·硬撼.md",
        "file-upload-testing": "薄青·岁岁索命.md",
        "kernel-exploitation": "逆骨·认族.md",
        "api-authorization-and-bola": "万我·信门.md",
        "cloud-security-audit": "定仙游·云骨.md",
        "jndi-injection": "凤九歌·天地歌.md",
        "android-rat-panel-pentest": "安器·探路.md",
        "ntlm-relay-coercion": "宗门·认族.md",
        "password-attacks-credential-access": "黑楼兰·硬撼.md",
    }
    bad = []
    for slug, expect in cases.items():
        got = _kit(slug)[0].rsplit("/", 1)[-1]
        if got != expect:
            bad.append(f"{slug}: {got} != {expect}")
    if bad:
        raise SystemExit("kit selfcheck fail:\n  " + "\n  ".join(bad))


def rekit_fused() -> int:
    """只改融合全文卡的手法/工具两行，不碰专卡正文。"""
    n = 0
    for dest in sorted(SKILLS.iterdir()):
        md = dest / "SKILL.md"
        if not md.is_file():
            continue
        text = md.read_text(encoding="utf-8", errors="replace")
        if "智道藏书/旁支传承" not in text:
            continue
        if "（大爱仙尊）" not in text[:800]:
            continue
        pb, tool = _kit(dest.name)
        new, c1 = re.subn(r"(手法：`)[^`]+(`)", rf"\1{pb}\2", text, count=1)
        new, c2 = re.subn(
            r"(工具：`python3 )[^\s`]+",
            rf"\1{tool}",
            new,
            count=1,
        )
        if c1 and c2 and new != text:
            md.write_text(new, encoding="utf-8")
            n += 1
    return n


def _split_fm(text: str) -> tuple[str, str]:
    m = re.match(r"^\s*---\s*\n(.*?)\n---\s*\n?(.*)", text, re.DOTALL)
    if not m:
        return "", text
    return m.group(1), m.group(2)


def _fm_field(fm: str, key: str) -> str:
    m = re.search(
        rf"(?ms)^{re.escape(key)}:\s*([|>][-+]?)\s*\n((?:[ \t]+.*\n?)*)",
        fm,
    )
    if m:
        return " ".join(ln.strip() for ln in m.group(2).splitlines() if ln.strip())
    m = re.search(rf"(?m)^{re.escape(key)}:\s*(.+?)\s*$", fm)
    return (m.group(1).strip().strip("'\"") if m else "")


def _is_biz_card(md: Path) -> bool:
    if not md.is_file():
        return False
    head = md.read_text(encoding="utf-8", errors="replace")[:4000]
    if "pack: survey-skill" in head or "owned: true" in head:
        return False
    if "shizhan-pack" in head or (MARK and MARK in head) or "长文：" in head:
        return False
    return True


def _slugs() -> dict[str, Path]:
    """leaf or path-slug → incoming SKILL.md"""
    mds = sorted(PACK.rglob("SKILL.md"))
    leaves: dict[str, list[Path]] = {}
    for md in mds:
        rel = md.parent.relative_to(PACK)
        leaves.setdefault(rel.parts[-1], []).append(md)
    out: dict[str, Path] = {}
    for md in mds:
        rel = md.parent.relative_to(PACK)
        leaf = rel.parts[-1]
        if len(leaves[leaf]) == 1 and NAME_RE.match(leaf):
            slug = leaf
        else:
            slug = "-".join(rel.parts)
            slug = re.sub(r"[^a-z0-9-]+", "-", slug.lower()).strip("-")
            if not NAME_RE.match(slug):
                slug = (slug + "-x")[:64]
        # 同 slug 后写覆盖：嵌套优先保留更长路径已处理
        if slug not in out:
            out[slug] = md
    return out


def _copy_sidecars(src_dir: Path, dest: Path) -> int:
    n = 0
    skip = {"SKILL.md", ".DS_Store"}
    for p in src_dir.rglob("*"):
        if not p.is_file() or p.name in skip:
            continue
        rel = p.relative_to(src_dir)
        if any(part.startswith(".") for part in rel.parts):
            continue
        tgt = dest / rel
        tgt.parent.mkdir(parents=True, exist_ok=True)
        if not tgt.exists():
            shutil.copy2(p, tgt)
            n += 1
    return n


def _append_ref(md: Path, pack_rel: str) -> bool:
    text = md.read_text(encoding="utf-8", errors="replace")
    line = f"- 长文：`{pack_rel}`"
    if pack_rel in text:
        return False
    if "## 真源" in text:
        text = text.rstrip() + "\n" + line + "\n"
    else:
        text = text.rstrip() + f"\n\n## 真源\n\n{line}\n"
    md.write_text(text, encoding="utf-8")
    return True


def _stub(slug: str, dest: Path, target: str, pack_rel: str) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "SKILL.md").write_text(
        f"---\n"
        f"name: {slug}\n"
        f"description: >-\n"
        f"  本卡仅重定向。已并入 `{target}`。立刻改读本库专卡。\n"
        f"---\n\n"
        f"# {slug}\n\n"
        f"本卡仅重定向。已并入 `{target}`。立刻改读 Skill `{target}`。\n\n"
        f"长文：`{pack_rel}`\n"
        f"`python3 炼蛊房/shizhan_pack_route.py --name {slug}`\n",
        encoding="utf-8",
    )


def _full_card(slug: str, dest: Path, src_md: Path, pack_rel: str) -> None:
    raw = src_md.read_text(encoding="utf-8", errors="replace")
    fm, body = _split_fm(raw)
    desc = _fm_field(fm, "description") or slug
    desc = re.sub(r"\s+", " ", desc).strip()
    if not desc.startswith("大爱仙尊"):
        desc = f"大爱仙尊·{desc}"
    if len(desc) > 480:
        desc = desc[:477] + "…"
    wrapped = "\n".join("  " + desc[i : i + 88] for i in range(0, len(desc), 88))
    pb, tool = _kit(slug)
    dest.mkdir(parents=True, exist_ok=True)
    lines = body.splitlines()
    if len(lines) > EMBED_MAX:
        body_out = (
            f"长文超过 {EMBED_MAX} 行，作业时 Read 真源全文，不要凭记忆。\n\n"
            + "\n".join(lines[:80])
            + "\n\n…（其余见长文）\n"
        )
    else:
        body_out = body.lstrip()
    text = (
        f"---\n"
        f"name: {slug}\n"
        f"description: >-\n{wrapped}\n"
        f"---\n\n"
        f"# {slug}（大爱仙尊）\n\n"
        f"目标须在 `授权范围`。本库已有专链时专卡赢。\n\n"
        f"## 真源\n\n"
        f"- 长文：`{pack_rel}`\n"
        f"- 手法：`{pb}`\n"
        f"- 工具：`python3 {tool} --help`\n"
        f"- 路由：`python3 炼蛊房/shizhan_pack_route.py --name {slug}`\n\n"
        f"---\n\n"
        f"{body_out.rstrip()}\n"
    )
    (dest / "SKILL.md").write_text(text, encoding="utf-8")
    _copy_sidecars(src_md.parent, dest)


def fuse() -> dict[str, int]:
    stats = {
        "incoming": 0,
        "hook_biz": 0,
        "stub": 0,
        "full": 0,
        "skip_exist": 0,
    }
    mapping = _slugs()
    stats["incoming"] = len(mapping)
    for slug, src_md in sorted(mapping.items()):
        rel = src_md.parent.relative_to(PACK)
        leaf = rel.parts[-1]
        pack_rel = str(src_md.relative_to(ROOT))
        dest = SKILLS / slug
        dest_md = dest / "SKILL.md"
        ours = TO_OURS.get(leaf) or TO_OURS.get(slug, "")

        if leaf in SKIP_PROMOTE or slug in SKIP_PROMOTE:
            target = ours or "edr-bypass-re"
            _stub(slug, dest, target, pack_rel)
            stats["stub"] += 1
            continue

        if dest_md.is_file() and _is_biz_card(dest_md):
            if _append_ref(dest_md, pack_rel):
                stats["hook_biz"] += 1
            else:
                stats["skip_exist"] += 1
            extra = dest / "references" / "shizhan-pack"
            extra.mkdir(parents=True, exist_ok=True)
            _copy_sidecars(src_md.parent, extra)
            continue

        if ours and ours != slug and (SKILLS / ours / "SKILL.md").is_file():
            _stub(slug, dest, ours, pack_rel)
            stats["stub"] += 1
            continue

        _full_card(slug, dest, src_md, pack_rel)
        stats["full"] += 1
    return stats


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="把 shizhan-pack 融进技能目录（须显式 fuse）")
    ap.add_argument("cmd", nargs="?", choices=("fuse", "rekit"))
    args = ap.parse_args()
    if args.cmd is None:
        ap.print_help()
        return 0
    _kit_selfcheck()
    if args.cmd == "rekit":
        n = rekit_fused()
        print(f"rekit fused={n}")
        return 0
    st = fuse()
    print(
        "fuse incoming={incoming} hook_biz={hook_biz} "
        "stub={stub} full={full} skip={skip_exist}".format(**st)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
