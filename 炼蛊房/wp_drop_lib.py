"""WP / PHP 高熵马文件名判定（与情报文件名清单解耦）。

本批金标准：恰好 11 位 [A-Za-z0-9] 且大小写混用。
排除 formatting.php 等全小写核心文件。不把具体文件名当字典。
"""
from __future__ import annotations

import re
from urllib.parse import unquote, urlparse

DROP_NAME_RE = re.compile(r"^[A-Za-z0-9]{11}\.php$", re.I)
HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.I)
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)

# 授权站上要看列表的目录（短，可进 dirbrute）
WEB_DROP_DIRS = (
    "/",
    "/wp-includes/",
    "/wp-content/uploads/",
    "/wp-content/upgrade/",
    "/wp-content/plugins/",
    "/wp-content/themes/",
    "/wp-content/cache/",
)

# 主机 IR：相对 webroot，只扫一层
HOST_REL_DIRS = (
    "",
    "wp-includes",
    "wp-content/uploads",
    "wp-content/upgrade",
    "wp-content/plugins",
    "wp-content/themes",
    "wp-content/cache",
    "public_html",
    "public_html/wp-includes",
    "public_html/wp-content/uploads",
)


def is_campaign_drop_name(name: str) -> bool:
    """True = 本批/同类高熵马文件名，不是 WP 核心。"""
    base = (name or "").split("?")[0].rstrip("/").rsplit("/", 1)[-1]
    if not DROP_NAME_RE.match(base):
        return False
    stem = base[:-4]
    if len(stem) != 11:
        return False
    has_upper = any("A" <= c <= "Z" for c in stem)
    has_lower = any("a" <= c <= "z" for c in stem)
    return has_upper and has_lower


def extract_drop_hrefs(html: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for m in HREF_RE.finditer(html or ""):
        raw = unquote(m.group(1)).split("?")[0]
        name = raw.rstrip("/").rsplit("/", 1)[-1]
        if is_campaign_drop_name(name) and name not in seen:
            seen.add(name)
            found.append(name)
    return found


def _split_glued_urls(raw: str) -> list[str]:
    chunks = re.split(r"(?=https?://)", raw.strip())
    return [c.rstrip(").,;") for c in chunks if c.startswith("http")]


def parse_shell_url_dump(text: str) -> list[dict[str, str]]:
    """从「最新 shell 目录」类文本抽出 URL，粘连行 / .phpv 尾巴也能拆。"""
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in URL_RE.findall(text or ""):
        for piece in _split_glued_urls(raw):
            p = urlparse(piece)
            if not p.scheme or not p.netloc:
                continue
            path = p.path or "/"
            name = path.rstrip("/").rsplit("/", 1)[-1]
            if name.endswith(".phpv"):
                name = name[:-1]
                path = path[: path.rfind(".phpv")] + ".php"
            key = f"{p.scheme}://{p.netloc.lower()}{path}"
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "url": key,
                    "host": p.netloc.lower(),
                    "path": path,
                    "name": name,
                    "drop": "1" if is_campaign_drop_name(name) else "0",
                }
            )
    return rows


def dump_stats(rows: list[dict[str, str]]) -> dict:
    dirs: dict[str, int] = {}
    for r in rows:
        prefix = r["path"].rsplit("/", 1)[0] or "/"
        dirs[prefix] = dirs.get(prefix, 0) + 1
    return {
        "n": len(rows),
        "hosts": len({r["host"] for r in rows}),
        "drop_names": sum(1 for r in rows if r["drop"] == "1"),
        "dir_prefix": dict(sorted(dirs.items(), key=lambda x: -x[1])[:12]),
    }
