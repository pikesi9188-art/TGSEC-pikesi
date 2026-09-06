#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cdn_tracer.py — CDN/WAF 真实 IP 溯源主入口 (v5.0)
================================================================
源自 SKILL.md §9「核心原则与分层流水线」+ §12「贝叶斯加权置信度评分」。

10 阶段全自动溯源流水线:
    阶段 1  识别 CDN    — DNS 解析 + HTTP 响应头指纹, 判断是否套 CDN
    阶段 2  证书透明度  — crt.sh 查询 CT 日志, 提取证书关联 IP/子域
    阶段 3  子域名枚举  — crt.sh + 常见子域 + 被动源, 解析非 CDN 子域
    阶段 4  被动 DNS    — 历史 A 记录聚合 (AlienVault OTX / HackerTarget / urlscan)
    阶段 5  邮件记录    — SPF/MX/TXT 中泄露的源站 IP
    阶段 6  CDN 过滤    — cdn_ranges.filter_candidates 剔除所有 CDN IP
    阶段 7  Host 验证   — 直连候选 IP + Host 头, 检查 200/内容相似
    阶段 8  TLS 指纹    — ja3extract 对比 CDN 节点 vs 候选源站 JA3S/JA4S/证书
    阶段 9  页面哈希    — 清洗后 body SHA256 对比 (去动态内容)
    阶段 10 贝叶斯评分  — 6 维 LLR 加权, 输出置信度排名表 + JSON 报告

用法:
    python cdn_tracer.py target.com
    python cdn_tracer.py target.com --threads 30
    python cdn_tracer.py target.com -o result.json
    python cdn_tracer.py target.com --no-verify         # 仅被动发现(不直连,隐蔽)
    python cdn_tracer.py target.com --no-fingerprint     # 跳过TLS/哈希(加速)

输出:
    - 终端彩色排名表 (Top N 候选源站 IP + 置信度 + 证据)
    - JSON 报告 report_<domain>_<timestamp>.json (或 -o 指定路径)

依赖:
    - requests
    - 标准库: socket / json / re / hashlib / subprocess / concurrent.futures / argparse
    - 复用 cdn_ranges.py (CDN IP 过滤)
    - 复用 ja3extract.py  (TLS 指纹对比)
    - 可选: openssl (证书指纹)
"""
import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests

# ======================================================================
# 复用同目录模块
# ======================================================================
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

try:
    from cdn_ranges import is_cdn, get_vendor, filter_candidates  # type: ignore
except ImportError:  # pragma: no cover
    print("[警告] 无法导入 cdn_ranges.py, CDN 过滤将不可用", file=sys.stderr)
    is_cdn = lambda ip: False  # type: ignore
    get_vendor = lambda ip: None  # type: ignore
    filter_candidates = lambda ips: list(ips)  # type: ignore

try:
    from ja3extract import (  # type: ignore
        extract_server_fingerprint,
        compare_fingerprints,
        extract_cert_fingerprint,
    )
except ImportError:  # pragma: no cover
    print("[警告] 无法导入 ja3extract.py, TLS 指纹验证将跳过", file=sys.stderr)
    extract_server_fingerprint = None  # type: ignore
    compare_fingerprints = None  # type: ignore
    extract_cert_fingerprint = None  # type: ignore


# ======================================================================
# 配置常量
# ======================================================================
VERSION = "5.0"
USER_AGENT = "Mozilla/5.0 (cdn_tracer/5.0)"
DEFAULT_TIMEOUT = 12
DEFAULT_THREADS = 30

# 多 DNS 解析器交叉验证 (P0-5 方法 #20)
PUBLIC_RESOLVERS = [
    ("8.8.8.8", "Google"),
    ("1.1.1.1", "Cloudflare"),
    ("9.9.9.9", "Quad9"),
    ("208.67.222.222", "OpenDNS"),
    ("114.114.114.114", "114DNS"),
    ("223.5.5.5", "AliDNS"),
    ("119.29.29.29", "DNSPod"),
    ("8.8.4.4", "Google-2"),
]

# HTTP 响应头中的 CDN 指纹特征 (与 cdn_origin_monitor 同步)
CDN_HEADER_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-amz-cf-pop": "Amazon CloudFront",
    "x-served-by": "Fastly",
    "x-azure-ref": "Azure Front Door",
    "x-cdn": "Imperva Incapsula",
    "x-iinfo": "Imperva Incapsula",
    "x-sucuri-id": "Sucuri",
    "x-bunnycdn": "BunnyCDN",
    "x-qiniu": "七牛云",
    "x-upyun": "又拍云",
    "x-akamai": "Akamai",
    "x-nws-log-uuid": "腾讯云 CDN",
    "x-hw": "华为云 CDN",
    "x-volc": "火山引擎 CDN",
}

# 常见可能直连源站的子域名 (绕过 CDN)
COMMON_SUBDOMAINS = [
    "www", "mail", "smtp", "pop", "imap", "webmail", "mx", "email",
    "direct", "origin", "backend", "real", "true", "raw", "ip",
    "cpanel", "whm", "admin", "panel", "manage", "console",
    "dev", "develop", "development", "test", "testing", "stage",
    "staging", "beta", "alpha", "qa", "sandbox", "demo",
    "api", "app", "m", "mobile", "wap", "h5",
    "ftp", "sftp", "ssh", "vpn", "remote",
    "ns1", "ns2", "dns", "ns", "dns1", "dns2",
    "upload", "download", "file", "files", "static", "assets",
    "blog", "forum", "bbs", "shop", "store", "pay",
    "cdn", "cache", "proxy", "gateway", "lb", "loadbalancer",
    "db", "database", "redis", "mysql", "mongo",
    "git", "svn", "jenkins", "ci", "cd", "gitlab", "jira",
    "monitor", "grafana", "prometheus", "status", "health",
    "internal", "intranet", "local", "lan", "office", "corp",
    "old", "new", "v1", "v2", "backup", "bak", "temp",
]

# 被动 DNS / 子域源 (免费, 无需 API Key)
PASSIVE_DNS_SOURCES = [
    # (名称, URL 模板, 解析函数标识)
    "otx",        # AlienVault OTX (免费无 key)
    "hackertarget",  # HackerTarget hostsearch (免费限速)
    "urlscan",    # urlscan.io (免费有限)
    "rapiddns",   # rapiddns.io (免费)
    "threatminer",  # ThreatMiner (免费)
    "anubis",     # Anubis-DB (免费)
]

# ======================================================================
# 贝叶斯评分常量 (SKILL.md §12.1)
# ======================================================================
LLR = {
    "A_cert":         {"hit": +2.5, "miss": -1.0},  # 证书透明度
    "B_dns_history":  {"hit": +2.0, "miss": -0.8},  # 历史 DNS
    "C_subdomain":    {"hit": +1.8, "miss": -0.5},  # 子域名关联
    "D_mail":         {"hit": +1.5, "miss": -0.3},  # 邮件头/SPF/MX
    "E_fingerprint":  {"hit": +3.0, "miss": -1.5},  # TLS/HTTP2 指纹
    "F_space_engine": {"hit": +2.0, "miss": -0.7},  # 网络空间引擎
}
PRIOR_LOGIT = -2.0  # 先验: 任意 IP 是源站的概率约 12%

# 判定阈值
THRESHOLD_CONFIRM = 0.95   # 几乎确定源站
THRESHOLD_HIGH = 0.80      # 高度疑似
THRESHOLD_SUSPECT = 0.50   # 可疑


# ======================================================================
# 彩色输出
# ======================================================================
class Color:
    """ANSI 终端彩色 (兼容 Windows 10+)"""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"

    @staticmethod
    def enable():
        """启用 Windows 终端彩色 (Linux/macOS 默认支持)"""
        if sys.platform == "win32":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except Exception:
                pass


def _c(text: str, color: str) -> str:
    """给文本上色"""
    return f"{color}{text}{Color.RESET}"


def _stage_header(idx: int, title: str) -> None:
    """打印阶段标题"""
    bar = "=" * 64
    print(f"\n{_c(bar, Color.CYAN)}")
    print(_c(f"  阶段 {idx:>2}  {title}", Color.BOLD + Color.CYAN))
    print(_c(bar, Color.CYAN))


def _ok(msg: str) -> None:
    print(f"  {_c('[+]', Color.GREEN)} {msg}")


def _warn(msg: str) -> None:
    print(f"  {_c('[!]', Color.YELLOW)} {msg}")


def _fail(msg: str) -> None:
    print(f"  {_c('[-]', Color.RED)} {msg}")


def _info(msg: str) -> None:
    print(f"  {_c('[*]', Color.GRAY)} {msg}")


# ======================================================================
# 通用辅助函数
# ======================================================================
def _root_domain(domain: str) -> str:
    """从子域名提取根域名 (简化版: 取最后两段, 处理常见双段 TLD)"""
    parts = domain.strip(".").split(".")
    if len(parts) <= 2:
        return domain.strip(".")
    # 常见双段 TLD
    double_tld = {
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
        "co.jp", "co.kr", "co.uk", "co.in", "com.au", "com.tw",
        "com.hk", "com.sg", "com.br", "com.mx", "com.tr",
    }
    last_two = ".".join(parts[-2:])
    if last_two in double_tld and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def _is_ip(s: str) -> bool:
    """判断字符串是否为合法 IPv4/IPv6"""
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except OSError:
        pass
    return False


def _resolve_dns(domain: str, record_type: str = "A",
                 resolver: Optional[str] = None) -> List[str]:
    """通过指定 DNS 解析器解析域名, 返回 IP 列表

    使用 socket + 自定义 DNS 服务器 (通过 dnspython 不可用时回退到系统解析)
    record_type: 'A' / 'AAAA' / 'CNAME' / 'MX' / 'TXT' / 'NS'
    """
    results: List[str] = []

    if record_type in ("A", "AAAA"):
        # 直接用系统解析 (getaddrinfo 支持指定解析器仅在新版 Python)
        try:
            family = socket.AF_INET if record_type == "A" else socket.AF_INET6
            infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
            for info in infos:
                ip = info[4][0]
                if ip not in results:
                    results.append(ip)
        except socket.gaierror:
            pass

    # 用 nslookup/dig 做指定解析器查询 (更可靠)
    if resolver:
        try:
            if _have_tool("dig"):
                cmd = ["dig", "+short", resolver and f"@{resolver}" or "",
                       domain, record_type]
                cmd = [c for c in cmd if c]
                out = subprocess.run(cmd, capture_output=True, timeout=8)
                for line in out.stdout.decode(errors="ignore").splitlines():
                    line = line.strip().rstrip(".")
                    if line and line not in results:
                        results.append(line)
            elif _have_tool("nslookup"):
                cmd = ["nslookup", "-type=" + record_type, domain, resolver]
                out = subprocess.run(cmd, capture_output=True, timeout=8)
                text = out.stdout.decode(errors="ignore")
                for line in text.splitlines():
                    line = line.strip()
                    # A 记录: "Address: 1.2.3.4"
                    if record_type == "A" and "Address" in line:
                        ip = line.split("Address:")[-1].strip()
                        if _is_ip(ip) and ip != resolver and ip not in results:
                            results.append(ip)
        except Exception:
            pass

    return results


def _have_tool(name: str) -> bool:
    """检查系统是否安装了某命令行工具"""
    from shutil import which
    return which(name) is not None


def _query_dns_records(domain: str, record_type: str,
                       resolvers: Optional[List[str]] = None) -> List[str]:
    """跨多个公共 DNS 解析器查询, 合并去重

    record_type: 'A' / 'AAAA' / 'MX' / 'TXT' / 'NS' / 'CNAME'
    返回去重后的记录列表 (MX/TXT 返回原始文本)
    """
    all_records: List[str] = []
    resolvers = resolvers or [r[0] for r in PUBLIC_RESOLVERS]

    for resolver in resolvers:
        try:
            if _have_tool("dig"):
                cmd = ["dig", "+short", f"@{resolver}", domain, record_type]
                out = subprocess.run(cmd, capture_output=True, timeout=6)
                for line in out.stdout.decode(errors="ignore").splitlines():
                    line = line.strip().rstrip(".")
                    if line and line not in all_records:
                        all_records.append(line)
        except Exception:
            continue

    # 系统解析兜底
    if not all_records and record_type == "A":
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_INET,
                                       socket.SOCK_STREAM)
            for info in infos:
                ip = info[4][0]
                if ip not in all_records:
                    all_records.append(ip)
        except socket.gaierror:
            pass

    return all_records


def _http_get(url: str, headers: Optional[Dict] = None,
              timeout: int = DEFAULT_TIMEOUT,
              verify: bool = False) -> Optional[requests.Response]:
    """安全 HTTP GET, 失败返回 None"""
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    try:
        return requests.get(url, headers=hdrs, timeout=timeout,
                            verify=verify, allow_redirects=True)
    except Exception:
        return None


def _http_get_ip(ip: str, host: str, port: int = 80,
                 use_https: bool = False,
                 timeout: int = DEFAULT_TIMEOUT) -> Optional[requests.Response]:
    """直连 IP + 伪造 Host 头发起请求"""
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{ip}:{port}/"
    headers = {"Host": host, "User-Agent": USER_AGENT}
    try:
        return requests.get(url, headers=headers, timeout=timeout,
                            verify=False, allow_redirects=False)
    except Exception:
        return None


def _clean_body(body: bytes) -> bytes:
    """清洗 HTML body, 去除动态内容后返回 (用于哈希对比)

    清洗规则:
      - 去除所有 <script>...</script>
      - 去除所有 <style>...</style>
      - 去除 HTML 注释 <!--...-->
      - 去除 CSRF token / nonce / 时间戳类属性
      - 压缩连续空白
    """
    text = body.decode("utf-8", errors="ignore")
    # 去 script/style/注释
    text = re.sub(r"<script[\s\S]*?</script>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"<style[\s\S]*?</style>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"<!--[\s\S]*?-->", "", text)
    # 去 nonce/csrf/timestamp 属性值
    text = re.sub(r'(nonce|csrf|token|timestamp|_t|v)["\']?\s*[:=]\s*["\']?[^"\'\s>]+',
                  "", text, flags=re.IGNORECASE)
    # 压缩空白
    text = re.sub(r"\s+", " ", text).strip()
    return text.encode("utf-8")


def _body_hash(body: bytes) -> str:
    """计算清洗后 body 的 SHA256"""
    return hashlib.sha256(_clean_body(body)).hexdigest()


def _extract_ips_from_spf(txt_records: List[str]) -> List[str]:
    """从 SPF (v=spf1) 记录中提取 IP"""
    ips: List[str] = []
    for txt in txt_records:
        if not txt:
            continue
        # TXT 记录可能带引号
        txt = txt.strip('"').strip("'")
        if "v=spf1" not in txt.lower():
            continue
        # ip4:x.x.x.x  /  ip4:x.x.x.x/cidr  /  ip6:...  /  a  /  mx  /  include
        for m in re.finditer(r"ip4:([0-9./]+)", txt, re.IGNORECASE):
            ip = m.group(1).split("/")[0]
            if _is_ip(ip) and ip not in ips:
                ips.append(ip)
        for m in re.finditer(r"ip6:([0-9a-fA-F:./]+)", txt, re.IGNORECASE):
            ip = m.group(1).split("/")[0]
            if _is_ip(ip) and ip not in ips:
                ips.append(ip)
        # include:xxx.com → 递归查 SPF (此处仅记录域名供后续)
    return ips


def _extract_domains_from_spf(txt_records: List[str]) -> List[str]:
    """从 SPF include 指令提取关联域名"""
    domains: List[str] = []
    for txt in txt_records:
        if not txt:
            continue
        txt = txt.strip('"').strip("'")
        for m in re.finditer(r"include:([^\s]+)", txt, re.IGNORECASE):
            d = m.group(1).rstrip(".")
            if d not in domains:
                domains.append(d)
    return domains


# ======================================================================
# 贝叶斯评分 (SKILL.md §12.2)
# ======================================================================
def bayesian_score(evidence: Dict[str, bool]) -> Tuple[float, List[str]]:
    """贝叶斯置信度评分

    参数:
        evidence: 6 维证据命中情况
            {
                'A_cert': bool,          # 证书透明度
                'B_dns_history': bool,    # 历史 DNS
                'C_subdomain': bool,      # 子域名关联
                'D_mail': bool,           # 邮件头/SPF/MX
                'E_fingerprint': bool,    # TLS/HTTP2 指纹
                'F_space_engine': bool,   # 网络空间引擎
            }

    返回:
        (概率 0~1, 证据详情列表)
    """
    logit = PRIOR_LOGIT  # 先验概率
    details: List[str] = []
    for dim, llr in LLR.items():
        hit = evidence.get(dim, False)
        delta = llr["hit"] if hit else llr["miss"]
        logit += delta
        flag = _c("HIT", Color.GREEN) if hit else _c("miss", Color.GRAY)
        details.append(f"{dim}: {flag} ({delta:+.1f})")
    # logit 转概率 (sigmoid)
    prob = 1.0 / (1.0 + math.exp(-logit))
    return prob, details


def _verdict(prob: float) -> str:
    """根据概率返回判定标签"""
    if prob >= THRESHOLD_CONFIRM:
        return _c("几乎确定源站", Color.GREEN + Color.BOLD)
    elif prob >= THRESHOLD_HIGH:
        return _c("高度疑似源站", Color.YELLOW)
    elif prob >= THRESHOLD_SUSPECT:
        return _c("可疑", Color.MAGENTA)
    else:
        return _c("排除", Color.GRAY)


def _verdict_plain(prob: float) -> str:
    """纯文本判定 (用于 JSON)"""
    if prob >= THRESHOLD_CONFIRM:
        return "几乎确定源站"
    elif prob >= THRESHOLD_HIGH:
        return "高度疑似源站"
    elif prob >= THRESHOLD_SUSPECT:
        return "可疑"
    else:
        return "排除"


# ======================================================================
# 10 阶段溯源主类
# ======================================================================
class CdnTracer:
    """CDN 真实 IP 溯源引擎 (10 阶段流水线)

    用法:
        tracer = CdnTracer("target.com", threads=30)
        report = tracer.run()
    """

    def __init__(self, target: str, threads: int = DEFAULT_THREADS,
                 verify: bool = True, fingerprint: bool = True,
                 timeout: int = DEFAULT_TIMEOUT):
        # 标准化目标域名
        self.target = target.strip().lower()
        self.target = re.sub(r"^https?://", "", self.target)
        self.target = self.target.split("/")[0].split(":")[0]
        self.root_domain = _root_domain(self.target)

        self.threads = threads
        self.do_verify = verify
        self.do_fingerprint = fingerprint
        self.timeout = timeout

        # 候选 IP 池 + 来源追踪
        # candidates: {ip: {sources: [str], evidence: {dim: bool}, ...}}
        self.candidates: Dict[str, Dict[str, Any]] = {}

        # 阶段产物
        self.cdn_info: Dict[str, Any] = {}        # 阶段 1
        self.cert_info: Dict[str, Any] = {}       # 阶段 2
        self.subdomains: List[str] = []           # 阶段 3
        self.passive_ips: List[str] = []          # 阶段 4
        self.mail_info: Dict[str, Any] = {}       # 阶段 5
        self.filtered: List[str] = []             # 阶段 6
        self.host_verified: Dict[str, Any] = {}   # 阶段 7
        self.tls_report: Dict[str, Any] = {}      # 阶段 8
        self.page_hashes: Dict[str, Any] = {}     # 阶段 9
        self.ranked: List[Dict[str, Any]] = []    # 阶段 10

        # CDN 节点参考指纹
        self.ref_tls: Optional[Dict[str, Any]] = None
        self.ref_body_hash: Optional[str] = None
        self.ref_body_len: int = 0

        self.start_time = time.time()

    # ------------------------------------------------------------------
    # 候选 IP 管理
    # ------------------------------------------------------------------
    def _add_candidate(self, ip: str, source: str,
                       evidence_dim: Optional[str] = None,
                       extra: Optional[Dict] = None) -> None:
        """添加候选 IP, 记录来源和证据维度"""
        if not ip or not _is_ip(ip):
            return
        if ip not in self.candidates:
            self.candidates[ip] = {
                "ip": ip,
                "sources": [],
                "evidence": {
                    "A_cert": False,
                    "B_dns_history": False,
                    "C_subdomain": False,
                    "D_mail": False,
                    "E_fingerprint": False,
                    "F_space_engine": False,
                },
                "is_cdn": is_cdn(ip),
                "vendor": get_vendor(ip),
                "details": {},
            }
        if source not in self.candidates[ip]["sources"]:
            self.candidates[ip]["sources"].append(source)
        if evidence_dim:
            self.candidates[ip]["evidence"][evidence_dim] = True
        if extra:
            self.candidates[ip]["details"].update(extra)

    # ==================================================================
    # 阶段 1: 识别 CDN
    # ==================================================================
    def stage1_identify_cdn(self) -> None:
        """阶段 1: DNS 解析 + HTTP 响应头, 判断目标是否套 CDN"""
        _stage_header(1, "识别 CDN")

        # 1.1 DNS 解析 (A / AAAA / CNAME)
        a_records = _query_dns_records(self.target, "A")
        aaaa_records = _query_dns_records(self.target, "AAAA")
        cname_records = _query_dns_records(self.target, "CNAME")

        _info(f"A 记录:    {', '.join(a_records) or '(无)'}")
        _info(f"AAAA 记录: {', '.join(aaaa_records) or '(无)'}")
        if cname_records:
            _info(f"CNAME:     {', '.join(cname_records)}")

        # 1.2 检测 CDN: IP 是否属于已知 CDN 段
        detected_by_ip: Set[str] = set()
        for ip in a_records + aaaa_records:
            vendor = get_vendor(ip)
            if vendor:
                detected_by_ip.add(vendor)

        # 1.3 HTTP 响应头指纹
        detected_by_header: Set[str] = set()
        http_info: Dict[str, Any] = {}
        for scheme in ("https", "http"):
            resp = _http_get(f"{scheme}://{self.target}/")
            if resp is None:
                continue
            http_info = {
                "status": resp.status_code,
                "server": resp.headers.get("Server", ""),
                "via": resp.headers.get("Via", ""),
                "final_url": resp.url,
                "cdn_headers": {},
            }
            for hname, vendor in CDN_HEADER_SIGNATURES.items():
                for k, v in resp.headers.items():
                    if k.lower() == hname:
                        detected_by_header.add(vendor)
                        http_info["cdn_headers"][k] = v
            # Server 头推断
            sv = resp.headers.get("Server", "").lower()
            if "cloudflare" in sv:
                detected_by_header.add("Cloudflare")
            elif "tengine" in sv or "alicdn" in sv:
                detected_by_header.add("阿里云 CDN")
            elif "bfe" in sv:
                detected_by_header.add("百度云加速")
            elif "microsoft-azure" in sv or "azure" in sv:
                detected_by_header.add("Azure Front Door")
            elif "akamaighost" in sv or "akamai" in sv:
                detected_by_header.add("Akamai")
            # CNAME 推断
            for cn in cname_records:
                cn_lower = cn.lower()
                if "cloudflare" in cn_lower or "cdn.cloudflare" in cn_lower:
                    detected_by_header.add("Cloudflare")
                elif "cloudfront" in cn_lower:
                    detected_by_header.add("Amazon CloudFront")
                elif "akamai" in cn_lower or "edgekey" in cn_lower:
                    detected_by_header.add("Akamai")
                elif "fastly" in cn_lower:
                    detected_by_header.add("Fastly")
                elif "azureedge" in cn_lower or "azurefd" in cn_lower:
                    detected_by_header.add("Azure Front Door")
                elif "cdn.dnsv1" in cn_lower or "dnsv1" in cn_lower:
                    detected_by_header.add("腾讯云 CDN")
                elif "kunlun" in cn_lower or "alicdn" in cn_lower:
                    detected_by_header.add("阿里云 CDN")
                elif "cdnhwc1" in cn_lower or "cdnhwc2" in cn_lower:
                    detected_by_header.add("华为云 CDN")
            break  # 成功一个 scheme 即可

        all_detected = detected_by_ip | detected_by_header
        is_behind_cdn = len(all_detected) > 0

        self.cdn_info = {
            "target": self.target,
            "root_domain": self.root_domain,
            "a_records": a_records,
            "aaaa_records": aaaa_records,
            "cname_records": cname_records,
            "detected_cdn_by_ip": sorted(detected_by_ip),
            "detected_cdn_by_header": sorted(detected_by_header),
            "all_detected_cdn": sorted(all_detected),
            "is_behind_cdn": is_behind_cdn,
            "http": http_info,
        }

        if is_behind_cdn:
            _ok(f"目标套了 CDN: {_c(', '.join(all_detected), Color.YELLOW)}")
        else:
            _warn("未检测到 CDN, 目标可能直连源站")

        # 1.4 把当前解析到的 IP 也加入候选 (会被阶段 6 过滤)
        for ip in a_records + aaaa_records:
            self._add_candidate(ip, "dns_current", None)

    # ==================================================================
    # 阶段 2: 证书透明度
    # ==================================================================
    def stage2_certificates(self) -> None:
        """阶段 2: crt.sh 证书透明度日志查询

        查询 crt.ct 中的所有证书, 提取:
          - 证书关联的子域名 (SAN)
          - 历史解析 IP (部分 CT 日志含 IP)
          - 当前证书 SHA256 指纹 (与阶段 8 对比用)
        """
        _stage_header(2, "证书透明度 (crt.sh)")

        # 2.1 查询 crt.sh
        ct_subdomains: Set[str] = set()
        ct_url = f"https://crt.sh/?q=%25.{self.root_domain}&output=json"
        resp = _http_get(ct_url, timeout=20)
        if resp is not None and resp.status_code == 200:
            try:
                data = resp.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower().rstrip(".")
                        if name and "*" not in name and name != self.root_domain:
                            if name.endswith(self.root_domain):
                                ct_subdomains.add(name)
                _ok(f"crt.sh 返回 {len(data)} 条证书, 提取 {len(ct_subdomains)} 个子域")
            except (json.JSONDecodeError, ValueError):
                _fail("crt.sh 返回非 JSON, 跳过")
        else:
            _warn("crt.sh 查询失败 (可能限速), 使用备选源")

        # 备选: 用 openssl 直接抓当前证书
        cert_sha256 = None
        if extract_cert_fingerprint is not None:
            cert_fp = extract_cert_fingerprint(self.target, 443,
                                               sni=self.target, timeout=10)
            if cert_fp.get("available"):
                cert_sha256 = cert_fp.get("sha256")
                _info(f"当前证书 SHA256: {cert_sha256}")
                self.cert_info["current_cert"] = cert_fp
                # SAN 中的子域名也加入
                subject = cert_fp.get("subject", "")
                if "CN=" in subject:
                    cn = subject.split("CN=")[1].split(",")[0].split("/")[0]
                    if cn.endswith(self.root_domain):
                        ct_subdomains.add(cn.lower())

        self.cert_info["ct_subdomains"] = sorted(ct_subdomains)
        self.cert_info["cert_sha256"] = cert_sha256

        # 2.2 解析 CT 子域名 (部分可能直连源站)
        resolved_count = 0
        for sub in ct_subdomains:
            ips = _query_dns_records(sub, "A")
            for ip in ips:
                self._add_candidate(ip, f"cert_ct:{sub}", "A_cert",
                                    {"subdomain": sub})
                resolved_count += 1
        if resolved_count:
            _ok(f"CT 子域名解析出 {resolved_count} 个 IP")

    # ==================================================================
    # 阶段 3: 子域名枚举
    # ==================================================================
    def stage3_subdomains(self) -> None:
        """阶段 3: 子域名枚举 + 解析

        来源:
          - 阶段 2 的 crt.sh 子域
          - 常见子域名字典探测
          - 被动源 (rapiddns / anubis)
        """
        _stage_header(3, "子域名枚举")

        all_subs: Set[str] = set(self.cert_info.get("ct_subdomains", []))

        # 3.1 常见子域名探测
        _info(f"探测 {len(COMMON_SUBDOMAINS)} 个常见子域名...")
        probe_targets = [f"{s}.{self.root_domain}" for s in COMMON_SUBDOMAINS]

        def _resolve_sub(sub_domain: str) -> Tuple[str, List[str]]:
            return sub_domain, _query_dns_records(sub_domain, "A")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(_resolve_sub, s): s for s in probe_targets}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    sub_domain, ips = fut.result()
                    if ips:
                        all_subs.add(sub_domain)
                        for ip in ips:
                            self._add_candidate(ip, f"subdomain:{sub_domain}",
                                                "C_subdomain",
                                                {"subdomain": sub_domain})
                except Exception:
                    pass

        # 3.2 被动源补充子域 (rapiddns)
        rd_url = f"https://rapiddns.io/subdomain/{self.root_domain}?full=1"
        resp = _http_get(rd_url, timeout=15)
        if resp is not None and resp.status_code == 200:
            found = re.findall(
                r"([a-zA-Z0-9_.-]+\." + re.escape(self.root_domain) + r")",
                resp.text)
            for sub in found:
                all_subs.add(sub.lower().rstrip("."))

        # 3.3 anubis-db
        anubis_url = f"https://jldc.me/anubis/subdomains/{self.root_domain}"
        resp = _http_get(anubis_url, timeout=12)
        if resp is not None and resp.status_code == 200:
            try:
                for sub in resp.json():
                    sub = str(sub).lower().rstrip(".")
                    if sub.endswith(self.root_domain):
                        all_subs.add(sub)
            except (json.JSONDecodeError, ValueError):
                pass

        self.subdomains = sorted(all_subs)
        _ok(f"共发现 {len(self.subdomains)} 个子域名")

        # 3.4 解析所有子域名 (非 CDN 的优先)
        non_cdn_resolved = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {}
            for sub in self.subdomains:
                futures[ex.submit(_query_dns_records, sub, "A")] = sub
            for fut in concurrent.futures.as_completed(futures):
                sub = futures[fut]
                try:
                    ips = fut.result()
                    for ip in ips:
                        self._add_candidate(ip, f"subdomain:{sub}",
                                            "C_subdomain",
                                            {"subdomain": sub})
                        if not is_cdn(ip):
                            non_cdn_resolved += 1
                except Exception:
                    pass

        if non_cdn_resolved:
            _ok(f"其中 {non_cdn_resolved} 个解析到非 CDN IP (疑似源站)")

    # ==================================================================
    # 阶段 4: 被动 DNS
    # ==================================================================
    def stage4_passive_dns(self) -> None:
        """阶段 4: 历史 DNS 记录聚合 (免费被动 DNS 源)

        来源:
          - AlienVault OTX passive_dns
          - HackerTarget hostsearch
          - urlscan.io
          - ThreatMiner
        """
        _stage_header(4, "被动 DNS (历史记录)")

        all_ips: Set[str] = set()

        def _fetch_otx() -> Set[str]:
            """AlienVault OTX (免费无 key)"""
            ips: Set[str] = set()
            url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
                   f"{self.target}/passive_dns")
            resp = _http_get(url, timeout=15)
            if resp is None or resp.status_code != 200:
                return ips
            try:
                for rec in resp.json().get("passive_dns", []):
                    ip = rec.get("address", "")
                    if _is_ip(ip):
                        ips.add(ip)
            except (json.JSONDecodeError, ValueError):
                pass
            return ips

        def _fetch_hackertarget() -> Set[str]:
            """HackerTarget hostsearch (免费限速)"""
            ips: Set[str] = set()
            url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
            resp = _http_get(url, timeout=12)
            if resp is None or resp.status_code != 200:
                return ips
            for line in resp.text.splitlines():
                parts = line.split(",")
                if len(parts) >= 2 and _is_ip(parts[1]):
                    ips.add(parts[1])
            return ips

        def _fetch_urlscan() -> Set[str]:
            """urlscan.io (免费有限)"""
            ips: Set[str] = set()
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.target}"
            resp = _http_get(url, timeout=12)
            if resp is None or resp.status_code != 200:
                return ips
            try:
                for result in resp.json().get("results", []):
                    page = result.get("page", {})
                    ip = page.get("ip", "")
                    if _is_ip(ip):
                        ips.add(ip)
            except (json.JSONDecodeError, ValueError):
                pass
            return ips

        def _fetch_threatminer() -> Set[str]:
            """ThreatMiner (免费)"""
            ips: Set[str] = set()
            url = (f"https://api.threatminer.org/v2/domain.php?q={self.target}"
                   f"&rt=2")
            resp = _http_get(url, timeout=12)
            if resp is None or resp.status_code != 200:
                return ips
            try:
                for rec in resp.json().get("response", []):
                    ip = rec.get("ip", "")
                    if _is_ip(ip):
                        ips.add(ip)
            except (json.JSONDecodeError, ValueError):
                pass
            return ips

        sources = {
            "otx": _fetch_otx,
            "hackertarget": _fetch_hackertarget,
            "urlscan": _fetch_urlscan,
            "threatminer": _fetch_threatminer,
        }

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            futures = {ex.submit(fn): name for name, fn in sources.items()}
            for fut in concurrent.futures.as_completed(futures):
                name = futures[fut]
                try:
                    ips = fut.result()
                    if ips:
                        _ok(f"[{name}] +{len(ips)} 历史 IP")
                        for ip in ips:
                            all_ips.add(ip)
                            self._add_candidate(ip, f"passivedns:{name}",
                                                "B_dns_history")
                    else:
                        _info(f"[{name}] 无数据")
                except Exception as e:
                    _fail(f"[{name}] 异常: {e}")

        self.passive_ips = sorted(all_ips)
        _ok(f"被动 DNS 共聚合 {len(self.passive_ips)} 个历史 IP")

    # ==================================================================
    # 阶段 5: 邮件记录
    # ==================================================================
    def stage5_mail(self) -> None:
        """阶段 5: SPF/MX/TXT 记录中泄露的源站 IP

        SPF (v=spf1 ip4:x.x.x.x) 常直接写源站 IP
        MX 记录的邮件服务器可能就是源站
        """
        _stage_header(5, "邮件记录 (SPF/MX/TXT)")

        # 查询根域 (SPF/MX 通常在根域)
        txt_records = _query_dns_records(self.root_domain, "TXT")
        mx_records = _query_dns_records(self.root_domain, "MX")
        spf_domains = _extract_domains_from_spf(txt_records)

        _info(f"TXT 记录: {len(txt_records)} 条")
        _info(f"MX 记录:  {len(mx_records)} 条")

        # 5.1 SPF 中提取 IP
        spf_ips = _extract_ips_from_spf(txt_records)
        for ip in spf_ips:
            self._add_candidate(ip, "spf_record", "D_mail")
        if spf_ips:
            _ok(f"SPF 记录泄露 IP: {', '.join(spf_ips)}")

        # 5.2 SPF include 域名递归查询
        for spf_domain in spf_domains:
            sub_txt = _query_dns_records(spf_domain, "TXT")
            sub_ips = _extract_ips_from_spf(sub_txt)
            for ip in sub_ips:
                self._add_candidate(ip, f"spf_include:{spf_domain}", "D_mail")
            if sub_ips:
                _ok(f"SPF include:{spf_domain} 泄露 IP: {', '.join(sub_ips)}")

        # 5.3 MX 记录解析 (邮件服务器可能就是源站)
        mx_ips: List[str] = []
        for mx in mx_records:
            # MX 格式: "10 mail.example.com"
            mx_domain = mx.split()[-1] if " " in mx else mx
            mx_domain = mx_domain.rstrip(".")
            if _is_ip(mx_domain):
                mx_ips.append(mx_domain)
            else:
                resolved = _query_dns_records(mx_domain, "A")
                mx_ips.extend(resolved)
        for ip in mx_ips:
            self._add_candidate(ip, "mx_record", "D_mail",
                                {"mx_domain": mx})
        if mx_ips:
            _ok(f"MX 记录解析 IP: {', '.join(mx_ips)}")

        # 5.4 DMARC / _dmarc TXT
        dmarc_txt = _query_dns_records(f"_dmarc.{self.root_domain}", "TXT")
        if dmarc_txt:
            _info(f"DMARC: {dmarc_txt[0][:80]}")

        self.mail_info = {
            "txt_records": txt_records,
            "mx_records": mx_records,
            "spf_ips": spf_ips,
            "spf_include_domains": spf_domains,
            "mx_ips": mx_ips,
        }

    # ==================================================================
    # 阶段 6: CDN 过滤
    # ==================================================================
    def stage6_filter(self) -> None:
        """阶段 6: 用 cdn_ranges.filter_candidates 剔除所有 CDN IP

        只保留非 CDN 的 IP 作为疑似源站候选
        """
        _stage_header(6, "CDN IP 过滤")

        all_ips = list(self.candidates.keys())
        _info(f"过滤前候选 IP: {len(all_ips)} 个")

        # 统计被过滤的 CDN IP
        cdn_ips = [ip for ip in all_ips if is_cdn(ip)]
        for ip in cdn_ips:
            vendor = get_vendor(ip) or "未知"
            _info(f"  CDN 过滤: {ip:20s} ({vendor})")

        # 过滤
        self.filtered = filter_candidates(all_ips)
        _ok(f"过滤后疑似源站 IP: {len(self.filtered)} 个")

        if not self.filtered:
            _warn("无候选源站 IP, 尝试保留所有 IP 进行宽松验证")
            # 宽松模式: 保留所有 IP (包括 CDN, 但标注)
            self.filtered = all_ips

        for ip in self.filtered:
            _info(f"  候选: {ip:20s} "
                  f"(来源: {', '.join(self.candidates[ip]['sources'][:3])})")

    # ==================================================================
    # 阶段 7: Host 验证
    # ==================================================================
    def stage7_host_verify(self) -> None:
        """阶段 7: 直连候选 IP + Host 头, 检查 HTTP 响应

        对每个候选 IP:
          - 发送 HTTP/HTTPS 请求, 伪造 Host: target.com
          - 检查状态码 (200/301/302/403 视为存活)
          - 对比响应内容相似度
        """
        _stage_header(7, "Host 头验证")

        if not self.do_verify:
            _warn("--no-verify 模式, 跳过直连验证 (隐蔽模式)")
            for ip in self.filtered:
                self.host_verified[ip] = {"verified": False, "reason": "skipped"}
            return

        if not self.filtered:
            _fail("无候选 IP 可验证")
            return

        # 7.1 先获取 CDN 节点的参考响应 (用于内容对比)
        _info("获取 CDN 节点参考响应...")
        ref_resp = _http_get(f"https://{self.target}/")
        if ref_resp is not None:
            self.ref_body_hash = _body_hash(ref_resp.content)
            self.ref_body_len = len(ref_resp.content)
            _info(f"参考 body 长度: {self.ref_body_len} | hash: {self.ref_body_hash[:24]}...")

        # 7.2 并发验证候选 IP
        _info(f"并发验证 {len(self.filtered)} 个候选 IP (threads={self.threads})...")

        def _verify_one(ip: str) -> Tuple[str, Dict[str, Any]]:
            """验证单个 IP: 尝试 HTTP + HTTPS, 检查存活 + 内容相似"""
            result: Dict[str, Any] = {
                "ip": ip,
                "verified": False,
                "alive": False,
                "status": None,
                "scheme": None,
                "body_len": 0,
                "body_hash": None,
                "hash_match": False,
                "similarity": 0.0,
            }
            for scheme, port in [("https", 443), ("http", 80)]:
                resp = _http_get_ip(ip, self.target, port=port,
                                    use_https=(scheme == "https"),
                                    timeout=self.timeout)
                if resp is None:
                    continue
                result["alive"] = True
                result["status"] = resp.status_code
                result["scheme"] = scheme
                result["body_len"] = len(resp.content)
                result["body_hash"] = _body_hash(resp.content)

                # 状态码判断存活
                if resp.status_code in (200, 301, 302, 401, 403, 404):
                    result["verified"] = True

                # body hash 对比
                if self.ref_body_hash and result["body_hash"]:
                    if result["body_hash"] == self.ref_body_hash:
                        result["hash_match"] = True
                        result["similarity"] = 1.0
                        return ip, result
                    # 内容相似度 (简单: 长度比 + 关键特征)
                    if self.ref_body_len > 0:
                        ratio = min(result["body_len"], self.ref_body_len) / \
                                max(result["body_len"], self.ref_body_len, 1)
                        result["similarity"] = round(ratio, 2)
                return ip, result
            return ip, result

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(_verify_one, ip): ip for ip in self.filtered}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    ip, result = fut.result()
                    self.host_verified[ip] = result
                    status_str = f"{result['status']}" if result["status"] else "超时"
                    if result["verified"]:
                        tag = _c("存活", Color.GREEN)
                    elif result["alive"]:
                        tag = _c("存活(状态异常)", Color.YELLOW)
                    else:
                        tag = _c("无响应", Color.RED)
                    hash_str = ""
                    if result["hash_match"]:
                        hash_str = _c(" [hash一致]", Color.GREEN + Color.BOLD)
                    elif result["similarity"] > 0.5:
                        hash_str = f" [相似{result['similarity']:.0%}]"
                    print(f"    {ip:20s} {tag} [{result['scheme'] or '-'}] "
                          f"{status_str}{hash_str}")
                except Exception as e:
                    _fail(f"验证异常: {e}")

        verified_count = sum(1 for r in self.host_verified.values()
                             if r.get("verified"))
        _ok(f"Host 验证完成: {verified_count}/{len(self.filtered)} 存活")

    # ==================================================================
    # 阶段 8: TLS 指纹
    # ==================================================================
    def stage8_tls_fingerprint(self) -> None:
        """阶段 8: TLS 指纹对比 (JA3S/JA4S/证书)

        流程:
          1. 提取 CDN 节点参考 TLS 指纹 (target.com:443)
          2. 对每个 Host 验证存活的候选 IP, 提取其 TLS 指纹
          3. compare_fingerprints 对比, 一致 → E_fingerprint 命中
        """
        _stage_header(8, "TLS 指纹 (JA3S/JA4S/证书)")

        if not self.do_fingerprint:
            _warn("--no-fingerprint 模式, 跳过 TLS 指纹 (加速)")
            return

        if extract_server_fingerprint is None or compare_fingerprints is None:
            _warn("ja3extract.py 不可用, 跳过 TLS 指纹")
            return

        # 8.1 获取 CDN 节点参考指纹
        _info(f"提取 CDN 节点参考指纹: {self.target}:443")
        self.ref_tls = extract_server_fingerprint(
            f"{self.target}:443", sni=self.target, timeout=10, with_cert=True)
        if self.ref_tls.get("error"):
            _warn(f"参考指纹提取失败: {self.ref_tls['error']}")
            return
        ja3s = self.ref_tls.get("ja3s", {}).get("ja3s_md5", "(无)")
        ja4s = self.ref_tls.get("ja4s", {}).get("ja4s", "(无)")
        _ok(f"参考 JA3S: {ja3s}")
        _ok(f"参考 JA4S: {ja4s}")

        # 8.2 对存活候选 IP 提取 TLS 指纹并对比
        alive_ips = [ip for ip, r in self.host_verified.items()
                     if r.get("alive")]
        if not alive_ips:
            _warn("无存活候选 IP, 跳过 TLS 指纹对比")
            return

        _info(f"对比 {len(alive_ips)} 个存活 IP 的 TLS 指纹...")

        def _fp_one(ip: str) -> Tuple[str, Dict[str, Any]]:
            """提取单个 IP 的 TLS 指纹并与参考对比"""
            try:
                fp = extract_server_fingerprint(
                    f"{ip}:443", sni=self.target, timeout=8, with_cert=True)
                if fp.get("error"):
                    return ip, {"ip": ip, "error": fp["error"], "match": False,
                                "score": 0}
                report = compare_fingerprints(self.ref_tls, fp)
                return ip, {
                    "ip": ip,
                    "ja3s": fp.get("ja3s", {}).get("ja3s_md5"),
                    "ja4s": fp.get("ja4s", {}).get("ja4s"),
                    "cert_sha256": fp.get("cert", {}).get("sha256"),
                    "match": report.get("match", False),
                    "score": report.get("score", 0),
                    "details": report.get("details", []),
                }
            except Exception as e:
                return ip, {"ip": ip, "error": str(e)[:60], "match": False,
                            "score": 0}

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.threads, 16)) as ex:
            futures = {ex.submit(_fp_one, ip): ip for ip in alive_ips}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    ip, result = fut.result()
                    self.tls_report[ip] = result
                    if result.get("match"):
                        # 指纹匹配 → E_fingerprint 命中
                        self._add_candidate(ip, "tls_match", "E_fingerprint")
                        _ok(f"  {ip:20s} 指纹匹配 (score={result['score']}) "
                            + _c("[E_fingerprint HIT]", Color.GREEN))
                    elif result.get("score", 0) > 0:
                        _info(f"  {ip:20s} 部分匹配 (score={result['score']})")
                    else:
                        if result.get("error"):
                            _info(f"  {ip:20s} 提取失败: {result['error']}")
                        else:
                            _info(f"  {ip:20s} 指纹不匹配")
                except Exception as e:
                    _fail(f"  指纹对比异常: {e}")

        matched = sum(1 for r in self.tls_report.values() if r.get("match"))
        _ok(f"TLS 指纹匹配: {matched}/{len(alive_ips)}")

    # ==================================================================
    # 阶段 9: 页面哈希
    # ==================================================================
    def stage9_page_hash(self) -> None:
        """阶段 9: 页面 body 哈希对比

        对 Host 验证存活的 IP, 对比清洗后 body 的 SHA256:
          - hash 一致 → 强证据 (同一后端)
          - hash 不一致但内容相似 → 中等证据
        """
        _stage_header(9, "页面哈希对比")

        if not self.do_verify:
            _warn("--no-verify 模式, 跳过页面哈希")
            return

        if not self.ref_body_hash:
            _warn("无参考 body hash, 跳过页面哈希对比")
            return

        _info(f"参考 body hash: {self.ref_body_hash[:32]}...")
        match_count = 0
        for ip, result in self.host_verified.items():
            if not result.get("alive"):
                continue
            ip_hash = result.get("body_hash")
            if not ip_hash:
                continue
            entry = {
                "ip": ip,
                "body_hash": ip_hash,
                "ref_hash": self.ref_body_hash,
                "hash_match": result.get("hash_match", False),
                "similarity": result.get("similarity", 0.0),
            }
            self.page_hashes[ip] = entry
            if result.get("hash_match"):
                match_count += 1
                # 页面哈希一致 → 强化 E_fingerprint 证据
                self._add_candidate(ip, "page_hash_match", "E_fingerprint")
                _ok(f"  {ip:20s} 页面哈希一致 [强证据]")
            elif result.get("similarity", 0) > 0.7:
                _info(f"  {ip:20s} 内容高度相似 ({result['similarity']:.0%})")

        _ok(f"页面哈希一致: {match_count}/{len(self.page_hashes)}")

    # ==================================================================
    # 阶段 10: 贝叶斯评分
    # ==================================================================
    def stage10_bayesian_scoring(self) -> None:
        """阶段 10: 6 维证据贝叶斯加权评分 + 排名

        证据维度:
          A_cert         — 阶段 2 证书透明度发现
          B_dns_history  — 阶段 4 被动 DNS 历史
          C_subdomain    — 阶段 3 子域名解析
          D_mail         — 阶段 5 邮件记录
          E_fingerprint  — 阶段 8 TLS 指纹 / 阶段 9 页面哈希
          F_space_engine — (外部 internet_wide_scanner 提供, 此处标注)
        """
        _stage_header(10, "贝叶斯置信度评分")

        ranked: List[Dict[str, Any]] = []
        for ip, data in self.candidates.items():
            # 跳过 CDN IP (除非宽松模式无候选)
            if is_cdn(ip) and self.filtered and ip not in self.filtered:
                continue

            evidence = data["evidence"]
            prob, details = bayesian_score(evidence)

            entry = {
                "ip": ip,
                "probability": round(prob, 4),
                "probability_pct": f"{prob * 100:.1f}%",
                "verdict": _verdict_plain(prob),
                "evidence": evidence,
                "evidence_details": details,
                "sources": data["sources"],
                "is_cdn": data["is_cdn"],
                "vendor": data["vendor"],
                "host_verified": self.host_verified.get(ip, {}).get("verified", False),
                "host_status": self.host_verified.get(ip, {}).get("status"),
                "tls_match": self.tls_report.get(ip, {}).get("match", False),
                "tls_score": self.tls_report.get(ip, {}).get("score", 0),
                "page_hash_match": self.page_hashes.get(ip, {}).get("hash_match", False),
                "page_similarity": self.page_hashes.get(ip, {}).get("similarity", 0.0),
            }
            ranked.append(entry)

        # 按概率降序排序
        ranked.sort(key=lambda x: x["probability"], reverse=True)
        self.ranked = ranked

        # 打印排名表
        self._print_ranking(ranked)

    # ------------------------------------------------------------------
    # 排名表输出
    # ------------------------------------------------------------------
    def _print_ranking(self, ranked: List[Dict[str, Any]]) -> None:
        """打印彩色排名表"""
        print(f"\n{_c('=' * 80, Color.BOLD)}")
        print(_c(f"  溯源结果排名 — {self.target}", Color.BOLD + Color.CYAN))
        print(_c('=' * 80, Color.BOLD))

        if not ranked:
            _fail("未能确定任何候选源站 IP")
            print(_c("\n  后续建议:", Color.YELLOW))
            print("    1. 提供 API Key 调用 internet_wide_scanner.py (Shodan/FOFA/Censys)")
            print("    2. 使用 cdn_ip_collector.py 深度收集 CDN IP 段后反查")
            print("    3. 手动方法: 邮件触发 / 移动 App 硬编码 / CI/CD 泄露")
            print("    4. 启动 cdn_origin_monitor.py 持续监控等待漂移事件")
            return

        # 表头
        header = (f"  {'排名':<4} {'IP':<20} {'置信度':<8} {'TLS':<4} "
                  f"{'哈希':<4} {'来源数':<6} {'判定'}")
        print(_c(header, Color.BOLD))
        print(_c("-" * 80, Color.GRAY))

        for idx, entry in enumerate(ranked[:20], 1):
            prob = entry["probability"]
            prob_str = f"{prob * 100:.1f}%"
            tls_str = _c("Y", Color.GREEN) if entry["tls_match"] else _c("-", Color.GRAY)
            hash_str = _c("Y", Color.GREEN) if entry["page_hash_match"] else _c("-", Color.GRAY)
            verdict = _verdict(prob)
            src_count = len(entry["sources"])

            # 置信度着色
            if prob >= THRESHOLD_CONFIRM:
                prob_color = Color.GREEN + Color.BOLD
            elif prob >= THRESHOLD_HIGH:
                prob_color = Color.YELLOW
            elif prob >= THRESHOLD_SUSPECT:
                prob_color = Color.MAGENTA
            else:
                prob_color = Color.GRAY

            ip_display = entry["ip"]
            if entry["is_cdn"]:
                ip_display += f" ({entry['vendor']})"

            print(f"  {idx:<4} {ip_display:<20} "
                  f"{_c(prob_str, prob_color):<8} {tls_str:<4} {hash_str:<4} "
                  f"{src_count:<6} {verdict}")

        # Top 1 证据详情
        if ranked:
            top = ranked[0]
            print(_c(f"\n  Top 1 证据 ({top['ip']}):", Color.BOLD))
            for dim in ["A_cert", "B_dns_history", "C_subdomain",
                        "D_mail", "E_fingerprint", "F_space_engine"]:
                hit = top["evidence"].get(dim, False)
                flag = _c("HIT", Color.GREEN) if hit else _c("miss", Color.GRAY)
                llr_val = LLR[dim]["hit"] if hit else LLR[dim]["miss"]
                print(f"    {dim:20s}: {flag} ({llr_val:+.1f})")
            print(f"\n  来源: {', '.join(top['sources'])}")

    # ==================================================================
    # 全流程编排
    # ==================================================================
    def run(self) -> Dict[str, Any]:
        """运行完整 10 阶段流水线, 返回报告 dict"""
        print(_c(f"\n{'#' * 80}", Color.BOLD + Color.CYAN))
        print(_c(f"  CDN 真实 IP 溯源 — {self.target}", Color.BOLD + Color.CYAN))
        print(_c(f"  根域名: {self.root_domain} | 线程: {self.threads} | "
                 f"验证: {'on' if self.do_verify else 'off'} | "
                 f"指纹: {'on' if self.do_fingerprint else 'off'}",
                 Color.GRAY))
        print(_c(f"{'#' * 80}", Color.BOLD + Color.CYAN))

        try:
            self.stage1_identify_cdn()
            self.stage2_certificates()
            self.stage3_subdomains()
            self.stage4_passive_dns()
            self.stage5_mail()
            self.stage6_filter()
            self.stage7_host_verify()
            self.stage8_tls_fingerprint()
            self.stage9_page_hash()
            self.stage10_bayesian_scoring()
        except KeyboardInterrupt:
            print(_c("\n\n[!] 用户中断, 输出已收集结果...", Color.YELLOW))
        except Exception as e:
            print(_c(f"\n[!] 流水线异常: {e}", Color.RED))
            import traceback
            traceback.print_exc()

        return self.build_report()

    # ------------------------------------------------------------------
    # 报告生成
    # ------------------------------------------------------------------
    def build_report(self) -> Dict[str, Any]:
        """构建完整 JSON 报告"""
        duration = round(time.time() - self.start_time, 2)
        report = {
            "meta": {
                "tool": "cdn_tracer.py",
                "version": VERSION,
                "target": self.target,
                "root_domain": self.root_domain,
                "timestamp": datetime.now().isoformat(),
                "duration_sec": duration,
                "threads": self.threads,
                "verify": self.do_verify,
                "fingerprint": self.do_fingerprint,
            },
            "stage1_cdn": self.cdn_info,
            "stage2_cert": {
                "ct_subdomains": self.cert_info.get("ct_subdomains", []),
                "cert_sha256": self.cert_info.get("cert_sha256"),
                "current_cert": self.cert_info.get("current_cert", {}),
            },
            "stage3_subdomains": self.subdomains,
            "stage4_passive_dns": self.passive_ips,
            "stage5_mail": self.mail_info,
            "stage6_filter": {
                "total_candidates": len(self.candidates),
                "filtered": self.filtered,
            },
            "stage7_host_verify": self.host_verified,
            "stage8_tls": {
                "ref_tls": {
                    "ja3s": self.ref_tls.get("ja3s", {}).get("ja3s_md5")
                            if self.ref_tls else None,
                    "ja4s": self.ref_tls.get("ja4s", {}).get("ja4s")
                            if self.ref_tls else None,
                    "cert_sha256": self.ref_tls.get("cert", {}).get("sha256")
                                   if self.ref_tls else None,
                },
                "candidates": self.tls_report,
            },
            "stage9_page_hash": {
                "ref_hash": self.ref_body_hash,
                "ref_body_len": self.ref_body_len,
                "candidates": self.page_hashes,
            },
            "stage10_ranking": self.ranked,
            "summary": {
                "total_candidates": len(self.candidates),
                "filtered_candidates": len(self.filtered),
                "confirmed": [r for r in self.ranked
                              if r["probability"] >= THRESHOLD_CONFIRM],
                "high_suspicion": [r for r in self.ranked
                                   if THRESHOLD_HIGH <= r["probability"] < THRESHOLD_CONFIRM],
            },
        }
        return report


# ======================================================================
# CLI
# ======================================================================
def _save_report(report: Dict[str, Any], path: str) -> None:
    """保存 JSON 报告"""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


def _default_output_path(target: str) -> str:
    """生成默认输出文件名: report_<domain>_<timestamp>.json"""
    safe = re.sub(r"[^a-zA-Z0-9.-]", "_", target)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"report_{safe}_{ts}.json"


def _main() -> int:
    Color.enable()
    parser = argparse.ArgumentParser(
        prog="cdn_tracer.py",
        description="CDN/WAF 真实 IP 溯源 — 10 阶段全自动流水线 (v5.0)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python cdn_tracer.py target.com
  python cdn_tracer.py target.com --threads 30
  python cdn_tracer.py target.com -o result.json
  python cdn_tracer.py target.com --no-verify
  python cdn_tracer.py target.com --no-fingerprint
""",
    )
    parser.add_argument("target", help="目标域名 (如 target.com)")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                        help=f"并发线程数 (默认 {DEFAULT_THREADS})")
    parser.add_argument("-o", "--output", default=None,
                        help="输出 JSON 报告路径 (默认 report_<domain>_<ts>.json)")
    parser.add_argument("--no-verify", action="store_true",
                        help="仅被动发现, 不直连候选 IP (隐蔽模式)")
    parser.add_argument("--no-fingerprint", action="store_true",
                        help="跳过 TLS 指纹和页面哈希 (加速模式)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"单次请求超时秒数 (默认 {DEFAULT_TIMEOUT})")
    parser.add_argument("-v", "--version", action="version",
                        version=f"cdn_tracer.py v{VERSION}")

    args = parser.parse_args()

    tracer = CdnTracer(
        target=args.target,
        threads=args.threads,
        verify=not args.no_verify,
        fingerprint=not args.no_fingerprint,
        timeout=args.timeout,
    )
    report = tracer.run()

    # 保存报告
    output_path = args.output or _default_output_path(args.target)
    _save_report(report, output_path)
    print(f"\n{_c('[*]', Color.BLUE)} 报告已保存: {_c(output_path, Color.BOLD)}")

    # 退出码: 有确认源站 → 0, 有疑似 → 1, 无候选 → 2
    if report["summary"]["confirmed"]:
        return 0
    elif report["summary"]["high_suspicion"]:
        return 1
    else:
        return 2


if __name__ == "__main__":
    sys.exit(_main())
