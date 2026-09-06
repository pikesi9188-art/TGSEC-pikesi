#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""waf_detector/detector.py — 9维指纹检测引擎

核心类 WAFDetector 提供基于9个维度的WAF指纹检测能力:
    1. HTTP响应头关键字匹配 — 检查 server, via, x-cache 等头
    2. 响应头值正则匹配 — 正则匹配头值
    3. Cookie关键字匹配 — 检查 Set-Cookie 中的特征
    4. 响应体关键字匹配 — 检查HTML中的WAF特征
    5. 状态码匹配 — 403/503/406/429等WAF拦截码
    6. HTML title匹配 — 检查页面标题
    7. 主动探测 — 发送特定路径请求(如 /cdn-cgi/trace)
    8. 行为指纹 — 发送恶意payload观察响应行为
    9. IP/ASN范围匹配 — 解析IP检查是否属于已知WAF ASN范围

置信度计算: confidence = min(1.0, sum(weight_i) / total_weight * fp_confidence_weight)

依赖: aiohttp (异步HTTP), waf_detector.fingerprints, waf_detector.payloads
"""

import asyncio
import ipaddress
import re
import socket
import time
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from waf_detector.fingerprints import (
    WAF_FINGERPRINTS,
    get_all_waf_names,
    get_stats,
    get_wafs_by_category,
)
from waf_detector.payloads import (
    BYPASS_PAYLOADS,
    get_payload_count,
    get_payloads,
    get_techniques,
)


# ========================================================================== #
#  常量定义
# ========================================================================== #

# CDN 检测 — 响应头映射
CDN_HEADER_MAP = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "cf-mitigated": "Cloudflare",
    "x-amz-cf-id": "AWS CloudFront",
    "x-amz-cf-pop": "AWS CloudFront",
    "x-sucuri-id": "Sucuri",
    "x-akamai-transformed": "Akamai",
    "x-akamai-request-id": "Akamai",
    "x-fastly-request-id": "Fastly",
    "x-served-by": "Fastly",
    "x-incapsula-request-id": "Incapsula/Imperva",
    "x-iinfo": "Incapsula/Imperva",
    "x-cdn": "Generic CDN",
    "x-cdn-forward": "Generic CDN",
    "x-edge-ip": "Generic CDN",
    "x-nc": "StackPath",
    "x-hw": "Highwinds/StackPath",
    "served-by": "Generic CDN",
    "x-proxy-cache": "Generic CDN",
    "x-cache": "Generic CDN/Cache",
    "via": "Proxy/CDN",
}

# CDN 检测 — Server 头模式
CDN_SERVER_PATTERNS = [
    (re.compile(r"cloudflare", re.I), "Cloudflare"),
    (re.compile(r"cloudfront", re.I), "AWS CloudFront"),
    (re.compile(r"akamai", re.I), "Akamai"),
    (re.compile(r"akamaighost", re.I), "Akamai"),
    (re.compile(r"fastly", re.I), "Fastly"),
    (re.compile(r"sucuri", re.I), "Sucuri"),
    (re.compile(r"incapsula", re.I), "Incapsula/Imperva"),
    (re.compile(r"imperva", re.I), "Incapsula/Imperva"),
    (re.compile(r"edgecast", re.I), "Verizon EdgeCast"),
    (re.compile(r"section\.io", re.I), "Section.io"),
    (re.compile(r"keycdn", re.I), "KeyCDN"),
    (re.compile(r"maxcdn", re.I), "MaxCDN"),
    (re.compile(r"stackpath", re.I), "StackPath"),
    (re.compile(r"varnish", re.I), "Varnish Cache"),
    (re.compile(r"amazons3", re.I), "AWS S3"),
]

# CDN 检测 — via 头值模式
CDN_VIA_PATTERNS = [
    (re.compile(r"cloudflare", re.I), "Cloudflare"),
    (re.compile(r"cloudfront", re.I), "AWS CloudFront"),
    (re.compile(r"akamai", re.I), "Akamai"),
    (re.compile(r"varnish", re.I), "Varnish Cache"),
    (re.compile(r"sucuri", re.I), "Sucuri"),
    (re.compile(r"incapsula", re.I), "Incapsula/Imperva"),
    (re.compile(r"fastly", re.I), "Fastly"),
]

# WAF 常见拦截状态码
WAF_BLOCK_STATUS_CODES = {400, 401, 403, 406, 418, 419, 429, 503, 999, 1020}

# 9维检测权重
DIMENSION_WEIGHTS = {
    "header_keyword": 1.0,
    "header_regex": 1.0,
    "cookie": 0.8,
    "body_keyword": 0.7,
    "status_code": 0.5,
    "html_title": 0.8,
    "active_probe": 1.0,
    "behavioral": 0.9,
    "ip_asn": 0.6,
}

TOTAL_WEIGHT = sum(DIMENSION_WEIGHTS.values())

# 行为指纹测试 payload
BEHAVIORAL_TEST_PAYLOADS = [
    ("id=1' OR '1'='1", "sqli"),
    ("q=<script>alert(1)</script>", "xss"),
    ("cmd=;cat /etc/passwd", "cmdi"),
]

# 默认请求头
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}

# HTML title 提取正则
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

# 已知 WAF ASN → CIDR 映射 (简化版, 用于 IP/ASN 维度)
KNOWN_ASN_CIDRS = {
    "AS13335": [  # Cloudflare
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
        "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    ],
    "AS16509": [  # AWS
        "13.32.0.0/15", "13.34.0.0/15", "52.46.0.0/18",
        "52.84.0.0/15", "54.230.0.0/16", "54.239.128.0/18",
        "99.84.0.0/16", "205.251.192.0/19", "205.251.224.0/22",
    ],
    "AS20940": [  # Akamai
        "23.0.0.0/12", "23.32.0.0/14", "23.36.0.0/16",
        "23.53.0.0/16", "23.62.0.0/15", "23.64.0.0/14",
        "72.246.0.0/15", "95.100.0.0/15", "184.24.0.0/13",
    ],
    "AS16625": [  # Akamai (Alt)
        "23.192.0.0/14", "23.196.0.0/14", "23.200.0.0/14",
        "95.96.0.0/14", "95.100.0.0/15", "184.26.0.0/15",
    ],
    "AS19551": [  # Incapsula/Imperva
        "199.83.128.0/21", "199.83.136.0/21",
        "45.64.64.0/22", "45.64.72.0/22",
        "103.28.248.0/22", "103.28.252.0/22",
        "193.34.96.0/22", "193.34.100.0/22",
    ],
    "AS54113": [  # Fastly
        "23.235.32.0/20", "23.235.48.0/20",
        "43.249.72.0/22", "103.244.50.0/24",
        "151.101.0.0/16", "199.232.0.0/16",
    ],
    "AS45090": [  # 火山引擎/ByteDance
        "180.76.0.0/16",
    ],
}


# ========================================================================== #
#  速率限制器 — 令牌桶算法
# ========================================================================== #

class RateLimiter:
    """令牌桶速率限制器, 用于控制异步请求频率。

    每秒生成 ``rate`` 个令牌, 桶容量为 ``rate``。
    每次 acquire 消耗 1 个令牌, 不足时等待。
    """

    def __init__(self, rate: float):
        self.rate = max(float(rate), 0.001)
        self.capacity = max(float(rate), 1.0)
        self.tokens = self.capacity
        self._updated_at = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        """获取令牌, 不足时自动等待。"""
        if self.rate <= 0:
            return
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._updated_at
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                self._updated_at = now
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return
                deficit = tokens - self.tokens
                wait_time = deficit / self.rate
            # 释放锁后等待, 避免长时间持锁
            await asyncio.sleep(min(wait_time, 2.0))


# ========================================================================== #
#  WAF 检测器
# ========================================================================== #

class WAFDetector:
    """9维 WAF 指纹检测引擎。

    通过9个维度对目标进行 WAF 指纹匹配, 支持异步批量检测、
    代理、速率限制、CDN 检测等功能。

    用法::

        async with WAFDetector(proxy=None, timeout=10) as detector:
            result = await detector.detect("https://example.com")
            results = await detector.detect_batch(["target1", "target2"])
    """

    def __init__(self, proxy=None, timeout=10, insecure=False, rate_limit=5):
        """初始化检测器。

        Args:
            proxy:    代理URL (http:// 或 socks5://)
            timeout:  请求超时秒数
            insecure: 跳过SSL证书验证
            rate_limit: 每秒请求数限制 (0 = 不限制)
        """
        self.proxy = proxy
        self.timeout_seconds = timeout
        self.insecure = insecure
        self.rate_limit = rate_limit
        self.rate_limiter = RateLimiter(rate_limit) if rate_limit and rate_limit > 0 else None
        self._session: Optional["aiohttp.ClientSession"] = None
        self._fingerprints = self._load_fingerprints()

    # ------------------------------------------------------------------ #
    #  指纹加载
    # ------------------------------------------------------------------ #

    def _load_fingerprints(self) -> list:
        """加载并标准化 WAF 指纹库。

        兼容 dict 和 list 两种 WAF_FINGERPRINTS 结构,
        确保每个指纹 dict 都包含 "name" 字段。
        """
        fps: list[dict] = []
        raw = WAF_FINGERPRINTS

        if isinstance(raw, dict):
            for name, data in raw.items():
                fp = dict(data) if isinstance(data, dict) else {}
                fp["name"] = name
                fps.append(fp)
        elif isinstance(raw, (list, tuple)):
            for item in raw:
                if isinstance(item, dict):
                    fp = dict(item)
                    fp.setdefault("name", fp.get("name", "Unknown"))
                    fps.append(fp)
        return fps

    # ------------------------------------------------------------------ #
    #  HTTP 会话管理
    # ------------------------------------------------------------------ #

    async def _get_session(self) -> "aiohttp.ClientSession":
        """获取或创建 aiohttp ClientSession。"""
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError("aiohttp is required for HTTP requests. Install with: pip install aiohttp")

        if self._session is None or self._session.closed:
            connector_kwargs: dict[str, Any] = {"limit": 100, "limit_per_host": 20}
            if self.insecure:
                connector_kwargs["ssl"] = False
            connector = aiohttp.TCPConnector(**connector_kwargs)
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                connector=connector,
                trust_env=True,
            )
        return self._session

    async def close(self) -> None:
        """关闭 HTTP 会话。"""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()

    # ------------------------------------------------------------------ #
    #  HTTP 请求
    # ------------------------------------------------------------------ #

    async def _request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        data: Optional[Any] = None,
        allow_redirects: bool = True,
    ) -> Optional[dict]:
        """执行异步 HTTP 请求, 带速率限制。

        Returns:
            包含 status, headers, body, cookies 的 dict, 失败返回 None。
        """
        if self.rate_limiter:
            await self.rate_limiter.acquire()

        session = await self._get_session()
        req_headers = dict(DEFAULT_HEADERS)
        if headers:
            req_headers.update(headers)

        try:
            async with session.request(
                method,
                url,
                headers=req_headers,
                params=params,
                data=data,
                proxy=self.proxy,
                allow_redirects=allow_redirects,
            ) as resp:
                body = await resp.text(errors="replace")
                resp_headers = {k: v for k, v in resp.headers.items()}

                # 收集所有 Set-Cookie 值
                set_cookies: list[str] = []
                for key, value in resp_headers.items():
                    if key.lower() == "set-cookie":
                        set_cookies.append(value)

                # aiohttp cookies
                cookies: dict[str, str] = {}
                if resp.cookies:
                    cookies = {k: v.value for k, v in resp.cookies.items()}

                return {
                    "status": resp.status,
                    "headers": resp_headers,
                    "body": body,
                    "cookies": cookies,
                    "set_cookies": set_cookies,
                    "url": str(resp.url),
                }
        except asyncio.TimeoutError:
            return None
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    #  工具方法
    # ------------------------------------------------------------------ #

    @staticmethod
    def _normalize_url(target: str) -> str:
        """确保 URL 包含 scheme。"""
        if not target:
            return target
        if not target.startswith(("http://", "https://")):
            return "http://" + target
        return target

    @staticmethod
    def _resolve_ip(hostname: str) -> Optional[str]:
        """将主机名解析为 IP 地址。"""
        hostname = hostname.replace("http://", "").replace("https://", "")
        hostname = hostname.split("/")[0].split(":")[0]
        try:
            info = socket.getaddrinfo(hostname, None)
            for item in info:
                ip = item[4][0]
                return ip
        except Exception:
            pass
        return None

    @staticmethod
    def _extract_title(body: str) -> str:
        """从 HTML 中提取 <title> 内容。"""
        match = TITLE_RE.search(body[:5000])
        if match:
            return match.group(1).strip()
        return ""

    @staticmethod
    def _inject_payload(url: str, payload: str) -> str:
        """将 payload 注入 URL 作为查询参数。"""
        parsed = urlparse(url)
        if parsed.query:
            return f"{url}&{payload}"
        return f"{url}?{payload}"

    def _lookup_asn_by_ip(self, ip: str) -> Optional[str]:
        """通过 IP 查找 ASN (使用内置 CIDR 映射)。

        遍历 KNOWN_ASN_CIDRS, 返回 IP 所属的 ASN 字符串 (如 "AS13335")。
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None

        for asn, cidr_list in KNOWN_ASN_CIDRS.items():
            for cidr in cidr_list:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if addr in network:
                        return asn
                except ValueError:
                    continue
        return None

    # ------------------------------------------------------------------ #
    #  CDN 检测
    # ------------------------------------------------------------------ #

    def _detect_cdn(self, headers: dict, status: int) -> tuple[bool, Optional[str]]:
        """通过响应头检测 CDN。

        Returns:
            (cdn_detected, cdn_provider)
        """
        lower_headers = {k.lower(): v for k, v in headers.items()}

        # 1. 检查 CDN 专属头
        for header_name, provider in CDN_HEADER_MAP.items():
            if header_name in lower_headers:
                value = lower_headers[header_name]
                if not value:
                    continue
                if header_name == "via":
                    # via 头需要进一步检查值
                    for pattern, via_provider in CDN_VIA_PATTERNS:
                        if pattern.search(value):
                            return True, via_provider
                    # via 存在但未匹配已知 CDN, 标记为 Generic Proxy
                    return True, "Proxy/CDN"
                elif header_name == "x-cache":
                    # x-cache 可能来自 CDN 或普通缓存
                    for pattern, _ in CDN_VIA_PATTERNS:
                        if pattern.search(value):
                            return True, "CDN (x-cache)"
                else:
                    return True, provider

        # 2. 检查 Server 头
        server = lower_headers.get("server", "")
        if server:
            for pattern, provider in CDN_SERVER_PATTERNS:
                if pattern.search(server):
                    return True, provider

        return False, None

    # ------------------------------------------------------------------ #
    #  9维检测方法
    # ------------------------------------------------------------------ #

    def _check_header_keywords(self, headers: dict, fp: dict) -> tuple[bool, list[str]]:
        """维度1: HTTP响应头关键字匹配。

        检查指纹中定义的响应头是否出现, 以及头值是否包含指定关键字。
        模式 ".*" 表示仅检查头是否存在。
        """
        fp_headers = fp.get("headers", {})
        if not fp_headers:
            return False, []

        lower_headers = {k.lower(): v for k, v in headers.items()}
        matched: list[str] = []

        for header_name, patterns in fp_headers.items():
            if not isinstance(patterns, list):
                patterns = [patterns]
            actual = lower_headers.get(header_name.lower(), "")
            if not actual:
                continue
            for pattern in patterns:
                pat = str(pattern)
                if pat in (".*", "*"):
                    # 仅检查头是否存在
                    matched.append(f"header:{header_name}=present")
                elif pat.lower() in actual.lower():
                    matched.append(f"header:{header_name}~{pat}")

        return len(matched) > 0, matched

    def _check_header_regex(self, headers: dict, fp: dict) -> tuple[bool, list[str]]:
        """维度2: 响应头值正则匹配。

        将指纹中的头模式编译为正则, 匹配 "header_name: value" 字符串。
        """
        fp_headers = fp.get("headers", {})
        if not fp_headers:
            return False, []

        matched: list[str] = []

        for header_name, patterns in fp_headers.items():
            if not isinstance(patterns, list):
                patterns = [patterns]
            actual = ""
            for key, value in headers.items():
                if key.lower() == header_name.lower():
                    actual = value
                    break
            if not actual:
                continue
            for pattern in patterns:
                pat = str(pattern)
                if pat in (".*", "*"):
                    continue  # 跳过通配模式 (已在维度1处理)
                try:
                    regex = re.compile(pat, re.I)
                    if regex.search(actual):
                        matched.append(f"header_regex:{header_name}~{pat}")
                except re.error:
                    # 非法正则, 回退为子串匹配
                    if pat.lower() in actual.lower():
                        matched.append(f"header_regex:{header_name}~{pat}")

        return len(matched) > 0, matched

    def _check_cookies(self, headers: dict, fp: dict) -> tuple[bool, list[str]]:
        """维度3: Cookie关键字匹配。

        检查 Set-Cookie 头中是否包含 WAF 特征 Cookie 名称。
        """
        cookie_patterns = fp.get("cookies", [])
        if not cookie_patterns:
            return False, []
        if not isinstance(cookie_patterns, list):
            cookie_patterns = [cookie_patterns]

        # 收集所有 Set-Cookie 值
        set_cookie_values: list[str] = []
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                set_cookie_values.append(value)
        if not set_cookie_values:
            return False, []

        all_cookies = " ".join(set_cookie_values).lower()
        matched: list[str] = []
        for kw in cookie_patterns:
            if str(kw).lower() in all_cookies:
                matched.append(f"cookie:{kw}")

        return len(matched) > 0, matched

    def _check_body_keywords(self, body: str, fp: dict) -> tuple[bool, list[str]]:
        """维度4: 响应体关键字匹配。

        检查响应正文中是否包含 WAF 特征关键词。
        """
        body_keywords = fp.get("body", [])
        if not body_keywords:
            return False, []
        if not isinstance(body_keywords, list):
            body_keywords = [body_keywords]

        body_lower = body.lower()[:50000]
        matched: list[str] = []
        for kw in body_keywords:
            kw_str = str(kw)
            if kw_str and kw_str.lower() in body_lower:
                matched.append(f"body:{kw_str}")

        return len(matched) > 0, matched

    def _check_status_code(self, status: int, fp: dict) -> tuple[bool, list[str]]:
        """维度5: 状态码匹配。

        检查响应状态码是否为 WAF 拦截码。
        """
        fp_codes = fp.get("status_codes", [])
        if not fp_codes:
            if status in WAF_BLOCK_STATUS_CODES:
                return True, [f"status:{status}(generic)"]
            return False, []

        if not isinstance(fp_codes, list):
            fp_codes = [fp_codes]

        matched: list[str] = []
        if status in fp_codes:
            matched.append(f"status:{status}")
        elif status in WAF_BLOCK_STATUS_CODES:
            matched.append(f"status:{status}(generic)")

        return len(matched) > 0, matched

    def _check_html_title(self, body: str, fp: dict) -> tuple[bool, list[str]]:
        """维度6: HTML title匹配。

        检查页面标题是否包含 WAF 特征关键词。
        """
        title_keywords = fp.get("title", [])
        if not title_keywords:
            return False, []
        if not isinstance(title_keywords, list):
            title_keywords = [title_keywords]

        title = self._extract_title(body)
        if not title:
            return False, []

        title_lower = title.lower()
        matched: list[str] = []
        for kw in title_keywords:
            kw_str = str(kw)
            if kw_str.lower() in title_lower:
                matched.append(f"title:{kw_str}")

        return len(matched) > 0, matched

    async def _check_active_probe(self, base_url: str, fp: dict) -> tuple[bool, list[str]]:
        """维度7: 主动探测。

        发送特定路径请求 (如 /cdn-cgi/trace), 检查响应是否包含 WAF 特征。
        """
        probe_config = fp.get("active_probe", {})
        if not probe_config or not isinstance(probe_config, dict):
            return False, []

        probe_path = probe_config.get("path", "")
        contains_keywords = probe_config.get("contains", [])
        if not probe_path:
            return False, []
        if not isinstance(contains_keywords, list):
            contains_keywords = [contains_keywords] if contains_keywords else []

        probe_url = urljoin(base_url, probe_path)
        resp = await self._request(probe_url)
        if resp is None:
            return False, []

        matched: list[str] = []
        if contains_keywords:
            body_lower = resp["body"].lower()[:10000]
            for kw in contains_keywords:
                kw_str = str(kw)
                if kw_str.lower() in body_lower:
                    matched.append(f"probe:{probe_path}~{kw_str}")
        else:
            # 无 contains 关键词时, 非 404 响应即为命中
            if resp["status"] != 404 and resp["status"] < 500:
                matched.append(f"probe:{probe_path}(status:{resp['status']})")

        return len(matched) > 0, matched

    async def _check_behavioral(
        self, base_url: str, fp: dict, baseline_resp: Optional[dict]
    ) -> tuple[bool, list[str]]:
        """维度8: 行为指纹。

        发送恶意 payload, 观察响应行为是否与 WAF 拦截特征一致。
        """
        behavior_config = fp.get("behavior", {})
        if not behavior_config or not isinstance(behavior_config, dict):
            # 即使没有 behavior 配置, 也可以做行为测试
            pass

        fp_status_codes = fp.get("status_codes", [])
        if not isinstance(fp_status_codes, list):
            fp_status_codes = [fp_status_codes] if fp_status_codes else []

        matched: list[str] = []
        baseline_status = baseline_resp["status"] if baseline_resp else 200
        baseline_len = len(baseline_resp["body"]) if baseline_resp else 0

        for payload, attack_type in BEHAVIORAL_TEST_PAYLOADS:
            test_url = self._inject_payload(base_url, payload)
            resp = await self._request(test_url)
            if resp is None:
                continue

            status = resp["status"]
            resp_len = len(resp["body"])

            # 状态码变为拦截码
            status_blocked = (
                status in WAF_BLOCK_STATUS_CODES
                or status in fp_status_codes
            ) and status != baseline_status

            # 内容显著变化 (可能是拦截页面)
            content_changed = False
            if baseline_len > 100:
                ratio = resp_len / baseline_len
                if ratio < 0.3 and status >= 400:
                    content_changed = True

            # 检查是否设置了行为 Cookie
            behavior_cookie = behavior_config.get("cookie_name", "") if behavior_config else ""
            cookie_set = False
            if behavior_cookie:
                for key, value in resp["headers"].items():
                    if key.lower() == "set-cookie" and behavior_cookie.lower() in value.lower():
                        cookie_set = True
                        break

            if status_blocked or content_changed or cookie_set:
                reason = []
                if status_blocked:
                    reason.append(f"blocked(status:{status})")
                if content_changed:
                    reason.append("content_changed")
                if cookie_set:
                    reason.append(f"cookie:{behavior_cookie}")
                matched.append(f"behavioral:{attack_type}({'+'.join(reason)})")
                break  # 一个行为命中即可

        return len(matched) > 0, matched

    def _check_ip_asn(self, ip: Optional[str], fp: dict) -> tuple[bool, list[str]]:
        """维度9: IP/ASN范围匹配。

        解析目标 IP, 检查是否属于已知 WAF 的 ASN 范围。
        """
        if not ip:
            return False, []

        asn_list = fp.get("asn", [])
        if not asn_list:
            return False, []
        if not isinstance(asn_list, list):
            asn_list = [asn_list]

        # 通过内置 CIDR 映射查找 ASN
        detected_asn = self._lookup_asn_by_ip(ip)
        matched: list[str] = []

        if detected_asn:
            for waf_asn in asn_list:
                waf_asn_str = str(waf_asn).upper()
                if waf_asn_str == detected_asn.upper():
                    matched.append(f"asn:{waf_asn_str}(ip:{ip})")

        return len(matched) > 0, matched

    # ------------------------------------------------------------------ #
    #  置信度计算
    # ------------------------------------------------------------------ #

    @staticmethod
    def _calculate_confidence(hit_dims: list[str], fp_weight: float = 1.0) -> float:
        """基于命中维度计算置信度。

        公式: confidence = min(1.0, sum(weight_i) / total_weight * fp_confidence_weight)
        """
        if not hit_dims:
            return 0.0
        hit_weight = sum(DIMENSION_WEIGHTS.get(dim, 0) for dim in hit_dims)
        confidence = (hit_weight / TOTAL_WEIGHT) * fp_weight
        return round(min(1.0, confidence), 4)

    # ------------------------------------------------------------------ #
    #  核心检测方法
    # ------------------------------------------------------------------ #

    async def detect(self, target: str) -> dict:
        """单目标 WAF 检测 — 9维指纹匹配。

        Args:
            target: 目标 URL 或主机名

        Returns:
            检测结果 dict, 包含以下字段:
                - target: 目标
                - waf_detected: 是否检测到 WAF
                - waf_name: WAF 名称 (未检测到为 None)
                - confidence: 置信度 (0-1)
                - matched_indicators: 命中的指标列表
                - response_status: 响应状态码
                - ip_address: 目标 IP
                - cdn_detected: 是否检测到 CDN
                - cdn_provider: CDN 提供商
                - detection_methods: 命中的检测维度
                - response_headers: 响应头
                - response_time_ms: 响应时间(毫秒)
        """
        url = self._normalize_url(target)
        parsed = urlparse(url)
        hostname = parsed.hostname or target

        # 解析 IP
        ip_address = self._resolve_ip(hostname)

        # 初始请求 — 获取基线响应
        req_start = time.monotonic()
        resp = await self._request(url)
        response_time_ms = round((time.monotonic() - req_start) * 1000, 2)

        if resp is None:
            return {
                "target": target,
                "waf_detected": False,
                "waf_name": None,
                "confidence": 0.0,
                "matched_indicators": [],
                "response_status": 0,
                "status_code": 0,
                "ip_address": ip_address or "",
                "ip": ip_address or "",
                "cdn_detected": False,
                "cdn": False,
                "cdn_provider": None,
                "detection_methods": [],
                "response_headers": {},
                "response_time_ms": response_time_ms,
                "error": "Request failed or timed out",
            }

        headers = resp["headers"]
        body = resp["body"]
        status = resp["status"]

        # CDN 检测
        cdn_detected, cdn_provider = self._detect_cdn(headers, status)

        # 对每个指纹执行9维检测
        best_match: Optional[str] = None
        best_confidence = 0.0
        best_indicators: list[str] = []
        best_methods: list[str] = []

        for fp in self._fingerprints:
            hit_dims: list[str] = []
            all_indicators: list[str] = []

            # 维度1: HTTP响应头关键字匹配
            hit, indicators = self._check_header_keywords(headers, fp)
            if hit:
                hit_dims.append("header_keyword")
                all_indicators.extend(indicators)

            # 维度2: 响应头值正则匹配
            hit, indicators = self._check_header_regex(headers, fp)
            if hit:
                hit_dims.append("header_regex")
                all_indicators.extend(indicators)

            # 维度3: Cookie关键字匹配
            hit, indicators = self._check_cookies(headers, fp)
            if hit:
                hit_dims.append("cookie")
                all_indicators.extend(indicators)

            # 维度4: 响应体关键字匹配
            hit, indicators = self._check_body_keywords(body, fp)
            if hit:
                hit_dims.append("body_keyword")
                all_indicators.extend(indicators)

            # 维度5: 状态码匹配
            hit, indicators = self._check_status_code(status, fp)
            if hit:
                hit_dims.append("status_code")
                all_indicators.extend(indicators)

            # 维度6: HTML title匹配
            hit, indicators = self._check_html_title(body, fp)
            if hit:
                hit_dims.append("html_title")
                all_indicators.extend(indicators)

            # 维度9: IP/ASN范围匹配 (被动检测, 放在主动检测前面)
            hit, indicators = self._check_ip_asn(ip_address, fp)
            if hit:
                hit_dims.append("ip_asn")
                all_indicators.extend(indicators)

            # 仅对有被动命中的指纹执行主动探测和行为指纹 (性能优化)
            has_passive_hit = len(hit_dims) > 0

            # 维度7: 主动探测
            if has_passive_hit or len(self._fingerprints) <= 10:
                hit, indicators = await self._check_active_probe(url, fp)
                if hit:
                    hit_dims.append("active_probe")
                    all_indicators.extend(indicators)

            # 维度8: 行为指纹
            if has_passive_hit or len(self._fingerprints) <= 10:
                hit, indicators = await self._check_behavioral(url, fp, resp)
                if hit:
                    hit_dims.append("behavioral")
                    all_indicators.extend(indicators)

            # 计算置信度
            if hit_dims:
                fp_weight = fp.get("confidence_weight", 1.0)
                confidence = self._calculate_confidence(hit_dims, fp_weight)
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = fp.get("name", "Unknown")
                    best_indicators = all_indicators
                    best_methods = hit_dims

        result = {
            "target": target,
            "waf_detected": best_match is not None,
            "waf_name": best_match,
            "confidence": best_confidence,
            "matched_indicators": best_indicators,
            "response_status": status,
            "status_code": status,  # reporter 兼容
            "ip_address": ip_address or "",
            "ip": ip_address or "",  # reporter 兼容
            "cdn_detected": cdn_detected,
            "cdn": cdn_detected,  # reporter 兼容
            "cdn_provider": cdn_provider,
            "detection_methods": best_methods,
            "response_headers": headers,
            "response_time_ms": response_time_ms,
        }

        return result

    async def detect_batch(self, targets: list, concurrency: int = 20) -> list:
        """批量检测多个目标。

        Args:
            targets: 目标列表
            concurrency: 最大并发数

        Returns:
            检测结果列表, 顺序与 targets 一致
        """
        semaphore = asyncio.Semaphore(max(1, concurrency))

        async def _detect_one(t: str) -> dict:
            async with semaphore:
                try:
                    return await self.detect(t)
                except Exception as e:
                    return {
                        "target": t,
                        "waf_detected": False,
                        "waf_name": None,
                        "confidence": 0.0,
                        "matched_indicators": [],
                        "response_status": 0,
                        "status_code": 0,
                        "ip_address": "",
                        "ip": "",
                        "cdn_detected": False,
                        "cdn": False,
                        "cdn_provider": None,
                        "detection_methods": [],
                        "response_headers": {},
                        "response_time_ms": 0.0,
                        "error": str(e),
                    }

        tasks = [_detect_one(t) for t in targets]
        results = await asyncio.gather(*tasks)
        return list(results)

    async def test_bypass(self, target: str, waf: str, attack_type: str) -> list:
        """测试绕过 payload。

        向目标发送绕过 payload, 判断是否被 WAF 拦截。

        Args:
            target: 目标 URL
            waf: WAF 名称 (用于获取针对性 payload)
            attack_type: 攻击类型 (sqli/xss/cmdi/lfi 等)

        Returns:
            payload 测试结果列表, 每项包含:
                - payload: payload 字符串
                - technique: 使用的技术
                - blocked: 是否被拦截
                - block_reason: 拦截原因
                - bypass_success: 是否绕过成功
                - status_code: 响应状态码
        """
        url = self._normalize_url(target)

        # 获取 payload — 尝试多种调用方式以兼容不同签名
        payloads_raw: list = []
        try:
            payloads_raw = get_payloads(attack_type=attack_type, waf=waf)
        except TypeError:
            try:
                payloads_raw = get_payloads(attack_type, waf)
            except TypeError:
                try:
                    payloads_raw = get_payloads(attack_type)
                except TypeError:
                    try:
                        payloads_raw = get_payloads()
                    except Exception:
                        payloads_raw = []
        except Exception:
            payloads_raw = []

        # 如果未获取到 payload, 尝试从 BYPASS_PAYLOADS 直接读取
        if not payloads_raw and BYPASS_PAYLOADS:
            if isinstance(BYPASS_PAYLOADS, dict):
                payloads_raw = BYPASS_PAYLOADS.get(attack_type, [])
                if not payloads_raw:
                    # 取所有类型的 payload
                    for v in BYPASS_PAYLOADS.values():
                        if isinstance(v, list):
                            payloads_raw.extend(v)
            elif isinstance(BYPASS_PAYLOADS, list):
                payloads_raw = BYPASS_PAYLOADS

        # 获取基线响应用于对比
        baseline_resp = await self._request(url)
        baseline_status = baseline_resp["status"] if baseline_resp else 200
        baseline_len = len(baseline_resp["body"]) if baseline_resp else 0

        results: list[dict] = []
        for item in payloads_raw:
            # 兼容 dict 和 str 两种 payload 格式
            if isinstance(item, dict):
                payload = item.get("payload", "")
                technique = item.get("technique", item.get("type", "unknown"))
            elif isinstance(item, str):
                payload = item
                technique = "unknown"
            else:
                continue

            if not payload:
                continue

            test_url = self._inject_payload(url, payload)
            resp = await self._request(test_url)

            if resp is None:
                results.append({
                    "payload": payload,
                    "technique": technique,
                    "blocked": True,
                    "block_reason": "Request failed or timed out",
                    "bypass_success": False,
                    "status_code": 0,
                })
                continue

            status = resp["status"]
            resp_len = len(resp["body"])

            # 判断是否被拦截
            blocked = status in WAF_BLOCK_STATUS_CODES or status >= 400

            block_reason = ""
            if blocked:
                if status in WAF_BLOCK_STATUS_CODES:
                    block_reason = f"HTTP {status} — WAF block status code"
                else:
                    block_reason = f"HTTP {status} — Error response"
                # 检查响应体中的拦截关键词
                body_lower = resp["body"].lower()[:2000]
                block_keywords = [
                    "blocked", "denied", "forbidden", "firewall", "waf",
                    "security", "protection", "rejected", "prohibited",
                    "access denied", "request blocked",
                ]
                for kw in block_keywords:
                    if kw in body_lower:
                        block_reason += f" (body: '{kw}')"
                        break
            elif baseline_len > 100 and resp_len < baseline_len * 0.3:
                blocked = True
                block_reason = "Response content significantly reduced (possible block)"

            bypass_success = not blocked

            results.append({
                "payload": payload,
                "technique": technique,
                "blocked": blocked,
                "block_reason": block_reason,
                "bypass_success": bypass_success,
                "status_code": status,
            })

        return results
