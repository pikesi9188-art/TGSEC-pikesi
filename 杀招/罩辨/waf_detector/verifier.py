#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""waf_detector/verifier.py — WAF检测误报消除器 (三重验证)

核心类 WAFVerifier 通过三重验证消除 WAF 检测误报:
    1. 状态码对比 — 对比正常请求 vs 恶意payload请求的状态码差异
    2. 内容签名   — 对比正常响应 vs 拦截响应的内容哈希差异
    3. 基线差异   — 建立正常响应基线, 对比探测响应的差异

验证流程:
    正常请求 → 建立基线 → 发送恶意payload → 三维对比 → 计算验证分数

依赖: aiohttp (异步HTTP)
"""

import asyncio
import hashlib
import re
from typing import Any, Optional
from urllib.parse import urlparse

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False


# ========================================================================== #
#  常量定义
# ========================================================================== #

# WAF 常见拦截状态码
WAF_BLOCK_STATUS_CODES = {400, 401, 403, 406, 418, 419, 429, 503, 999, 1020}

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

# 恶意 payload 库 — 按攻击类型分组 (用于验证 WAF 拦截行为)
MALICIOUS_PAYLOADS: dict[str, list[str]] = {
    "sqli": [
        "id=1' OR '1'='1",
        "id=1; DROP TABLE users--",
        "id=1 UNION SELECT NULL,NULL--",
        "id=1' AND SLEEP(5)--",
        "id=1' OR 1=1#",
    ],
    "xss": [
        "q=<script>alert(1)</script>",
        "q=<img src=x onerror=alert(1)>",
        "q=\"><script>alert(1)</script>",
        "q=javascript:alert(1)",
        "q=<svg onload=alert(1)>",
    ],
    "cmdi": [
        "cmd=; cat /etc/passwd",
        "cmd=| id",
        "cmd=$(whoami)",
        "cmd=`id`",
        "cmd=&& dir",
    ],
    "lfi": [
        "file=../../etc/passwd",
        "file=....//....//etc/passwd",
        "file=/etc/passwd",
        "file=..%252f..%252fetc/passwd",
        "file=php://filter/convert.base64-encode/resource=index",
    ],
    "ssti": [
        "x={{7*7}}",
        "x=${7*7}",
        "x=#{7*7}",
        "x={{config}}",
        "x={{''.__class__.__mro__[1].__subclasses__()}}",
    ],
}

# 良性 payload — 用于建立正常响应基线
BENIGN_PAYLOADS = [
    "id=1",
    "q=hello",
    "search=test",
    "page=1",
    "name=world",
    "type=normal",
    "view=list",
    "lang=en",
]

# 拦截页面内容关键词
BLOCK_KEYWORDS = [
    "blocked", "denied", "forbidden", "firewall", "waf",
    "security", "protection", "rejected", "prohibited",
    "access denied", "request blocked", "suspicious",
    "malicious", "attack", "incapsula", "cloudflare",
    "akamai", "sucuri", "imperva", "mod_security",
    "request rejected", "not acceptable",
]

# Title 提取正则
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

# 三重验证权重
VERIFICATION_WEIGHTS = {
    "status_code_comparison": 0.30,
    "content_signature": 0.35,
    "baseline_diff": 0.35,
}


# ========================================================================== #
#  WAF 验证器
# ========================================================================== #

class WAFVerifier:
    """WAF 检测误报消除器 — 三重验证。

    通过状态码对比、内容签名、基线差异三重验证来消除误报。
    如果三重验证均未检测到 WAF 拦截行为, 则判定为误报。

    用法::

        async with WAFVerifier(timeout=10) as verifier:
            result = await verifier.verify("https://example.com")
            if result["verified"]:
                print(f"WAF confirmed: {result['verification_score']}")
    """

    def __init__(self, proxy=None, timeout=10, insecure=False):
        """初始化验证器。

        Args:
            proxy:    代理URL (http:// 或 socks5://)
            timeout:  请求超时秒数
            insecure: 跳过SSL证书验证
        """
        self.proxy = proxy
        self.timeout_seconds = timeout
        self.insecure = insecure
        self._session: Optional["aiohttp.ClientSession"] = None

    # ------------------------------------------------------------------ #
    #  HTTP 会话管理
    # ------------------------------------------------------------------ #

    async def _get_session(self) -> "aiohttp.ClientSession":
        """获取或创建 aiohttp ClientSession。"""
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError(
                "aiohttp is required for HTTP requests. Install with: pip install aiohttp"
            )

        if self._session is None or self._session.closed:
            connector_kwargs: dict[str, Any] = {"limit": 50, "limit_per_host": 10}
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
    ) -> Optional[dict]:
        """执行异步 HTTP 请求。

        Returns:
            包含 status, headers, body 的 dict, 失败返回 None。
        """
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
                allow_redirects=True,
            ) as resp:
                body = await resp.text(errors="replace")
                resp_headers = {k: v for k, v in resp.headers.items()}
                return {
                    "status": resp.status,
                    "headers": resp_headers,
                    "body": body,
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
    def _inject_payload(url: str, payload: str) -> str:
        """将 payload 注入 URL 作为查询参数。"""
        parsed = urlparse(url)
        if parsed.query:
            return f"{url}&{payload}"
        return f"{url}?{payload}"

    @staticmethod
    def _content_hash(body: str) -> str:
        """计算响应正文的 SHA256 哈希。"""
        return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()

    @staticmethod
    def _extract_title(body: str) -> str:
        """从 HTML 中提取 <title> 内容。"""
        match = TITLE_RE.search(body[:5000])
        if match:
            return match.group(1).strip()
        return ""

    def _extract_signature(self, body: str) -> dict:
        """提取响应正文的内容签名。

        包含: 哈希、长度、标题、是否含拦截关键词。
        """
        normalized = re.sub(r"\s+", " ", body).strip()
        body_lower = body.lower()[:5000]
        return {
            "hash": self._content_hash(normalized),
            "raw_hash": self._content_hash(body),
            "length": len(body),
            "normalized_length": len(normalized),
            "title": self._extract_title(body),
            "has_block_keywords": any(kw in body_lower for kw in BLOCK_KEYWORDS),
            "matched_block_keywords": [
                kw for kw in BLOCK_KEYWORDS if kw in body_lower
            ],
        }

    @staticmethod
    def _flatten_payloads() -> list[tuple[str, str]]:
        """将所有恶意 payload 展平为 (attack_type, payload) 列表。"""
        result: list[tuple[str, str]] = []
        for attack_type, payloads in MALICIOUS_PAYLOADS.items():
            for payload in payloads:
                result.append((attack_type, payload))
        return result

    # ------------------------------------------------------------------ #
    #  验证方法 1: 状态码对比
    # ------------------------------------------------------------------ #

    async def _verify_status_code(self, url: str, baseline_status: int) -> dict:
        """验证1: 状态码对比。

        对比正常请求 vs 恶意 payload 请求的状态码差异。
        如果恶意请求返回 WAF 拦截码而正常请求不返回, 说明 WAF 存在。
        """
        status_changes: list[dict] = []
        block_count = 0
        total_tests = 0

        for attack_type, payload in self._flatten_payloads():
            test_url = self._inject_payload(url, payload)
            resp = await self._request(test_url)
            total_tests += 1

            if resp is None:
                status_changes.append({
                    "payload": payload,
                    "attack_type": attack_type,
                    "baseline_status": baseline_status,
                    "malicious_status": 0,
                    "changed": False,
                    "blocked": False,
                    "error": "Request failed",
                })
                continue

            status = resp["status"]
            changed = status != baseline_status
            blocked = status in WAF_BLOCK_STATUS_CODES or status >= 400

            status_changes.append({
                "payload": payload,
                "attack_type": attack_type,
                "baseline_status": baseline_status,
                "malicious_status": status,
                "changed": changed,
                "blocked": blocked,
            })

            if blocked:
                block_count += 1

        changed_count = sum(1 for s in status_changes if s.get("changed"))
        score = block_count / total_tests if total_tests > 0 else 0.0

        return {
            "passed": block_count > 0,
            "score": round(min(1.0, score), 4),
            "baseline_status": baseline_status,
            "total_tests": total_tests,
            "status_changed_count": changed_count,
            "blocked_count": block_count,
            "details": status_changes,
        }

    # ------------------------------------------------------------------ #
    #  验证方法 2: 内容签名
    # ------------------------------------------------------------------ #

    async def _verify_content_signature(self, url: str, baseline_body: str) -> dict:
        """验证2: 内容签名对比。

        对比正常响应 vs 拦截响应的内容哈希差异。
        如果恶意请求的响应内容与正常响应显著不同且包含拦截关键词,
        说明 WAF 对恶意请求做了拦截处理。
        """
        baseline_sig = self._extract_signature(baseline_body)
        signature_diffs: list[dict] = []
        block_signature_count = 0
        total_tests = 0

        for attack_type, payload in self._flatten_payloads():
            test_url = self._inject_payload(url, payload)
            resp = await self._request(test_url)
            total_tests += 1

            if resp is None:
                signature_diffs.append({
                    "payload": payload,
                    "attack_type": attack_type,
                    "hash_changed": False,
                    "length_diff": 0,
                    "length_ratio": 1.0,
                    "has_block_keywords": False,
                    "error": "Request failed",
                })
                continue

            sig = self._extract_signature(resp["body"])
            hash_changed = sig["hash"] != baseline_sig["hash"]
            length_diff = abs(sig["length"] - baseline_sig["length"])
            length_ratio = (
                sig["length"] / baseline_sig["length"]
                if baseline_sig["length"] > 0
                else 1.0
            )
            has_block = sig["has_block_keywords"]

            diff_info = {
                "payload": payload,
                "attack_type": attack_type,
                "hash_changed": hash_changed,
                "length_diff": length_diff,
                "length_ratio": round(length_ratio, 4),
                "has_block_keywords": has_block,
                "matched_keywords": sig["matched_block_keywords"],
                "title": sig["title"],
                "baseline_title": baseline_sig["title"],
            }
            signature_diffs.append(diff_info)

            # 显著内容变化: 哈希不同 且 (内容大幅缩减 或 包含拦截关键词)
            if hash_changed and (length_ratio < 0.5 or has_block):
                block_signature_count += 1

        score = block_signature_count / total_tests if total_tests > 0 else 0.0

        return {
            "passed": block_signature_count > 0,
            "score": round(min(1.0, score), 4),
            "baseline_hash": baseline_sig["raw_hash"],
            "baseline_length": baseline_sig["length"],
            "baseline_title": baseline_sig["title"],
            "total_tests": total_tests,
            "significant_diff_count": block_signature_count,
            "details": signature_diffs,
        }

    # ------------------------------------------------------------------ #
    #  验证方法 3: 基线差异
    # ------------------------------------------------------------------ #

    async def _verify_baseline_diff(self, url: str, baseline_resp: dict) -> dict:
        """验证3: 基线差异对比。

        使用良性 payload 建立正常响应基线, 然后对比恶意 payload 响应的差异。
        如果恶意请求响应显著偏离基线, 说明 WAF 在拦截恶意请求。
        """
        # 使用良性 payload 建立基线
        benign_responses: list[dict] = []
        for payload in BENIGN_PAYLOADS:
            test_url = self._inject_payload(url, payload)
            resp = await self._request(test_url)
            if resp is not None:
                benign_responses.append(resp)

        if not benign_responses:
            return {
                "passed": False,
                "score": 0.0,
                "reason": "Could not establish baseline with benign requests",
                "baseline_samples": 0,
                "total_tests": 0,
                "anomaly_count": 0,
                "details": [],
            }

        # 计算基线统计
        benign_statuses = [r["status"] for r in benign_responses]
        benign_lengths = [len(r["body"]) for r in benign_responses]
        benign_hashes = {self._content_hash(r["body"]) for r in benign_responses}

        # 众数作为基线状态码
        baseline_status_mode = max(set(benign_statuses), key=benign_statuses.count)
        baseline_length_avg = (
            sum(benign_lengths) / len(benign_lengths) if benign_lengths else 0
        )
        baseline_hash_set = benign_hashes

        # 用恶意 payload 测试, 对比基线
        diff_results: list[dict] = []
        anomaly_count = 0
        total_tests = 0

        for attack_type, payload in self._flatten_payloads():
            test_url = self._inject_payload(url, payload)
            resp = await self._request(test_url)
            total_tests += 1

            if resp is None:
                diff_results.append({
                    "payload": payload,
                    "attack_type": attack_type,
                    "status": 0,
                    "baseline_status": baseline_status_mode,
                    "status_anomaly": False,
                    "response_length": 0,
                    "baseline_length_avg": round(baseline_length_avg, 2),
                    "length_anomaly": False,
                    "hash_anomaly": False,
                    "is_anomaly": False,
                    "error": "Request failed",
                })
                continue

            status = resp["status"]
            resp_len = len(resp["body"])
            resp_hash = self._content_hash(resp["body"])

            # 异常检测
            status_anomaly = (
                status != baseline_status_mode
                and (status in WAF_BLOCK_STATUS_CODES or status >= 400)
            )
            length_anomaly = (
                baseline_length_avg > 0
                and resp_len < baseline_length_avg * 0.3
            )
            hash_anomaly = resp_hash not in baseline_hash_set

            # 综合判断: 状态码异常 或 (哈希异常 且 内容缩减)
            is_anomaly = status_anomaly or (hash_anomaly and length_anomaly)

            diff_results.append({
                "payload": payload,
                "attack_type": attack_type,
                "status": status,
                "baseline_status": baseline_status_mode,
                "status_anomaly": status_anomaly,
                "response_length": resp_len,
                "baseline_length_avg": round(baseline_length_avg, 2),
                "length_anomaly": length_anomaly,
                "hash_anomaly": hash_anomaly,
                "is_anomaly": is_anomaly,
            })

            if is_anomaly:
                anomaly_count += 1

        score = anomaly_count / total_tests if total_tests > 0 else 0.0

        return {
            "passed": anomaly_count > 0,
            "score": round(min(1.0, score), 4),
            "baseline_status": baseline_status_mode,
            "baseline_length_avg": round(baseline_length_avg, 2),
            "baseline_samples": len(benign_responses),
            "total_tests": total_tests,
            "anomaly_count": anomaly_count,
            "details": diff_results,
        }

    # ------------------------------------------------------------------ #
    #  核心验证方法
    # ------------------------------------------------------------------ #

    async def verify(self, target: str) -> dict:
        """三重验证 WAF 检测结果。

        通过状态码对比、内容签名、基线差异三个维度验证 WAF 是否真实存在,
        消除因 CDN、服务器配置等导致的误报。

        Args:
            target: 目标 URL

        Returns:
            验证结果 dict, 包含以下字段:
                - target: 目标
                - verified: 是否验证通过 (WAF 确实存在)
                - verification_score: 验证分数 (0-1)
                - checks: 三重验证详情
                    - status_code_comparison: 状态码对比结果
                    - content_signature: 内容签名对比结果
                    - baseline_diff: 基线差异对比结果
                - false_positive_reasons: 误报原因列表
                - recommendation: 建议
        """
        url = self._normalize_url(target)

        # 获取基线响应 (无 payload 的正常请求)
        baseline_resp = await self._request(url)

        if baseline_resp is None:
            return {
                "target": target,
                "verified": False,
                "verification_score": 0.0,
                "checks": {},
                "false_positive_reasons": [
                    "Could not reach target for baseline request",
                ],
                "recommendation": "Target is unreachable. Verify the URL and try again.",
            }

        baseline_status = baseline_resp["status"]
        baseline_body = baseline_resp["body"]

        # 执行三重验证
        status_check = await self._verify_status_code(url, baseline_status)
        content_check = await self._verify_content_signature(url, baseline_body)
        baseline_check = await self._verify_baseline_diff(url, baseline_resp)

        # 计算总验证分数 (加权平均)
        verification_score = (
            status_check["score"] * VERIFICATION_WEIGHTS["status_code_comparison"]
            + content_check["score"] * VERIFICATION_WEIGHTS["content_signature"]
            + baseline_check["score"] * VERIFICATION_WEIGHTS["baseline_diff"]
        )
        verification_score = round(verification_score, 4)

        # 判定是否验证通过 (WAF 确实存在)
        any_passed = (
            status_check["passed"]
            or content_check["passed"]
            or baseline_check["passed"]
        )
        verified = verification_score >= 0.3 and any_passed

        # 识别误报原因
        false_positive_reasons: list[str] = []
        if not verified:
            if not status_check["passed"]:
                false_positive_reasons.append(
                    "Status code comparison: No status code changes detected "
                    "with malicious payloads — WAF may not be actively blocking"
                )
            if not content_check["passed"]:
                false_positive_reasons.append(
                    "Content signature: No significant content differences "
                    "between normal and malicious responses"
                )
            if not baseline_check["passed"]:
                false_positive_reasons.append(
                    "Baseline diff: Malicious responses do not deviate "
                    "from benign response baseline"
                )
            if baseline_status >= 400:
                false_positive_reasons.append(
                    f"Target returns HTTP {baseline_status} for normal requests "
                    "— target may be down or blocking all traffic"
                )

        # 生成建议
        if verified:
            if verification_score >= 0.7:
                recommendation = (
                    "High confidence: WAF is present and actively blocking "
                    "malicious requests."
                )
            elif verification_score >= 0.4:
                recommendation = (
                    "Medium confidence: WAF likely present. "
                    "Some malicious requests were blocked."
                )
            else:
                recommendation = (
                    "Low confidence: WAF may be present but blocking "
                    "behavior is inconsistent."
                )
        else:
            recommendation = (
                "Likely false positive: No WAF blocking behavior detected. "
                "The initial detection may have been triggered by CDN "
                "or server configuration."
            )

        return {
            "target": target,
            "verified": verified,
            "verification_score": verification_score,
            "checks": {
                "status_code_comparison": {
                    "passed": status_check["passed"],
                    "score": status_check["score"],
                    "baseline_status": status_check["baseline_status"],
                    "blocked_count": status_check["blocked_count"],
                    "status_changed_count": status_check["status_changed_count"],
                    "total_tests": status_check["total_tests"],
                },
                "content_signature": {
                    "passed": content_check["passed"],
                    "score": content_check["score"],
                    "significant_diff_count": content_check["significant_diff_count"],
                    "baseline_length": content_check["baseline_length"],
                    "total_tests": content_check["total_tests"],
                },
                "baseline_diff": {
                    "passed": baseline_check["passed"],
                    "score": baseline_check["score"],
                    "anomaly_count": baseline_check["anomaly_count"],
                    "baseline_samples": baseline_check.get("baseline_samples", 0),
                    "baseline_status": baseline_check.get("baseline_status", 0),
                    "total_tests": baseline_check["total_tests"],
                },
            },
            "false_positive_reasons": false_positive_reasons,
            "recommendation": recommendation,
        }
