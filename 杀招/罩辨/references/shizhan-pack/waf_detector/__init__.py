#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""waf_detector — WAF 检测与绕过工具核心数据层

提供 WAF 指纹数据库和绕过 Payload 库。

模块:
    - fingerprints: 150+ WAF 厂商指纹数据库
    - payloads: 333+ 绕过 Payload 库
"""

from .fingerprints import (
    WAF_FINGERPRINTS,
    get_stats as get_fingerprint_stats,
    get_wafs_by_category,
    get_all_waf_names,
    get_waf_fingerprint,
    get_all_categories,
    search_waf_by_cookie,
    search_waf_by_header,
    get_wafs_by_asn,
)

from .payloads import (
    BYPASS_PAYLOADS,
    ADVANCED_BYPASS_TECHNIQUES,
    get_payloads,
    get_payload_count,
    get_techniques,
    get_attack_types,
    get_supported_wafs,
    get_technique_details,
    get_payloads_by_technique,
    get_stats as get_payload_stats,
)

__version__ = "2.0.0"
__all__ = [
    # fingerprints
    "WAF_FINGERPRINTS",
    "get_fingerprint_stats",
    "get_wafs_by_category",
    "get_all_waf_names",
    "get_waf_fingerprint",
    "get_all_categories",
    "search_waf_by_cookie",
    "search_waf_by_header",
    "get_wafs_by_asn",
    # payloads
    "BYPASS_PAYLOADS",
    "ADVANCED_BYPASS_TECHNIQUES",
    "get_payloads",
    "get_payload_count",
    "get_techniques",
    "get_attack_types",
    "get_supported_wafs",
    "get_technique_details",
    "get_payloads_by_technique",
    "get_payload_stats",
]
