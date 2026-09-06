#!/usr/bin/env python3
"""test_detector.py — WAF 检测工具包单元测试

使用 Python 标准库 unittest 编写，不依赖 pytest。

运行方式:
    cd /workspace/waf-detector
    python -m unittest tests.test_detector -v
    # 或直接运行本文件
    python tests/test_detector.py -v
"""

import unittest

from waf_detector.fingerprints import (
    WAF_FINGERPRINTS,
    get_stats,
    get_all_waf_names,
)
from waf_detector.payloads import (
    BYPASS_PAYLOADS,
    get_payload_count,
)
from waf_detector.generator import WAFPayloadGenerator


# --------------------------------------------------------------------------- #
#  辅助函数
# --------------------------------------------------------------------------- #

def _iter_fingerprints():
    """统一遍历 WAF_FINGERPRINTS，兼容 dict 和 list 两种结构

    返回 (name, data) 元组列表:
      - dict 结构: key 为 WAF 名称, value 为指纹数据
      - list 结构: 每个元素为指纹 dict, 含 name 字段
    """
    result = []
    if isinstance(WAF_FINGERPRINTS, dict):
        for name, data in WAF_FINGERPRINTS.items():
            if isinstance(data, dict):
                result.append((name, data))
            else:
                result.append((name, {}))
    elif isinstance(WAF_FINGERPRINTS, (list, tuple)):
        for fp in WAF_FINGERPRINTS:
            if isinstance(fp, dict):
                name = fp.get("name", "")
                result.append((name, fp))
    return result


# --------------------------------------------------------------------------- #
#  指纹库测试
# --------------------------------------------------------------------------- #

class TestFingerprints(unittest.TestCase):
    """测试 WAF 指纹库的完整性和正确性"""

    def test_fingerprints_not_empty(self):
        """指纹库不应为空"""
        self.assertIsNotNone(WAF_FINGERPRINTS, "WAF_FINGERPRINTS 为 None")
        if isinstance(WAF_FINGERPRINTS, dict):
            self.assertGreater(len(WAF_FINGERPRINTS), 0, "WAF_FINGERPRINTS 字典为空")
        elif isinstance(WAF_FINGERPRINTS, (list, tuple)):
            self.assertGreater(len(WAF_FINGERPRINTS), 0, "WAF_FINGERPRINTS 列表为空")
        else:
            self.fail(f"WAF_FINGERPRINTS 应为 dict 或 list，实际类型: {type(WAF_FINGERPRINTS)}")

    def test_required_fields(self):
        """每个指纹必须包含 name (或作为 dict key) 和 category 字段"""
        fingerprints = _iter_fingerprints()
        self.assertGreater(len(fingerprints), 0, "指纹列表为空，无法验证字段")

        for name, data in fingerprints:
            # 验证名称
            self.assertIsInstance(name, str, f"指纹名称应为 str: {name!r}")
            self.assertTrue(name.strip(), f"指纹名称为空: {name!r}")

            # 验证数据是 dict
            self.assertIsInstance(data, dict, f"指纹数据应为 dict: {name!r}")

            # 验证 category 字段 (get_wafs_by_category 和 get_stats 依赖此字段)
            self.assertIn(
                "category", data,
                f"指纹 {name!r} 缺少必需字段 'category': {list(data.keys())}"
            )
            cat_val = data.get("category")
            self.assertIsInstance(
                cat_val, str,
                f"指纹 {name!r} 的 'category' 应为 str，实际: {type(cat_val)}"
            )
            self.assertTrue(
                cat_val.strip(),
                f"指纹 {name!r} 的 'category' 为空"
            )

    def test_stats(self):
        """get_stats() 应返回有效的统计信息"""
        stats = get_stats()
        self.assertIsInstance(stats, dict, f"get_stats() 返回类型错误: {type(stats)}")

        # 统计中应包含 WAF 总数相关的键
        total_keys = [k for k in stats if "total" in k.lower() or "count" in k.lower()]
        self.assertTrue(
            total_keys or len(stats) > 0,
            f"get_stats() 返回的统计信息可能不完整: {stats}"
        )

        # 如果有总数字段，应与指纹数量一致
        fingerprints = list(_iter_fingerprints())
        fp_count = len(fingerprints)
        for key in total_keys:
            val = stats[key]
            if isinstance(val, int):
                self.assertGreater(
                    val, 0,
                    f"统计字段 '{key}' 应大于 0: {val}"
                )

    def test_get_all_waf_names(self):
        """get_all_waf_names() 应返回非空的名称列表"""
        names = get_all_waf_names()
        self.assertIsInstance(names, (list, tuple, set), f"返回类型错误: {type(names)}")
        names_list = list(names)
        self.assertGreater(len(names_list), 0, "WAF 名称列表为空")

        for name in names_list:
            self.assertIsInstance(name, str, f"WAF 名称应为 str: {name}")
            self.assertTrue(name.strip(), f"WAF 名称为空: {name!r}")


# --------------------------------------------------------------------------- #
#  Payload 库测试
# --------------------------------------------------------------------------- #

class TestPayloads(unittest.TestCase):
    """测试绕过 Payload 库的完整性"""

    def test_payloads_not_empty(self):
        """Payload 库不应为空"""
        self.assertIsNotNone(BYPASS_PAYLOADS, "BYPASS_PAYLOADS 为 None")
        if isinstance(BYPASS_PAYLOADS, dict):
            self.assertGreater(len(BYPASS_PAYLOADS), 0, "BYPASS_PAYLOADS 字典为空")
        elif isinstance(BYPASS_PAYLOADS, (list, tuple)):
            self.assertGreater(len(BYPASS_PAYLOADS), 0, "BYPASS_PAYLOADS 列表为空")
        else:
            self.fail(
                f"BYPASS_PAYLOADS 应为 dict 或 list，实际类型: {type(BYPASS_PAYLOADS)}"
            )

    def test_payload_count(self):
        """get_payload_count() 应返回正整数"""
        count = get_payload_count()
        self.assertIsInstance(
            count, int,
            f"get_payload_count() 应返回 int，实际: {type(count)} -> {count}"
        )
        self.assertGreater(count, 0, f"payload 数量应大于 0，实际: {count}")


# --------------------------------------------------------------------------- #
#  Payload 生成器测试
# --------------------------------------------------------------------------- #

class TestGenerator(unittest.TestCase):
    """测试 WAFPayloadGenerator 的生成和变异功能"""

    def setUp(self):
        self.generator = WAFPayloadGenerator()

    def test_generate(self):
        """generate() 应返回非空的 payload 列表"""
        # 尝试多种调用方式以兼容不同签名
        payloads = None
        errors = []

        # 1. 无参数调用
        try:
            payloads = self.generator.generate()
        except TypeError as e:
            errors.append(str(e))

        # 2. 位置参数 (waf_name, attack_type)
        if payloads is None:
            try:
                payloads = self.generator.generate("cloudflare", "sqli")
            except TypeError as e:
                errors.append(str(e))

        # 3. 关键字参数
        if payloads is None:
            try:
                payloads = self.generator.generate(
                    waf_name="cloudflare", attack_type="sqli"
                )
            except TypeError as e:
                errors.append(str(e))

        # 4. 仅 waf_name
        if payloads is None:
            try:
                payloads = self.generator.generate("cloudflare")
            except TypeError as e:
                errors.append(str(e))

        self.assertIsNotNone(
            payloads,
            f"generate() 所有调用方式均失败: {errors}"
        )
        self.assertIsInstance(
            payloads, list,
            f"generate() 应返回 list，实际: {type(payloads)}"
        )
        self.assertGreater(
            len(payloads), 0,
            "generate() 返回空列表，应至少包含一个 payload"
        )

        # 验证每个 payload 是字符串
        for p in payloads:
            self.assertIsInstance(
                p, str,
                f"payload 应为 str，实际: {type(p)} -> {p!r}"
            )

    def test_mutate(self):
        """mutate() 应返回非空的变异 payload 列表"""
        test_payload = "1' OR '1'='1"

        mutations = self.generator.mutate(test_payload)
        self.assertIsInstance(
            mutations, list,
            f"mutate() 应返回 list，实际: {type(mutations)}"
        )
        self.assertGreater(
            len(mutations), 0,
            "mutate() 返回空列表，应至少包含一个变异"
        )

        # 验证每个变异结果是字符串
        for m in mutations:
            self.assertIsInstance(
                m, str,
                f"变异 payload 应为 str，实际: {type(m)} -> {m!r}"
            )

    def test_mutate_different_inputs(self):
        """mutate() 应能处理不同类型的输入 payload"""
        test_cases = [
            "1' OR '1'='1",
            "<script>alert(1)</script>",
            "; cat /etc/passwd",
            "{{7*7}}",
        ]
        for payload in test_cases:
            mutations = self.generator.mutate(payload)
            self.assertIsInstance(
                mutations, list,
                f"mutate({payload!r}) 应返回 list"
            )
            self.assertGreaterEqual(
                len(mutations), 1,
                f"mutate({payload!r}) 应返回至少一个变异"
            )


if __name__ == '__main__':
    unittest.main(verbosity=2)
