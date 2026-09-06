#!/usr/bin/env python3
"""waf_hunter.py — WAF 检测与绕过 CLI 工具 v2.0

150+ WAF 厂商指纹 / 333+ Bypass Payload / 9维指纹检测 / 三重验证

Usage:
  python waf_hunter.py stats
  python waf_hunter.py detect -t https://example.com
  python waf_hunter.py detect -f targets.txt --concurrency 20 -o results.json
  python waf_hunter.py bypass -t https://example.com --waf cloudflare --attack sqli
  python waf_hunter.py full -t https://example.com --format html -o report.html
  python waf_hunter.py verify -t https://example.com
  python waf_hunter.py list [--category cloud]

管道模式:
  cat targets.txt | python waf_hunter.py detect --concurrency 10
  echo https://example.com | python waf_hunter.py detect
"""

import argparse
import asyncio
import csv
import io
import json
import os
import sys
from datetime import datetime

# --------------------------------------------------------------------------- #
#  路径设置 — 确保能找到 waf_detector 包
# --------------------------------------------------------------------------- #

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

# --------------------------------------------------------------------------- #
#  模块导入
# --------------------------------------------------------------------------- #

# 数据模块（无网络依赖，始终可用）
from waf_detector.fingerprints import (  # noqa: E402
    WAF_FINGERPRINTS,
    get_stats,
    get_wafs_by_category,
    get_all_waf_names,
)
from waf_detector.payloads import (  # noqa: E402
    BYPASS_PAYLOADS,
    get_payloads,
    get_payload_count,
    get_techniques,
)
from waf_detector.reporter import WAFReporter  # noqa: E402

# Payload 生成器（纯计算，通常无网络依赖）
try:
    from waf_detector.generator import WAFPayloadGenerator
    _HAS_GENERATOR = True
except Exception:
    _HAS_GENERATOR = False

# 网络模块（依赖 aiohttp）
try:
    from waf_detector.detector import WAFDetector
    from waf_detector.verifier import WAFVerifier
    _HAS_NETWORK = True
except Exception:
    _HAS_NETWORK = False


# --------------------------------------------------------------------------- #
#  常量
# --------------------------------------------------------------------------- #

__version__ = "2.0.0"
STATE_FILE = ".waf_hunter_state.json"
SUPPORTED_FORMATS = ["json", "html", "md", "csv", "sarif"]
ATTACK_TYPES = ["sqli", "xss", "lfi", "rce", "ssrf", "ssti", "cmdi"]


# --------------------------------------------------------------------------- #
#  ANSI 颜色
# --------------------------------------------------------------------------- #

class Color:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def _supports_color():
    """检测终端是否支持颜色输出"""
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_COLOR_OK = _supports_color()


def c(text, *colors):
    """为文本添加颜色"""
    if not _COLOR_OK or not colors:
        return text
    return "".join(colors) + str(text) + Color.RESET


def print_info(msg=""):
    print(msg)

def print_success(msg):
    print(f"{c('[+]', Color.GREEN, Color.BOLD)} {msg}")

def print_error(msg):
    print(f"{c('[-]', Color.RED, Color.BOLD)} {msg}", file=sys.stderr)

def print_warning(msg):
    print(f"{c('[!]', Color.YELLOW, Color.BOLD)} {msg}", file=sys.stderr)

def print_verbose(msg, verbose):
    if verbose:
        print(f"{c('[~]', Color.DIM)} {msg}")


def print_banner():
    """打印工具 Banner"""
    banner = r"""
 _      _  __   _  __   ____  _   _ ___
| | /| / |/ /  | |/_/ / __ \/ | / / __ \
| |/ |/ / / _>  <  / /_/ /| |/ / /_/ /
|__/|__/_/ /_/|_|  \____/ |___/\____/   v{}
""".format(__version__)
    print(c(banner, Color.CYAN, Color.BOLD))
    print(c("  WAF 检测与绕过工具 | 150+ WAF | 333+ Payload | 9维指纹 | 三重验证",
            Color.DIM))
    print()


# --------------------------------------------------------------------------- #
#  目标收集与处理
# --------------------------------------------------------------------------- #

def normalize_target(target):
    """规范化目标 URL，确保有 scheme"""
    target = target.strip()
    if not target:
        return None
    # 去除可能的协议前缀空格
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    return target


def collect_targets(args):
    """从 -t / -f / stdin 收集目标列表"""
    targets = []

    # 单目标
    single = getattr(args, "target", None)
    if single:
        t = normalize_target(single)
        if t:
            targets.append(t)

    # 文件
    file_path = getattr(args, "file", None)
    if file_path:
        if not os.path.isfile(file_path):
            print_error(f"目标文件不存在: {file_path}")
            return targets
        with open(file_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    t = normalize_target(line)
                    if t:
                        targets.append(t)

    # stdin 管道模式（当没有 -t 和 -f，且 stdin 不是终端时）
    if not targets and not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith("#"):
                t = normalize_target(line)
                if t:
                    targets.append(t)

    # 去重并保持顺序
    seen = set()
    unique = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)

    return unique


def validate_proxy(proxy):
    """验证并规范化代理地址"""
    if not proxy:
        return None
    proxy = proxy.strip()
    if proxy.startswith(("http://", "https://", "socks5://", "socks4://")):
        return proxy
    # 默认使用 http
    return f"http://{proxy}"


# --------------------------------------------------------------------------- #
#  断点续扫状态管理
# --------------------------------------------------------------------------- #

def save_state(command, all_targets, results):
    """保存扫描状态到文件"""
    state = {
        "command": command,
        "timestamp": datetime.now().isoformat(),
        "targets": all_targets,
        "results": results,
    }
    try:
        state_path = os.path.join(os.getcwd(), STATE_FILE)
        with open(state_path, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, ensure_ascii=False)
    except Exception:
        pass


def load_state():
    """加载扫描状态"""
    state_path = os.path.join(os.getcwd(), STATE_FILE)
    if not os.path.isfile(state_path):
        return None
    try:
        with open(state_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def clear_state():
    """清除扫描状态文件"""
    state_path = os.path.join(os.getcwd(), STATE_FILE)
    try:
        if os.path.isfile(state_path):
            os.remove(state_path)
    except Exception:
        pass


# --------------------------------------------------------------------------- #
#  进度显示
# --------------------------------------------------------------------------- #

def _waf_name_str(result):
    """从结果中提取 WAF 名称字符串"""
    name = result.get("waf_name", "")
    if isinstance(name, (list, tuple)):
        return "; ".join(str(n) for n in name if n)
    return str(name) if name else ""


def print_progress(current, total, result, verbose=False):
    """打印单个目标的检测进度"""
    target = result.get("target", "?")
    detected = result.get("waf_detected", False)
    error = result.get("error")

    if error:
        status = c(f"ERROR: {error}", Color.RED)
    elif detected:
        waf = _waf_name_str(result)
        conf = result.get("confidence", "")
        conf_str = f" ({conf}%)" if conf else ""
        status = c(f"WAF: {waf}{conf_str}", Color.RED, Color.BOLD)
    else:
        status = c("No WAF", Color.GREEN)

    prefix = c(f"[{current}/{total}]", Color.CYAN, Color.BOLD)
    print(f"  {prefix} {target:50s} → {status}")

    if verbose and detected:
        # 详细信息
        status_code = result.get("status_code", "")
        ip = result.get("ip", "")
        cdn = result.get("cdn", "")
        fingerprints = result.get("fingerprints_matched", [])
        if status_code:
            print(f"         Status: {status_code}")
        if ip:
            print(f"         IP: {ip}  CDN: {cdn}")
        if fingerprints:
            print(f"         Fingerprints: {', '.join(fingerprints[:5])}")


def print_summary(results):
    """打印批量扫描汇总"""
    total = len(results)
    detected = sum(1 for r in results if r.get("waf_detected"))
    no_waf = sum(1 for r in results if not r.get("waf_detected") and not r.get("error"))
    errors = sum(1 for r in results if r.get("error"))
    rate = (detected / total * 100) if total > 0 else 0.0

    line = c("━" * 50, Color.DIM)
    print()
    print(line)
    print(c(f"  扫描完成: {total}/{total}", Color.BOLD))
    print(f"    {c('WAF 检测:', Color.RED)}   {detected}")
    print(f"    {c('无 WAF:', Color.GREEN)}    {no_waf}")
    if errors:
        print(f"    {c('错误:', Color.YELLOW)}      {errors}")
    print(f"    检测率:  {rate:.1f}%")
    print(line)
    print()

    # WAF 分布
    waf_dist = {}
    for r in results:
        if r.get("waf_detected"):
            name = _waf_name_str(r)
            if name:
                waf_dist[name] = waf_dist.get(name, 0) + 1

    if waf_dist:
        print(c("  WAF 分布:", Color.BOLD))
        for name, count in sorted(waf_dist.items(), key=lambda x: -x[1]):
            bar = c("█" * count, Color.RED)
            print(f"    {name:30s} {bar} {count}")
        print()


# --------------------------------------------------------------------------- #
#  异步检测运行器
# --------------------------------------------------------------------------- #

async def run_detection(targets, args, command_name="detect"):
    """并发执行 WAF 检测

    Args:
        targets:      目标 URL 列表
        args:         argparse 参数对象
        command_name: 命令名称（用于状态保存）

    Returns:
        检测结果列表
    """
    if not _HAS_NETWORK:
        print_error("网络检测模块不可用，请安装依赖: pip install aiohttp")
        return []

    concurrency = getattr(args, "concurrency", 10) or 10
    proxy = validate_proxy(getattr(args, "proxy", None))
    insecure = getattr(args, "insecure", False)
    rate_limit = getattr(args, "rate", None)

    # 创建检测器
    detector = WAFDetector(
        proxy=proxy,
        insecure=insecure,
        rate_limit=rate_limit,
    )

    semaphore = asyncio.Semaphore(concurrency)
    results = []
    total = len(targets)
    completed = 0
    lock = asyncio.Lock()

    # 断点续扫
    existing_results = []
    if getattr(args, "resume", False):
        state = load_state()
        if state and state.get("results"):
            existing_results = state["results"]
            completed_targets = {r.get("target") for r in existing_results}
            targets = [t for t in targets if t not in completed_targets]
            if existing_results:
                print_info(
                    c(f"  断点续扫: 已完成 {len(existing_results)} 个目标，"
                      f"剩余 {len(targets)} 个",
                      Color.YELLOW)
                )
            if not targets:
                print_success("所有目标已完成，无需续扫")
                return existing_results

    total = len(targets)
    if total == 0:
        return existing_results

    print_info(c(f"  开始检测 {total} 个目标 (并发: {concurrency})...\n", Color.DIM))

    async def detect_one(target):
        nonlocal completed
        async with semaphore:
            try:
                result = await detector.detect(target)
            except asyncio.TimeoutError:
                result = {
                    "target": target,
                    "waf_detected": False,
                    "error": "请求超时",
                }
            except Exception as e:
                error_type = type(e).__name__
                result = {
                    "target": target,
                    "waf_detected": False,
                    "error": f"{error_type}: {e}",
                }

            async with lock:
                results.append(result)
                completed += 1
                print_progress(completed, total, result, getattr(args, "verbose", False))

                # 定期保存状态
                if completed % 10 == 0:
                    save_state(command_name, targets, existing_results + results)

    tasks = [detect_one(t) for t in targets]
    await asyncio.gather(*tasks)

    # 合并已有结果
    all_results = existing_results + results

    # 扫描完成，清除状态
    clear_state()

    return all_results


# --------------------------------------------------------------------------- #
#  命令实现
# --------------------------------------------------------------------------- #

def cmd_stats(args):
    """显示指纹库统计"""
    print_banner()

    stats = get_stats()
    payload_count = get_payload_count()
    try:
        techniques = get_techniques()
    except Exception:
        techniques = []

    all_names = get_all_waf_names()
    total_wafs = len(all_names) if all_names else 0

    # 如果 stats 中有 total，优先使用
    if isinstance(stats, dict):
        for key in ("total", "total_wafs", "waf_count"):
            if key in stats and isinstance(stats[key], int):
                total_wafs = stats[key]
                break

    print(c("  ╔══════════════════════════════════════╗", Color.CYAN))
    print(c("  ║       WAF 指纹库统计                  ║", Color.CYAN))
    print(c("  ╚══════════════════════════════════════╝", Color.CYAN))
    print()
    print(f"    {c('WAF 总数:', Color.BOLD)}     {c(str(total_wafs), Color.GREEN, Color.BOLD)}")
    print(f"    {c('Payload 数:', Color.BOLD)}   {c(str(payload_count), Color.GREEN, Color.BOLD)}")
    if techniques:
        print(f"    {c('绕过技术数:', Color.BOLD)}  {c(str(len(techniques)), Color.GREEN, Color.BOLD)}")
    print()

    # 分类统计
    if isinstance(stats, dict):
        cat_data = None
        for key in ("categories", "by_category", "category_stats"):
            if key in stats and isinstance(stats[key], dict):
                cat_data = stats[key]
                break

        if cat_data:
            print(c("  分类统计:", Color.BOLD))
            print()
            for cat, count in sorted(cat_data.items(), key=lambda x: -x[1]):
                bar = c("█" * min(count, 30), Color.BLUE)
                print(f"    {cat:25s} {bar} {count}")
            print()

        # 其他统计信息
        other_keys = [k for k in stats if k not in
                      ("total", "total_wafs", "waf_count", "categories",
                       "by_category", "category_stats")]
        if other_keys:
            print(c("  其他统计:", Color.BOLD))
            for key in other_keys:
                val = stats[key]
                if isinstance(val, (int, float, str)):
                    print(f"    {key}: {val}")
            print()

    print(c(f"  使用 '{'python waf_hunter.py list'}' 查看完整 WAF 列表", Color.DIM))


async def cmd_detect(args):
    """WAF 检测"""
    print_banner()

    targets = collect_targets(args)
    if not targets:
        print_error("未提供目标。使用 -t <URL> / -f <file> / 管道输入")
        return

    results = await run_detection(targets, args, "detect")

    if not results:
        print_error("未获取到检测结果")
        return

    # 终端汇总
    print_summary(results)

    # 文件输出
    output = getattr(args, "output", None)
    fmt = getattr(args, "format", "json")

    if output:
        reporter = WAFReporter(format=fmt)
        reporter.generate_batch(results, output_file=output)
        print_success(f"报告已保存: {output}")
    elif fmt != "json":
        # 非 JSON 格式且未指定输出文件时，打印到终端
        reporter = WAFReporter(format=fmt)
        content = reporter.generate_batch(results)
        print(content)


def cmd_bypass(args):
    """绕过 Payload 生成"""
    print_banner()

    if not _HAS_GENERATOR:
        print_error("Payload 生成器模块不可用")
        return

    generator = WAFPayloadGenerator()

    waf_name = getattr(args, "waf", None)
    attack = getattr(args, "attack", "sqli")
    target = getattr(args, "target", None)

    print_info(c("  绕过 Payload 生成", Color.CYAN, Color.BOLD))
    print(f"    {c('WAF:', Color.BOLD)}     {waf_name or '通用'}")
    print(f"    {c('攻击类型:', Color.BOLD)} {attack}")
    if target:
        print(f"    {c('目标:', Color.BOLD)}   {target}")
    print()

    # 生成 payload — 尝试多种调用方式
    payloads = None
    errors = []
    call_attempts = [
        lambda: generator.generate(waf_name=waf_name, attack_type=attack),
        lambda: generator.generate(waf_name, attack),
        lambda: generator.generate(),
        lambda: generator.generate(attack_type=attack),
    ]
    for attempt in call_attempts:
        try:
            payloads = attempt()
            if payloads is not None:
                break
        except TypeError as e:
            errors.append(str(e))
        except Exception:
            pass

    if payloads is None:
        print_error(f"生成器调用失败: {errors}")
        return

    if not payloads:
        print_warning("未生成任何 payload")
        return

    print_success(f"生成 {len(payloads)} 个绕过 payload:\n")

    # 终端输出
    for i, p in enumerate(payloads, 1):
        print(f"    {c(f'{i:3d}.', Color.DIM)} {p}")
    print()

    # 文件输出
    output = getattr(args, "output", None)
    fmt = getattr(args, "format", "json")

    if output:
        content = _format_bypass_output(target, waf_name, attack, payloads, fmt)
        _write_output(output, content)
        print_success(f"已保存: {output}")
    elif fmt != "json":
        content = _format_bypass_output(target, waf_name, attack, payloads, fmt)
        print(content)


async def cmd_full(args):
    """完整流程: 检测 + 绕过 + 报告"""
    print_banner()

    targets = collect_targets(args)
    if not targets:
        print_error("未提供目标。使用 -t <URL> / -f <file> / 管道输入")
        return

    print_info(c("  [1/3] WAF 检测", Color.CYAN, Color.BOLD))
    results = await run_detection(targets, args, "full")

    if not results:
        print_error("未获取到检测结果")
        return

    print_summary(results)

    # 对检测到 WAF 的目标生成绕过 payload
    if _HAS_GENERATOR:
        print_info(c("  [2/3] 绕过 Payload 生成", Color.CYAN, Color.BOLD))
        generator = WAFPayloadGenerator()

        for result in results:
            if result.get("waf_detected"):
                waf = _waf_name_str(result)
                target = result.get("target", "")

                # 尝试生成 payload
                payloads = None
                for attempt in [
                    lambda: generator.generate(waf_name=waf, attack_type="sqli"),
                    lambda: generator.generate(waf, "sqli"),
                    lambda: generator.generate(),
                ]:
                    try:
                        payloads = attempt()
                        if payloads:
                            break
                    except (TypeError, Exception):
                        continue

                if payloads:
                    result["bypass_payloads"] = payloads
                    print_info(
                        f"    {target} → {c(waf, Color.RED)}: "
                        f"{len(payloads)} 个 payload"
                    )
                    if getattr(args, "verbose", False):
                        for i, p in enumerate(payloads[:5], 1):
                            print(f"      {i}. {p}")
                        if len(payloads) > 5:
                            print(f"      ... 共 {len(payloads)} 个")
        print()
    else:
        print_warning("Payload 生成器不可用，跳过绕过 payload 生成")

    # 生成报告
    print_info(c("  [3/3] 报告生成", Color.CYAN, Color.BOLD))
    fmt = getattr(args, "format", "html")
    output = getattr(args, "output", None)

    reporter = WAFReporter(format=fmt)

    if output:
        reporter.generate_batch(results, output_file=output)
        print_success(f"报告已保存: {output}")
    else:
        content = reporter.generate_batch(results)
        print(content)


async def cmd_verify(args):
    """误报验证"""
    print_banner()

    if not _HAS_NETWORK:
        print_error("网络验证模块不可用，请安装依赖: pip install aiohttp")
        return

    target = normalize_target(getattr(args, "target", None))
    if not target:
        print_error("请使用 -t 指定目标")
        return

    proxy = validate_proxy(getattr(args, "proxy", None))
    insecure = getattr(args, "insecure", False)
    rate_limit = getattr(args, "rate", None)

    print_info(c("  误报验证", Color.CYAN, Color.BOLD))
    print(f"    {c('目标:', Color.BOLD)} {target}")
    print()

    # 第一步：检测
    print_verbose("执行初始检测...", getattr(args, "verbose", False))
    detector = WAFDetector(proxy=proxy, insecure=insecure, rate_limit=rate_limit)

    detection_result = None
    try:
        detection_result = await detector.detect(target)
    except Exception as e:
        print_error(f"检测失败: {type(e).__name__}: {e}")
        return

    detected = detection_result.get("waf_detected", False)
    waf = _waf_name_str(detection_result)

    if detected:
        print_success(f"检测到 WAF: {c(waf, Color.RED)}")
    else:
        print_info(c("未检测到 WAF", Color.GREEN))
        return

    # 第二步：验证
    print_verbose("执行三重验证...", getattr(args, "verbose", False))
    verifier = WAFVerifier(proxy=proxy, insecure=insecure, rate_limit=rate_limit)

    verification = None
    # 尝试多种调用方式
    for attempt in [
        lambda: verifier.verify(target, detection_result),
        lambda: verifier.verify(target),
        lambda: verifier.verify(target=target, detection_result=detection_result),
    ]:
        try:
            verification = await attempt()
            if verification is not None:
                break
        except TypeError:
            continue
        except Exception as e:
            print_error(f"验证失败: {type(e).__name__}: {e}")
            return

    if verification is None:
        print_error("验证模块调用失败")
        return

    # 输出验证结果
    print()
    print(c("  ┌─────────────────────────────────┐", Color.CYAN))
    print(c("  │          验证结果                │", Color.CYAN))
    print(c("  └─────────────────────────────────┘", Color.CYAN))
    print()

    verified = verification.get("verified", False)
    if verified:
        print_success(f"验证通过: WAF 确认为 {c(_waf_name_str(verification), Color.RED)}")
    else:
        print_warning("验证未通过: 可能存在误报")

    # 打印详细信息
    for key in ("confidence", "methods", "tests", "details", "original_waf",
                "verified_waf", "false_positive"):
        if key in verification:
            val = verification[key]
            if isinstance(val, (list, tuple)):
                print(f"    {key}:")
                for item in val:
                    print(f"      - {item}")
            elif isinstance(val, dict):
                print(f"    {key}:")
                for k, v in val.items():
                    print(f"      {k}: {v}")
            else:
                print(f"    {key}: {val}")

    # 文件输出
    output = getattr(args, "output", None)
    fmt = getattr(args, "format", "json")

    if output:
        report_data = {
            "target": target,
            "detection": detection_result,
            "verification": verification,
        }
        reporter = WAFReporter(format=fmt)
        reporter.generate(report_data, output_file=output)
        print_success(f"验证报告已保存: {output}")


def cmd_list(args):
    """列出所有 WAF"""
    print_banner()

    category = getattr(args, "category", None)

    if category:
        print_info(c(f"  分类 '{category}' 下的 WAF:", Color.CYAN, Color.BOLD))
        print()
        wafs = get_wafs_by_category(category)
        if not wafs:
            print_warning(f"分类 '{category}' 下无 WAF 或分类不存在")
            # 显示可用分类
            stats = get_stats()
            if isinstance(stats, dict):
                for key in ("categories", "by_category", "category_stats"):
                    if key in stats and isinstance(stats[key], dict):
                        print_info(f"  可用分类: {', '.join(stats[key].keys())}")
                        break
            return

        # 处理返回值可能是名称列表或指纹字典列表
        if isinstance(wafs, dict):
            items = list(wafs.values())
        elif isinstance(wafs, (list, tuple)):
            items = list(wafs)
        else:
            items = []

        for item in items:
            if isinstance(item, dict):
                name = item.get("name", "?")
                desc = item.get("description", item.get("vendor", ""))
                if desc:
                    print(f"    {c(name, Color.GREEN)} — {desc}")
                else:
                    print(f"    {c(name, Color.GREEN)}")
            elif isinstance(item, str):
                print(f"    {c(item, Color.GREEN)}")
        print()
        print_info(f"  共 {len(items)} 个 WAF")
    else:
        names = get_all_waf_names()
        if not names:
            print_warning("指纹库为空")
            return

        names_list = sorted(names) if not isinstance(names, dict) else sorted(names.keys())

        print_info(c(f"  所有 WAF ({len(names_list)}):", Color.CYAN, Color.BOLD))
        print()

        # 按首字母分组
        current_letter = ""
        for name in names_list:
            if isinstance(name, dict):
                name = name.get("name", "?")
            letter = name[0].upper() if name else "?"
            if letter != current_letter:
                current_letter = letter
                print(f"  {c(f'--- {letter} ---', Color.DIM)}")
            print(f"    {c(name, Color.GREEN)}")
        print()
        print_info(f"  共 {len(names_list)} 个 WAF")
        print()
        print(c("  使用 '--category <name>' 按分类过滤", Color.DIM))

        # 显示可用分类
        stats = get_stats()
        if isinstance(stats, dict):
            for key in ("categories", "by_category", "category_stats"):
                if key in stats and isinstance(stats[key], dict):
                    cats = list(stats[key].keys())
                    if cats:
                        print(c(f"  可用分类: {', '.join(cats)}", Color.DIM))
                    break


# --------------------------------------------------------------------------- #
#  Bypass 输出格式化
# --------------------------------------------------------------------------- #

def _format_bypass_output(target, waf_name, attack, payloads, fmt):
    """格式化绕过 payload 输出"""
    if fmt == "json":
        data = {
            "tool": "WAF-Hunter",
            "version": __version__,
            "generated_at": datetime.now().isoformat(),
            "target": target or "",
            "waf": waf_name or "generic",
            "attack": attack,
            "payload_count": len(payloads),
            "payloads": payloads,
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    elif fmt == "md":
        lines = [
            "# WAF 绕过 Payload",
            "",
            f"- **目标**: {target or 'N/A'}",
            f"- **WAF**: {waf_name or '通用'}",
            f"- **攻击类型**: {attack}",
            f"- **Payload 数**: {len(payloads)}",
            "",
            "| # | Payload |",
            "|---|---------|",
        ]
        for i, p in enumerate(payloads, 1):
            escaped = p.replace("|", "\\|").replace("`", "\\`")
            lines.append(f"| {i} | `{escaped}` |")
        lines.append("")
        return "\n".join(lines)

    elif fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["target", "waf", "attack", "payload"])
        for p in payloads:
            writer.writerow([target or "", waf_name or "", attack, p])
        return output.getvalue()

    elif fmt == "html":
        rows = ""
        for i, p in enumerate(payloads, 1):
            from html import escape
            rows += (
                f"                <tr><td>{i}</td>"
                f"<td><code>{escape(p)}</code></td></tr>\n"
            )
        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>WAF 绕过 Payload — WAF-Hunter</title>
    <style>
        body {{ font-family: monospace; padding: 30px; background: #1e1e2e; color: #cdd6f4; }}
        h1 {{ color: #89b4fa; }}
        .info {{ color: #a6adc8; margin-bottom: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th {{ background: #313244; padding: 10px; text-align: left; color: #89b4fa; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #45475a; }}
        td:first-child {{ color: #fab387; width: 50px; }}
        code {{ color: #a6e3a1; word-break: break-all; }}
    </style>
</head>
<body>
    <h1>WAF 绕过 Payload</h1>
    <div class="info">
        目标: {target or 'N/A'}<br>
        WAF: {waf_name or '通用'}<br>
        攻击类型: {attack}<br>
        Payload 数: {len(payloads)}
    </div>
    <table>
        <thead><tr><th>#</th><th>Payload</th></tr></thead>
        <tbody>
{rows}        </tbody>
    </table>
</body>
</html>"""

    elif fmt == "sarif":
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "WAF-Hunter",
                        "version": __version__,
                        "rules": [{
                            "id": "BYPASS001",
                            "name": "BypassPayload",
                            "shortDescription": {"text": "WAF 绕过 Payload"},
                            "defaultConfiguration": {"level": "note"},
                        }]
                    }
                },
                "results": [
                    {
                        "ruleId": "BYPASS001",
                        "level": "note",
                        "message": {"text": f"绕过 payload: {p}"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": target or "N/A"}
                            }
                        }],
                        "properties": {
                            "waf": waf_name or "generic",
                            "attack": attack,
                            "payload": p,
                        },
                    }
                    for p in payloads
                ],
            }],
        }
        return json.dumps(sarif, indent=2, ensure_ascii=False)

    return "\n".join(payloads)


def _write_output(path, content):
    """写入输出文件，自动创建目录"""
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


# --------------------------------------------------------------------------- #
#  参数解析
# --------------------------------------------------------------------------- #

def build_parser():
    """构建 argparse 参数解析器"""
    parser = argparse.ArgumentParser(
        prog="waf_hunter",
        description=c("WAF 检测与绕过 CLI 工具", Color.CYAN, Color.BOLD)
                   + f" v{__version__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
示例:
  %(prog)s stats                                    显示指纹库统计
  %(prog)s detect -t https://example.com            检测单个目标
  %(prog)s detect -f targets.txt --concurrency 20   批量检测
  %(prog)s detect -f targets.txt -o results.json    检测并保存结果
  %(prog)s detect --format html -o report.html      生成 HTML 报告
  cat urls.txt | %(prog)s detect                    管道模式
  %(prog)s bypass -t https://example.com --waf cloudflare --attack sqli
  %(prog)s full -t https://example.com --format html -o report.html
  %(prog)s verify -t https://example.com            误报验证
  %(prog)s list                                     列出所有 WAF
  %(prog)s list --category cloud                    按分类列出
""",
    )

    # 通用参数 (网络相关)
    net_common = argparse.ArgumentParser(add_help=False)
    net_common.add_argument(
        "--proxy",
        help="代理地址 (http://host:port 或 socks5://host:port)",
    )
    net_common.add_argument(
        "--insecure",
        action="store_true",
        help="跳过 SSL 证书验证",
    )
    net_common.add_argument(
        "-r", "--rate",
        type=float,
        help="速率限制 (请求/秒)",
    )

    # 通用参数 (输出相关)
    out_common = argparse.ArgumentParser(add_help=False)
    out_common.add_argument(
        "--format",
        default="json",
        choices=SUPPORTED_FORMATS,
        help="输出格式 (默认: json)",
    )
    out_common.add_argument(
        "-o", "--output",
        help="输出文件路径 (自动创建目录)",
    )

    # 通用参数 (verbose)
    verbose_common = argparse.ArgumentParser(add_help=False)
    verbose_common.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="详细输出",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="子命令",
        metavar="{stats,detect,bypass,full,verify,list}",
    )

    # --- stats ---
    sp_stats = subparsers.add_parser(
        "stats",
        parents=[verbose_common],
        help="显示指纹库统计",
        description="显示 WAF 指纹库的统计信息，包括 WAF 总数、分类统计、Payload 数量等。",
    )

    # --- detect ---
    sp_detect = subparsers.add_parser(
        "detect",
        parents=[net_common, out_common, verbose_common],
        help="WAF 检测",
        description="对目标进行 WAF 检测。支持单目标、批量文件、stdin 管道输入。",
    )
    sp_detect.add_argument("-t", "--target", help="单个目标 URL")
    sp_detect.add_argument("-f", "--file", help="目标文件 (每行一个 URL)")
    sp_detect.add_argument(
        "--concurrency",
        type=int,
        default=10,
        help="并发数 (默认: 10)",
    )
    sp_detect.add_argument(
        "--resume",
        action="store_true",
        help="从上次中断处续扫",
    )

    # --- bypass ---
    sp_bypass = subparsers.add_parser(
        "bypass",
        parents=[net_common, out_common, verbose_common],
        help="绕过 Payload 生成",
        description="生成针对特定 WAF 的绕过 Payload。",
    )
    sp_bypass.add_argument("-t", "--target", help="目标 URL (可选)")
    sp_bypass.add_argument("--waf", help="WAF 名称 (如 cloudflare)")
    sp_bypass.add_argument(
        "--attack",
        default="sqli",
        choices=ATTACK_TYPES,
        help="攻击类型 (默认: sqli)",
    )

    # --- full ---
    sp_full = subparsers.add_parser(
        "full",
        parents=[net_common, out_common, verbose_common],
        help="完整流程 (检测+绕过+报告)",
        description="执行完整流程: WAF 检测 → 绕过 Payload 生成 → 报告输出。",
    )
    sp_full.add_argument("-t", "--target", help="单个目标 URL")
    sp_full.add_argument("-f", "--file", help="目标文件 (每行一个 URL)")
    sp_full.add_argument(
        "--concurrency",
        type=int,
        default=10,
        help="并发数 (默认: 10)",
    )
    sp_full.add_argument(
        "--resume",
        action="store_true",
        help="从上次中断处续扫",
    )

    # --- verify ---
    sp_verify = subparsers.add_parser(
        "verify",
        parents=[net_common, out_common, verbose_common],
        help="误报验证",
        description="对检测结果进行三重验证，降低误报率。",
    )
    sp_verify.add_argument("-t", "--target", required=True, help="目标 URL")

    # --- list ---
    sp_list = subparsers.add_parser(
        "list",
        parents=[verbose_common],
        help="列出所有 WAF",
        description="列出指纹库中的所有 WAF，支持按分类过滤。",
    )
    sp_list.add_argument(
        "--category",
        help="按分类过滤 (如 cloud, hardware, software)",
    )

    return parser


# --------------------------------------------------------------------------- #
#  主入口
# --------------------------------------------------------------------------- #

def main():
    """主入口函数"""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # 分发到对应命令
    if args.command == "stats":
        cmd_stats(args)
    elif args.command == "detect":
        asyncio.run(cmd_detect(args))
    elif args.command == "bypass":
        cmd_bypass(args)
    elif args.command == "full":
        asyncio.run(cmd_full(args))
    elif args.command == "verify":
        asyncio.run(cmd_verify(args))
    elif args.command == "list":
        cmd_list(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
