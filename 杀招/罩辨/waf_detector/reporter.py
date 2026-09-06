"""reporter.py — WAF 检测报告生成器

支持 JSON / HTML / Markdown / CSV / SARIF 五种格式输出。
所有实现仅依赖 Python 标准库，无需第三方包。

用法:
    from waf_detector.reporter import WAFReporter

    reporter = WAFReporter(format="html")
    report = reporter.generate(detection_result, output_file="report.html")
    report = reporter.generate_batch(results_list, output_file="batch_report.json")
"""

import csv
import io
import json
import os
from datetime import datetime
from html import escape as _html_escape


class WAFReporter:
    """多格式 WAF 检测报告生成器

    支持的格式:
        - json:  标准 JSON 格式，含缩进
        - html:  完整 HTML 报告，含 CSS 样式、表格、颜色编码
        - md:    Markdown 表格格式，适合 GitHub / 文档
        - csv:   标准 CSV，列为 target,waf_detected,waf_name,confidence,status_code,ip,cdn
        - sarif: SARIF 2.1.0 格式，用于 CI/CD 集成
    """

    TOOL_NAME = "WAF-Hunter"
    TOOL_VERSION = "2.0.0"
    TOOL_INFO_URI = "https://github.com/waf-hunter/waf-hunter"

    _SUPPORTED_FORMATS = {"json", "html", "md", "csv", "sarif"}

    def __init__(self, format="json"):
        """初始化报告生成器

        Args:
            format: 输出格式 (json/html/md/csv/sarif)
        """
        fmt = (format or "json").lower().strip()
        if fmt not in self._SUPPORTED_FORMATS:
            raise ValueError(
                f"不支持的格式: {format!r}，"
                f"支持: {', '.join(sorted(self._SUPPORTED_FORMATS))}"
            )
        self.format = fmt

    # ------------------------------------------------------------------ #
    #  公共 API
    # ------------------------------------------------------------------ #

    def generate(self, data: dict, output_file=None) -> str:
        """生成单目标报告

        Args:
            data:        单个检测结果字典
            output_file: 输出文件路径; None 则仅返回字符串

        Returns:
            报告内容字符串
        """
        if not isinstance(data, dict):
            raise TypeError("data 必须是 dict")
        content = self._dispatch([data])
        if output_file:
            self._write_file(output_file, content)
        return content

    def generate_batch(self, results: list, output_file=None) -> str:
        """生成批量报告

        Args:
            results:     检测结果列表
            output_file: 输出文件路径; None 则仅返回字符串

        Returns:
            报告内容字符串
        """
        if not isinstance(results, list):
            raise TypeError("results 必须是 list")
        content = self._dispatch(results)
        if output_file:
            self._write_file(output_file, content)
        return content

    # ------------------------------------------------------------------ #
    #  内部分发
    # ------------------------------------------------------------------ #

    def _dispatch(self, results: list) -> str:
        handlers = {
            "json": self._gen_json,
            "html": self._gen_html,
            "md": self._gen_md,
            "csv": self._gen_csv,
            "sarif": self._gen_sarif,
        }
        return handlers[self.format](results)

    # ------------------------------------------------------------------ #
    #  辅助方法
    # ------------------------------------------------------------------ #

    @staticmethod
    def _write_file(path: str, content: str):
        """写入文件，自动创建父目录"""
        directory = os.path.dirname(os.path.abspath(path))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)

    @staticmethod
    def _waf_name_to_str(name) -> str:
        """将 waf_name 字段统一转为字符串"""
        if name is None:
            return ""
        if isinstance(name, (list, tuple)):
            return "; ".join(str(n) for n in name if n)
        return str(name)

    @staticmethod
    def _calc_summary(results: list) -> dict:
        """计算汇总统计

        分区: waf_detected + no_waf + errors = total
        """
        total = len(results)
        detected = sum(1 for r in results if r.get("waf_detected"))
        errors = sum(1 for r in results if r.get("error"))
        not_detected = total - detected - errors

        waf_distribution = {}
        for r in results:
            if r.get("waf_detected") and r.get("waf_name"):
                name = r["waf_name"]
                if isinstance(name, (list, tuple)):
                    for n in name:
                        if n:
                            waf_distribution[str(n)] = waf_distribution.get(str(n), 0) + 1
                else:
                    waf_distribution[str(name)] = waf_distribution.get(str(name), 0) + 1

        rate = (detected / total * 100) if total > 0 else 0.0
        return {
            "total": total,
            "waf_detected": detected,
            "no_waf": not_detected,
            "errors": errors,
            "detection_rate": round(rate, 1),
            "waf_distribution": waf_distribution,
        }

    # ------------------------------------------------------------------ #
    #  JSON
    # ------------------------------------------------------------------ #

    def _gen_json(self, results: list) -> str:
        report = {
            "tool": self.TOOL_NAME,
            "version": self.TOOL_VERSION,
            "generated_at": datetime.now().isoformat(),
            "summary": self._calc_summary(results),
            "results": results,
        }
        return json.dumps(report, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------ #
    #  HTML
    # ------------------------------------------------------------------ #

    def _gen_html(self, results: list) -> str:
        summary = self._calc_summary(results)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        rows_html = []
        for r in results:
            detected = r.get("waf_detected", False)
            row_class = "waf-detected" if detected else "waf-none"
            waf_name = self._waf_name_to_str(r.get("waf_name"))
            confidence = r.get("confidence", "")
            status_code = r.get("status_code", "")
            ip = r.get("ip", "")
            cdn = r.get("cdn", "")
            if isinstance(cdn, bool):
                cdn = "Yes" if cdn else "No"
            target = _html_escape(str(r.get("target", "")))
            error = _html_escape(str(r.get("error", ""))) if r.get("error") else ""

            status_cell = f'<span class="badge {"badge-detected" if detected else "badge-none"}">{"DETECTED" if detected else "NONE"}</span>'
            error_cell = f'<span class="error-text">{error}</span>' if error else ""

            rows_html.append(
                f"""                <tr class="{row_class}">
                    <td>{target}</td>
                    <td>{status_cell}</td>
                    <td>{_html_escape(waf_name)}</td>
                    <td>{confidence}</td>
                    <td>{status_code}</td>
                    <td>{_html_escape(str(ip))}</td>
                    <td>{cdn}</td>
                    <td>{error_cell}</td>
                </tr>"""
            )

        rows_html_str = "\n".join(rows_html) if rows_html else ""
        distribution_rows = ""
        if summary["waf_distribution"]:
            distribution_rows = "<h3>WAF 分布</h3>\n<table>\n<tr><th>WAF 名称</th><th>数量</th></tr>\n"
            for name, count in sorted(
                summary["waf_distribution"].items(), key=lambda x: -x[1]
            ):
                distribution_rows += (
                    f"<tr><td>{_html_escape(name)}</td><td>{count}</td></tr>\n"
                )
            distribution_rows += "</table>\n"

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF 检测报告 — {self.TOOL_NAME} v{self.TOOL_VERSION}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #f5f7fa;
            color: #2c3e50;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            padding: 30px 40px;
            border-radius: 12px;
            margin-bottom: 24px;
        }}
        .header h1 {{ font-size: 28px; margin-bottom: 8px; }}
        .header .meta {{ font-size: 14px; opacity: 0.9; }}
        .summary-cards {{
            display: flex;
            gap: 16px;
            margin-bottom: 24px;
            flex-wrap: wrap;
        }}
        .card {{
            flex: 1;
            min-width: 140px;
            background: #fff;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        .card .value {{ font-size: 32px; font-weight: 700; margin-bottom: 4px; }}
        .card .label {{ font-size: 13px; color: #7f8c8d; text-transform: uppercase; letter-spacing: 0.5px; }}
        .card.total .value {{ color: #3498db; }}
        .card.detected .value {{ color: #e74c3c; }}
        .card.none .value {{ color: #27ae60; }}
        .card.rate .value {{ color: #f39c12; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #fff;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        th {{
            background: #2c3e50;
            color: #fff;
            padding: 12px 14px;
            text-align: left;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        td {{ padding: 10px 14px; border-bottom: 1px solid #ecf0f1; font-size: 14px; }}
        tr.waf-detected {{ background: #fdf0f0; }}
        tr.waf-detected:hover {{ background: #fce5e5; }}
        tr.waf-none {{ background: #f0fdf4; }}
        tr.waf-none:hover {{ background: #e5fce9; }}
        tr:last-child td {{ border-bottom: none; }}
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-detected {{ background: #e74c3c; color: #fff; }}
        .badge-none {{ background: #27ae60; color: #fff; }}
        .error-text {{ color: #e74c3c; font-size: 12px; }}
        h3 {{ margin: 24px 0 10px; font-size: 18px; color: #2c3e50; }}
        .footer {{ margin-top: 24px; text-align: center; color: #95a5a6; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>WAF 检测报告</h1>
            <div class="meta">
                {self.TOOL_NAME} v{self.TOOL_VERSION} &nbsp;|&nbsp;
                生成时间: {now} &nbsp;|&nbsp;
                目标数: {summary['total']}
            </div>
        </div>

        <div class="summary-cards">
            <div class="card total">
                <div class="value">{summary['total']}</div>
                <div class="label">总目标数</div>
            </div>
            <div class="card detected">
                <div class="value">{summary['waf_detected']}</div>
                <div class="label">检测到 WAF</div>
            </div>
            <div class="card none">
                <div class="value">{summary['no_waf']}</div>
                <div class="label">无 WAF</div>
            </div>
            <div class="card rate">
                <div class="value">{summary['detection_rate']}%</div>
                <div class="label">检测率</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>目标</th>
                    <th>状态</th>
                    <th>WAF 名称</th>
                    <th>置信度</th>
                    <th>状态码</th>
                    <th>IP</th>
                    <th>CDN</th>
                    <th>错误</th>
                </tr>
            </thead>
            <tbody>
{rows_html_str}
            </tbody>
        </table>

        {distribution_rows}

        <div class="footer">
            Generated by {self.TOOL_NAME} v{self.TOOL_VERSION} &mdash; {now}
        </div>
    </div>
</body>
</html>"""

    # ------------------------------------------------------------------ #
    #  Markdown
    # ------------------------------------------------------------------ #

    def _gen_md(self, results: list) -> str:
        summary = self._calc_summary(results)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines = [
            f"# WAF 检测报告",
            "",
            f"> 工具: **{self.TOOL_NAME}** v{self.TOOL_VERSION}  ",
            f"> 生成时间: {now}  ",
            f"> 目标总数: {summary['total']}",
            "",
            "## 汇总统计",
            "",
            f"| 指标 | 值 |",
            f"|------|-----|",
            f"| 总目标数 | {summary['total']} |",
            f"| 检测到 WAF | {summary['waf_detected']} |",
            f"| 无 WAF | {summary['no_waf']} |",
            f"| 错误数 | {summary['errors']} |",
            f"| 检测率 | {summary['detection_rate']}% |",
            "",
        ]

        if summary["waf_distribution"]:
            lines.append("## WAF 分布")
            lines.append("")
            lines.append("| WAF 名称 | 数量 |")
            lines.append("|----------|------|")
            for name, count in sorted(
                summary["waf_distribution"].items(), key=lambda x: -x[1]
            ):
                lines.append(f"| {name} | {count} |")
            lines.append("")

        lines.append("## 详细结果")
        lines.append("")
        lines.append("| 目标 | WAF 检测 | WAF 名称 | 置信度 | 状态码 | IP | CDN | 错误 |")
        lines.append("|------|----------|----------|--------|--------|----|-----|------|")

        for r in results:
            detected = "Yes" if r.get("waf_detected") else "No"
            waf_name = self._waf_name_to_str(r.get("waf_name"))
            confidence = r.get("confidence", "")
            status_code = r.get("status_code", "")
            ip = r.get("ip", "")
            cdn = r.get("cdn", "")
            if isinstance(cdn, bool):
                cdn = "Yes" if cdn else "No"
            target = str(r.get("target", ""))
            error = str(r.get("error", "")) if r.get("error") else ""

            # Escape pipe characters in markdown table
            target = target.replace("|", "\\|")
            waf_name = waf_name.replace("|", "\\|")
            error = error.replace("|", "\\|").replace("\n", " ")

            lines.append(
                f"| {target} | {detected} | {waf_name} | {confidence} | {status_code} | {ip} | {cdn} | {error} |"
            )

        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    #  CSV
    # ------------------------------------------------------------------ #

    def _gen_csv(self, results: list) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            ["target", "waf_detected", "waf_name", "confidence", "status_code", "ip", "cdn"]
        )
        for r in results:
            detected = "true" if r.get("waf_detected") else "false"
            waf_name = self._waf_name_to_str(r.get("waf_name"))
            confidence = r.get("confidence", "")
            status_code = r.get("status_code", "")
            ip = r.get("ip", "")
            cdn = r.get("cdn", "")
            if isinstance(cdn, bool):
                cdn = "true" if cdn else "false"
            writer.writerow(
                [r.get("target", ""), detected, waf_name, confidence, status_code, ip, cdn]
            )
        return output.getvalue()

    # ------------------------------------------------------------------ #
    #  SARIF 2.1.0
    # ------------------------------------------------------------------ #

    def _gen_sarif(self, results: list) -> str:
        rules = [
            {
                "id": "WAF001",
                "name": "WafDetected",
                "shortDescription": {"text": "检测到 Web 应用防火墙 (WAF)"},
                "fullDescription": {
                    "text": "目标站点部署了 Web 应用防火墙，可能影响安全测试和漏洞扫描。"
                },
                "defaultConfiguration": {"level": "warning"},
                "properties": {"tags": ["security", "waf", "recon"]},
            },
            {
                "id": "WAF002",
                "name": "NoWafDetected",
                "shortDescription": {"text": "未检测到 WAF"},
                "fullDescription": {
                    "text": "目标站点未检测到 Web 应用防火墙。"
                },
                "defaultConfiguration": {"level": "note"},
                "properties": {"tags": ["security", "waf", "recon"]},
            },
        ]

        sarif_results = []
        for r in results:
            detected = r.get("waf_detected", False)
            target = str(r.get("target", ""))
            waf_name = self._waf_name_to_str(r.get("waf_name"))
            confidence = r.get("confidence", 0)

            if detected:
                rule_id = "WAF001"
                level = "warning"
                message_text = f"检测到 WAF: {waf_name}"
                if confidence:
                    message_text += f" (置信度: {confidence}%)"
            else:
                rule_id = "WAF002"
                level = "note"
                message_text = "未检测到 WAF"

            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": message_text},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": target},
                            }
                        }
                    ],
                    "properties": {
                        "waf_detected": detected,
                        "waf_name": waf_name,
                        "confidence": confidence,
                        "status_code": r.get("status_code"),
                        "ip": r.get("ip", ""),
                        "cdn": r.get("cdn"),
                        "error": r.get("error", ""),
                    },
                }
            )

        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.TOOL_NAME,
                            "version": self.TOOL_VERSION,
                            "informationUri": self.TOOL_INFO_URI,
                            "rules": rules,
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }
        return json.dumps(sarif, indent=2, ensure_ascii=False)
