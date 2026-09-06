---
name: 伤呈文
description: >-
  大爱仙尊·当用户发漏洞报告要求深度复现时使用。验证报告声明、扩展攻击面。
---

# vuln-report-reproduction（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/vuln-report-reproduction/SKILL.md`
- 手法：`传承/春秋蝉·分案.md`
- 工具：`python3 炼蛊房/kit_run.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name vuln-report-reproduction`

---

# 漏洞报告深度复现

触发词：深度复现、验证漏洞报告、按报告打这个站（有现成漏洞ID/复现步骤）。

## 核心铁律

1. **报告只是线索，不是结论**：复现时所有关键声明必须重新实测。实战案例：报告称"第一级密码 admin 有效"，实测 admin 被拒（返回「IDあるいはPASSWORDが不正です」）——但真正问题更严重：GET 后台页无需任何密码直接泄露员工名册。报告描述与现网状态常不符，但漏洞往往依然成立且更糟。
2. **字节差分法验证密码状态**：当登录响应回显密码值时，用不同长度密码对比响应字节数。若字节差=密码长度差，说明两密码被同样处理（如都被拒绝），唯一区别是回显值。例：admin(5字符) 2802B vs wrongpass123(12字符) 2809B，差7B=长度差 → admin 并未通过验证。
3. **跟随 302 与不跟随对比**：POST 302 响应体可能带错误提示，跟随后的 GET 页面可能清空错误。两者都要看，diff 才能定位真实差异。
4. **老站字符集解码**：日文站常为 charset=euc-jp，必须 `iconv -f EUC-JP -t UTF-8` 才能读内容。乱码页面先转码再 grep，否则漏掉关键信息。

## 标准流程

### 1. 验证报告核心声明
- 原样重放报告请求（POST/GET 参数、字段名、编码）
- 对照错误密码响应，用字节差分法判断密码真实状态
- 保存原始响应转码后 diff，找唯一差异点

### 2. 未授权直接访问测试
- 直接 GET 登录页/后台路径（无 cookie 无参数）——往往比报告更严重（零认证泄露）
- 提取完整泄露数据（名册/列表）存文件取证，标注人数/字段

### 3. 调试文件狩猎
旧 PHP 站（X-Powered-By: PHP/5.x）常残留调试文件：
- /test.php /test2.php /test3.php /test4.php
- /test/a.php /test/test.php
- /backup/test.php /manage/test.php
这些文件常泄露：数据库表结构（SHOW COLUMNS 输出）、phpinfo、绝对路径、图片路径、业务ID。逐一 curl 查看，不只看状态码。

### 4. phpinfo 关键配置提取
- disable_functions / open_basedir（空=拿到写入点可 RCE）
- register_globals=On（变量覆盖风险）
- display_errors=On（信息泄露）
- SERVER_ADDR（内网IP）、DOCUMENT_ROOT、SCRIPT_FILENAME（绝对路径）

### 5. 第二级认证/密码测试
- 两级登录：第一级共享密码→员工/用户选择→第二级密码
- 系统管理员 ID 常为 32767（日本系统常见）
- 字典：admin/admin123/123456/0000 + 日本风格（toshiba、员工姓名、2024-2026年份）
- 注意失败锁定/验证码，控制爆破节奏

### 6. 注入测试
- magic_quotes_gpc=On 时试宽字节绕过（%df%27）
- 数值参数测 UNION/布尔盲注，对比响应字节数找差异
- 路径遍历（?file=/ ?page=/ ?f=/）

### 7. 时序侧信道验证
- 单次采样不可信（网络波动可达数百ms），必须≥10次采样取均值
- 实战：单次 admin 724ms vs wrong 419ms 看似差异，10次采样后 589 vs 594 无差异——虚假信号

### 8. 隐藏目录标记
403 的目录（/backup/、/manage/backup/、/phpmyadmin/、/common/）存在但不可列——记入攻击面，后续可文件名爆破突破。403 ≠ 404，区分对待。

## 取证与报告
- 所有 PII 数据存文件（如 /tmp/roster.txt）
- 报告区分三档：✅ 实测确认 / ⚠️ 报告与现网不符（附实测证据）/ 新增发现
- 未突破项如实标注，绝不编造成功

## 陷阱
- 响应大小差异 = 回显值长度差 ≠ 验证通过
- 乱码页面不转码直接 grep 会漏关键信息
- 302 的 Location 与 body 可能指向不同状态
- 调试文件可能被删/被加，每次重新枚举

参考案例：references/49.212.65.223-case.md（完整实战记录）
