# 漏洞报告复现验证技巧（实战提炼）

## 1. 响应字节数差值对比（识破错误复现描述）
场景：报告声称"密码X有效、Y无效"，两响应体大小不同（2802B vs 2809B）。
技巧：先算差值是否 = 参数长度差。例：admin(5) vs wrongpass123(12)，差7字节 = 密码长度差。
结论：两响应唯一区别是表单回显 value 长度 → **两个都被拒绝**，报告描述不准确。
教训：不要轻信报告结论，用字节差/字段回显推断真实逻辑。

## 2. 未授权访问验证优先级高于弱口令
报告描述"弱口令进入后台泄露PII"，实际 GET 目标 URL 无需任何参数直接返回数据。
技巧：先裸 GET 再 POST，先试无认证访问再试认证绕过——往往洞比报告说的更严重。

## 3. 遗留调试文件是金矿
PHP 老站常见攻击面（按价值排序）：
- `/test.php` `test/a.php`（phpinfo）→ 泄露版本/内部IP/危险配置（register_globals、disable_functions、open_basedir）
- `/manage/test.php` `backup/test.php` → 泄露绝对路径、迁移脚本、图片路径、业务ID
- robots.txt → 真实域名、虚拟主机名（sakura.ne.jp 等）
- 判断标准：`curl -s http://IP/xxx.php | head`，凡有 PHP 报错含绝对路径即信息泄露

## 4. 老 PHP 环境判断（5.2.x 时代）
- X-Powered-By: PHP/5.2.17 + nginx → Sakuraレンタルサーバー类虚拟主机特征
- magic_quotes_gpc=On → 常规单引号注入被转义，需宽字节(%df')或换注入点
- register_globals=On + 无 disable_functions → 一旦拿到写入点可直接 RCE

## 5. 日语 EUC-JP 编码站点处理
- 响应头 charset=euc-jp，必须 `iconv -f EUC-JP -t UTF-8` 转码才能读
- 错误提示特征词：「IDあるいはPASSWORDが不正です」「不正です」
- 区分成功/失败：grep 错误提示词，有=拒绝，无=可能通过

## 6. 时序侧信道验证要点
单次时序不可信（网络抖动±400ms），必须多次采样取均值；若均值差异 <50ms 视为无差异。
