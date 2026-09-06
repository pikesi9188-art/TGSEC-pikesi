---
name: 译毒
description: >-
  大爱仙尊·给Web后台/网页/APK加中英语言切换。触发词：加多语言、语言切换、中英切换、i18n、界面翻译、把英文界面改中文。
---

# web-ui-i18n-injection（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/web-pentest/web-ui-i18n-injection/SKILL.md`
- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name web-ui-i18n-injection`

---

# Web 界面中英切换注入（不重build、不动业务逻辑）

> 给已部署的 Web 后台/HTML 页/Android APK 加"点一下切中文/英文"，只加文件不改业务逻辑，界面布局和功能完全不变。2026-08 在 vida C&C 面板实战验证。

## 适用形态判断（先看再动手）
| 形态 | 方案 | 是否需重build |
|---|---|---|
| React/Vue SPA 构建产物（web-dist/index.html + assets/*.js） | 注入 i18n.js 到 index.html | 否 |
| 静态 HTML（伪装页/引导页） | 注入 HTML 版 i18n 脚本 | 否 |
| 后端模板渲染（Jinja/PHP） | 同样 DOM 注入 或 后端变量 | 否 |
| Android APK（原生界面） | values-en/values-zh 资源 + 应用内切换 | 是（需重build APK） |
| 控制端 WebView 壳 APK | 不用改，继承 Web 后台的切换 | 否 |

## 一、SPA 构建产物注入（核心方案）
1. **写 i18n.js**（见 scripts/i18n_template.js）：词条表 `DICT{原文:{en,zh}}` + 浮动按钮 + DOM文本节点遍历替换 + MutationObserver 监听动态渲染 + localStorage 记忆语言
2. **改 index.html**：`</body>` 前加 `<script src="./assets/i18n.js"></script>`
3. **关键坑——静态挂载路径**：FastAPI 类后端常只 `app.mount("/assets", StaticFiles(directory=web-dist/assets))`，根目录文件访问 404 → i18n.js 必须放 **assets/** 下，引用写 `./assets/i18n.js`（2026-08 实测踩坑）
4. 验证：`curl /assets/i18n.js` = 200；node 模拟 translateText 逻辑测词条

## 二、词条提取流程（从打包JS批量提UI文案）
```python
# 提取 JS 字符串字面量后过滤：
# 1) 纯英文/葡语字符+常见标点，长度 3-80
# 2) 排除：驼峰图标名(AlertCircle)、Tailwind类名(bg-/text-/absolute等)、
#    React内部错误、HTTP头(Accept-Encoding)、协议错误
# 3) 排序翻译成 {"en": "...", "zh": "..."}
```
- 多词短语优先翻译；单词只挑真UI词（Login/Password/Online…）
- 界面可能实际是葡语等外语，老板常以为是英文 → 默认语言=en（原文→英文），切 zh→中文，最符合认知

## 三、i18n.js 翻译算法要点（坑）
- **词边界只挡字母 [a-z]，不挡数字**：`Dispositivos (3)` 要能翻译成 `设备 (3)`；用 `[a-z0-9]` 会挡住数字后缀 → 翻译失败（实测踩坑）
- 词条按**长度降序**匹配（长词优先），避免短词先吃掉长词
- 跳过 SCRIPT/STYLE/TEXTAREA/`data-i18n-skip` 节点（按钮自身不翻译）
- 短单词避免误伤："Save" 不替换 "Saved"（词边界正则解决）

## 四、静态 HTML 页注入
同一套逻辑，脚本塞进 `</body>` 前。词条覆盖该页可见文本（用 `grep -oE ">[^<>]{3,60}<"` 提取）。按钮样式适配移动端（WebView 场景）。

## 五、Android APK 原生界面
1. **资源多语言**：`res/values-en/strings.xml` + `res/values-zh-rCN/strings.xml`（复制 values/ 翻译全部 string）
2. **应用内切换**：LangHelper.java（AppCompatDelegate.setApplicationLocales + LocaleListCompat.forLanguageTags），`setContentView` **之前**调 `applySaved()`；toolbar 动态 addView 一个 TextView 按钮（"EN/中文"）点击 toggle + recreate
3. **WebView 壳控制端不用改**：加载后台 URL 即继承后台切换
4. APK 重构建需要 Android SDK + gradle wrapper（详见 references/vida-finalvnc-panel-deploy.md 的 SDK 安装与构建链）

## 交付纪律（老板红线）
- 改前先说明："只加文件不改业务逻辑，布局功能不变，只是文字变语言"
- 词条表人工翻译，不瞎翻；验证通过才报 ✅

## 支持文件
- `scripts/i18n_template.js` — SPA 注入脚本模板（词条表+按钮+翻译+MutationObserver）
- `references/vida-finalvnc-panel-deploy.md` — vida C&C 面板（FastAPI+React+AndroidRAT）部署与 APK 重建全流程
