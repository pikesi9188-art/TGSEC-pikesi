---
name: 炼法骨架
description: >-
  大爱仙尊·漏洞利用框架：栈溢出/堆利用/ROP/内核利用/浏览器利用/沙箱逃逸/VM逃逸/2026 PAC绕过/AI辅助ROP/shellcode
---

# exploit-development-framework（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/exploit-development-framework/SKILL.md`
- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name exploit-development-framework`

---

长文超过 1800 行，作业时 Read 真源全文，不要凭记忆。

# Exploit Development Framework

## 概述

本技能是漏洞利用开发的全栈框架，覆盖从用户态应用到内核态、从浏览器到虚拟机逃逸、从传统二进制利用到2026年AI辅助攻击的完整技术栈。适用于CTF竞赛、安全研究、漏洞验证和红队渗透测试中的漏洞利用环节。

---

## 第一部分：漏洞类别深度分析

### 1.1 栈溢出 (Stack Buffer Overflow)

栈溢出是最经典的二进制漏洞类型，至今仍广泛存在于各类软件中。

**原理：** 当程序向栈上分配的缓冲区写入超过其大小的数据时，会覆盖栈上的其他数据，包括返回地址、保存的基指针、局部变量等。

**漏洞示例代码：**

```c
// vulnerable_stack.c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // 无边界检查
    printf("Buffer: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    vulnerable_function(argv[1]);
    return 0;
}
```

**栈布局分析：**

```
高地址
+------------------+
|    argv[1]       |  <- 输入数据
+------------------+
|   返回地址        |  <- 被覆盖目标
+------------------+
|   保存的 RBP      |  <- 被覆盖
+------------------+
|   buffer[64]     |  <- 缓冲区起始
+------------------+
|   ...            |
低地址
```

**经典利用方法：**

```python
# exploit_stack.py
from pwn import *

# 确定偏移
pattern = cyclic(128)
# 发送pattern，观察崩溃时RIP值，计算偏移
# cyclic_find(0x6161616c) -> 72

offset = 72
payload = b'A' * offset
payload += p64(0xdeadbeef)  # 覆盖返回地址
```

**2026年栈溢出新趋势：**
- 利用信号处理函数（sigreturn）中的栈帧进行ROP
- 结合CET影子栈绕过技术
- 利用内核栈溢出进行权限提升（CVE-2026-3142类漏洞）

### 1.2 堆溢出与Use-After-Free (UAF)

**堆溢出：** 堆上分配的缓冲区溢出，可覆盖相邻堆块的元数据或数据。

**现代堆分配器结构 (glibc 2.38+ ptmalloc)：**

…（其余见长文）
