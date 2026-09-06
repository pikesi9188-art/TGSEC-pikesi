---
name: 坞壳落子猎
description: >-
 授权 WordPress 上狩猎已落地高熵 PHP 马：wp-includes / 站点根 11 位大小写混用 .php。
 
 只猎授权站；情报域名禁止扩权；随机文件名不当字典；授权内连马直接做。
---

# WP 高熵 PHP 马落点狩猎

## 真源

1. `传承/坞壳落子猎.md`
2. `python3 炼蛊房/shell_drop_intel.py ingest --file <清单.txt> --case <案卷>`
3. `python3 炼蛊房/shell_drop_intel.py hunt --url https://授权站 --case <案卷>`
4. 已拿 shell：`host_ir_check.py`（同一判定，已排除 `formatting.php` 误报）
5. 落点库：`python3 炼蛊房/wp_drop_lib.py --help`

## 强制

1. 目标在 `授权范围`。清单里的第三方 host **禁止** `--grant`。
2. ingest 只出统计 + 与 scope 重叠；hunt 只列目录筛文件名。
3. 11 位文件名不要 ffuf。命中只记存在性，连蚁剑/清马授权内直接做。
4. 博彩/假支付站若同时是 WP，本卡与业务专链并行，不替代。

---

## 一、高熵 PHP 马特征

```
命名模式：
 - 11位大小写混用：如 aBcDeFgHiJk.php / xYzAbCdEfGh.php
 - 8-12位随机字母数字：Abc123DeF.php / a1B2c3D4e.php
 - 全小写"合法"混入（非马）：formatting.php / functions.php（别误报）

落点目录（优先级顺序）：
 /wp-includes/ # 最常见落地目录，混入核心文件
 /wp-content/uploads/ # 上传目录，PHP执行取决于.htaccess
 /wp-content/themes/<theme>/ # 主题内隐藏
 /wp-content/plugins/<plugin>/ # 插件内隐藏
 /wp-admin/includes/ # 混入管理员文件夹
 / # 站点根目录

排除（非马）的常见11位文件：
 formatting.php / functions.php / theme-compat/
 load.php / class-wp.php（官方文件，全小写+连字符）
```

---

## 二、黑盒探测（无 shell，只验证存在性）

### 2.1 工具自动扫

```bash
# shell_drop_intel 自动探测（不爆破，只验已知路径）
python3 炼蛊房/shell_drop_intel.py hunt \
 --url https://<授权站> \
 --case <案卷> \
 --depth wp-includes,wp-content/uploads \
 --out 案卷/<案卷>/wp_shell/

# 导入情报清单（与 scope 交叉，自动过滤非授权域名）
python3 炼蛊房/shell_drop_intel.py ingest \
 --file /path/to/shell_paths.txt \
 --case <案卷>
```

### 2.2 手动 HEAD 验证（不拉响应体）

```bash
# 验证特定文件是否存在（HEAD 请求）
TARGETS=(
 "aBcDeFgHiJk.php"
 "xYzAbCdEfGh.php"
 "wp-includes/aBcDeFgHiJk.php"
)
BASE="https://<授权站>"

for t in "${TARGETS[@]}"; do
 CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 -I "$BASE/$t")
 echo "$CODE $BASE/$t"
done
```

### 2.3 wp-includes 文件列举（有目录列表时）

```bash
# 检查 wp-includes 是否开了目录列表
curl -sk https://<授权站>/wp-includes/ | grep -oE '"[a-zA-Z0-9]{8,14}\.php"' | sort -u

# 用 ffuf 扫特定目录（只用于已授权且确认有异常文件的情况）
# 注意：11 位随机文件不要当字典穷举，只验证情报清单中的路径
ffuf -u https://<授权站>/wp-includes/FUZZ \
 -w /path/to/known_shells.txt \
 -mc 200 -fc 403,404 -t 5 --timeout 10 2>/dev/null
```

---

## 三、白盒排查（已拿 shell）

### 3.1 文件系统扫描

```bash
# 在授权服务器上执行：扫高熵 PHP 文件
WP_ROOT="/var/www/html" # 替换为实际 WP 路径

# 方法1：按文件名模式匹配（11位大小写混用）
find "$WP_ROOT" -name "*.php" -type f 2>/dev/null | while read f; do
 basename=$(basename "$f" .php)
 # 检查：长度8-14，包含大写字母（排除全小写官方文件）
 if echo "$basename" | grep -qE '^[a-zA-Z0-9]{8,14}$' && \
 echo "$basename" | grep -qE '[A-Z]'; then
 echo "SUSPECT: $f"
 fi
done

# 方法2：按修改时间过滤（近30天新增的 PHP）
find "$WP_ROOT/wp-includes" "$WP_ROOT/wp-content/uploads" \
 -name "*.php" -newer /etc/passwd -type f 2>/dev/null \
 | grep -vE 'class-|functions|formatting|load|version' | head -30

# 方法3：按文件内容特征扫（eval/system/exec 等 webshell 关键词）
find "$WP_ROOT" -name "*.php" -type f 2>/dev/null \
 | xargs grep -lE 'eval\(base64_decode|system\(\$_|exec\(\$_|passthru\(\$_|assert\(\$_|\$_POST\[.{1,10}\]\(\$_|\$GLOBALS\[' 2>/dev/null \
 | grep -vE 'node_modules|vendor|test' | head -20
```

### 3.2 内容预览（只读，禁止执行）

```bash
# 查看可疑文件头部（不执行）
for f in $(find /var/www/html/wp-includes -name "*.php" -newer /etc/passwd 2>/dev/null | head -5); do
 echo "=== $f ==="
 head -10 "$f" 2>/dev/null
 echo "---"
done

# 对高熵文件做 strings 提取（不 source/include）
strings /var/www/html/wp-includes/<高熵文件名>.php | grep -iE 'cmd|shell|exec|system|base64|eval' | head -20

# 查看文件 hash（留证据）
md5sum /var/www/html/wp-includes/<高熵文件名>.php
sha256sum /var/www/html/wp-includes/<高熵文件名>.php
```

---

## 四、比对 WP 官方文件清单

```bash
# 下载官方 wp-includes 文件清单并比对
WP_VERSION=$(grep "'\$wp_version'" /var/www/html/wp-includes/version.php 2>/dev/null | grep -oE "[0-9]+\.[0-9]+(\.[0-9]+)?")
echo "WP Version: $WP_VERSION"

# 从 GitHub 拉取官方文件列表
curl -sk "https://api.github.com/repos/WordPress/WordPress/contents/wp-includes?ref=$WP_VERSION" \
 | python3 -c "
import json,sys
data = json.load(sys.stdin)
official = {f['name'] for f in data if isinstance(f,dict)}
print('Official files:', len(official))
" 2>/dev/null

# 本地列举并比对（需已有官方清单）
ls /var/www/html/wp-includes/*.php 2>/dev/null | xargs -I{} basename {} \
 | sort > /tmp/local_wp_includes.txt
# 差集 = 可疑文件
```

---

## 五、证据固化（命中后）

```bash
# 1. 记录文件信息（不删除、不连马）
SHELL_PATH="/var/www/html/wp-includes/<高熵文件>.php"
CASE_DIR="案卷/<案卷>/wp_shell"
mkdir -p "$CASE_DIR"

# 文件元信息
ls -la "$SHELL_PATH" > "$CASE_DIR/file_info.txt"
md5sum "$SHELL_PATH" >> "$CASE_DIR/file_info.txt"
stat "$SHELL_PATH" >> "$CASE_DIR/file_info.txt"

# 内容备份（取证，不执行）
cp "$SHELL_PATH" "$CASE_DIR/shell_backup.php.txt"

# 2. 更新 STATUS
echo "$(date) WP Shell found: $SHELL_PATH" >> "案卷/<案卷>/STATUS.md"

# 3. 连马操作：授权内直接做
echo "Shell found at $SHELL_PATH - connecting..."
```

---

## 六、HTTP 请求探针（验证马是否活跃）

```bash
# 只发GET请求验证响应（不发任何命令参数）
curl -sk https://<授权站>/wp-includes/<高熵文件名>.php \
 -o /dev/null -w "HTTP %{http_code} Size:%{size_download}\n" --max-time 15

# 200 + 小响应体（<500B）= 可能是马（等待参数）
# 200 + 大响应体 = 可能是内容型马或错误页
# 404 = 不存在或被删
# 403 = .htaccess 保护
```

---

## 七、成功口径

| 级别 | 条件 |
|------|------|
| L1 | 发现符合高熵命名规则的可疑 PHP 文件（存在性确认） |
| L2 | 内容确认含 webshell 特征代码（eval/system/\_POST 参数执行） |
| L3 | 连接成功执行命令并记录到证据（需用户明确授权） |
