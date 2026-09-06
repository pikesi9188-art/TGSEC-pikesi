---
name: 库府
description: >-
  大爱仙尊·数据库安全测试全栈：SQL注入/NoSQL注入/数据库配置审计/权限提升/数据库横向移动/存储过程后门/2026最新数据库攻击/云数据库安全/Redis/MongoD
  B/Elasticsearch/PostgreSQL/MySQL/Oracle/MSSQL/Cassandra
---

# database-security（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/database-security/SKILL.md`
- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name database-security`

---

长文超过 1800 行，作业时 Read 真源全文，不要凭记忆。

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

…（其余见长文）
