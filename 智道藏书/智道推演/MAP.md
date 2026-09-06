# 假设作业长文地图

作业入口：Skill `春秋蝉-账本` · `传承/东方长凡·推演.md`  
`python3 炼蛊房/hypothesis_route.py --signal "<词>"`  
医生：`python3 炼蛊房/hypothesis_route.py --doctor`（先命中先赢）  
蒸馏记录：`DISTILL.md`

| 长文 | 本库专卡 | 探针 |
|------|----------|------|
| `techniques/web.md` | `web-vuln-router` · `web-cache-poisoning` | `core_web_surface_probe.py` · `cache_poison_probe.py` |
| `techniques/新印.md` | `identity-federation` · `oauth2-password-grant-login-testing` | `jwt_gql_probe.py` |
| `techniques/recon.md` | `cdn-origin-tracing` | `origin_recon.py` |
| `techniques/cloud.md` | `cloud-k8s` / `cloud-metadata-harvesting` | `ssrf_probe.py` |
| `techniques/cloud-cn.md` | `cloud-metadata-harvesting` · 阿里云 AK-SK | `ssrf_probe.py` |
| `techniques/database.md` | `database-security` · `doris-unauth` | `middleware_unauth_probe.py` |
| `techniques/network-services.md` | `ad-windows-router` | `middleware_unauth_probe.py` |
| `techniques/code-audit.md` | `deepaudit-code-audit` | `tools/deepaudit/bin/da_pipeline.py` |
| `techniques/中原骨架.md` | 若依专卡；其余 `java_web --stack cnoa` + 用友致远 Playbook | `java_web_surface_probe.py` |
| `techniques/realworld-patterns.md` | 假支付 / `acg-faka` / `tg-cloud-panel` / Cognito | `pay_matrix.py` |
| `techniques/器物谱.md` | `1day-nuclei-kit` | `nday_route.py` |
| `techniques/reversing.md` | `reverse-engineering` | `reverse_skill_route.py` |
| `techniques/pwn.md` | `binary-pwn` | `tools/pwn-kit/pwn_triage.py` |
| `techniques/ad.md` | `ad-windows-router` | `ad_surface_check.py` |
| `techniques/evasion.md` | **只读** `edr-bypass-re` | `css_query.py` |
| `techniques/ai-llm.md` | `llm-security` | `llm_surface_probe.py` |
| `techniques/telegram.md` | `tg-cloud-panel` | `tg_cloud_panel_probe.py` |
| `techniques/cracking.md` | `auth-brute` | `auth_brute_probe.py` |
| `techniques/social-engineering.md` | `autonomous-social-engagement` | `social_engineer_agent.py` |
| `techniques/crypto-attacks.md` | `crypto-toolkit` | `crypto_decode.py` |
| `techniques/blockchain.md` | `defi-attack-patterns` | `css_query.py` |
| `techniques/forensic.md` | `digital-forensics` · `host-ir-check` | `host_ir_check.py` |

模板：`templates/finding-report.md` · `templates/engagement-report.md`（人类结论仍写 `STATUS.md`）  
降级盒：`tools/stdlib-kit/` · `stdlib_fallback.py`  
账本脚本以本库 `炼蛊房/case_ledger.py` 为准（案卷落到 `案卷/<案卷>/证据/`），不回退。
