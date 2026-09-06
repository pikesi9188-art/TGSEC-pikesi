# 大爱仙尊 39 模块分类目录

> 39 模块 / 195 技能  
> 本目录：`智道藏书/三十九门/`  
> 业务专链（假支付 / 芋道 / TG 号库）仍优先 `杀招/`，本包是**分类知识层**。  
> 查询：`python3 炼蛊房/css_query.py search --keyword 凭证` · `get --id 05-002`

## 模块对照

| # | 模块 | 本库 | 作业入口 |
|---|------|------|----------|
| 01 | 信息搜集 | 有 | Skill `棋道纵横` · `space_search.py` · `origin_recon` · `test_subdomain_enum` · `空间眼.md` · 九阶段 `recon-*` |
| 02 | 漏洞扫描 | 有 | Skill `一日针匣` · `auto_campaign.py` · `nday_route.py` · `pentest-swarm` |
| 03 | 漏洞利用 | 有且更强 | 假支付 / SQLi / XSS / 上传 / SSRF / 认证绕过均有专卡；Metasploit 上游全文在本模块 `skills/` |
| 04 | 权限提升 | 有 | `反客·总诀.md` · `linux_lpe_checker.py` · `windows_lpe_checker.py` · Skill `青丘` |
| 05 | 后渗透 | 有（知识卡已入库） | `linux-post-exploit` · `ad_surface_check.py` · 本模块 `skills/`（凭证转储 / 远程控制 / 键盘记录知识卡） |
| 06 | 横向移动 | 有 | `纵横天下.md` · `宗门·认族.md` · Skill `内地道` · `ad_surface_check.py` |
| 07 | 持久化 | 有（知识卡已入库） | 九阶段 `persistence-mechanisms` · 本模块 `skills/`（含 Bootkit 知识卡） |
| 08 | 痕迹清除 | 有（知识卡已入库） | `隐鳞·手册.md`（WAF/流量）· 本模块 `skills/`（AMSI/EDR / 进程注入知识卡） |
| 09 | 报告撰写 | 有 | 案卷 `STATUS.md` / `FULL_REPORT.md` · Skill `春秋蝉` |
| 10 | 移动安全 | 有（Android 强 / iOS 弱） | Skill `铁血冷·探路` · `apk-reverse` · `mobile-reverse` · `macos-reverse` |
| 11 | 无线安全 | 有知识 | Skill `无线` · `radio-sdr`；网站案默认降权 |
| 12 | 代码审计 | 有 | Skill `文审` · `autocve-cve-hunt` · `文审.md` |
| 13 | 逆向工程 | 有 | Skill `逆骨` · `ghidra-reverse` · `go-rust-reverse` · `binary-pwn` · `逆骨·认族.md` |
| 14 | 安全审计 | 部分 | 等保/架构审计以本模块上游卡为准；云/容器审计交叉 17/33 |
| 15 | 应急响应 | 有知识 | 九阶段 `incident-response` |
| 16 | 大模型安全 | 有 | `大灵.md` · `llm_surface_probe.py` · `灯笼·破印.md` |
| 17 | 云安全 | 有（阿里云强） | `云府·临钥.md` · Actuator 堆转云 · `定仙游·云骨.md` |
| 18 | 安全开发运维 | 部分 | TeamCity 杀伤链 · DeepAudit SAST；IaC/完整 SDLC 用本模块上游卡 |
| 19 | 工控安全 | 补齐（原先缺专卡） | Skill `工控` · 本模块上游全文；网站案默认降权 |
| 20 | 区块链/Web3安全 | 有知识 | 九阶段 `web3-dev-services` |
| 21 | 物联网安全 | 有知识 | Skill `固胚` · `hardware-security` · 固件/binwalk 网站案降权 |
| 22 | 数据安全与隐私保护 | 补齐（原先缺专卡） | 本模块上游全文 |
| 23 | 社会工程学 | 有且更强 | Skill `tg-social-engage` · `social_engineer_agent.py` · 代理社工杀伤链 |
| 24 | 红蓝对抗 | 部分 | 授权作业口径；BAS/紫队用本模块上游卡 |
| 25 | 供应链安全 | 有 | TeamCity · AutoCVE · 九阶段 `supply-chain-attacks` |
| 26 | 漏洞管理 | 有 | Skill `房睇长·日更` · `1day-nuclei-kit` · `房睇长·耳报.md` |
| 27 | 操作系统安全 | 部分 | Linux/Windows 提权卡；加固基线用本模块上游卡 |
| 28 | 威胁狩猎 | 补齐（原先缺专卡） | 本模块上游全文 |
| 29 | 威胁情报 | 有 | `cve-daily-intel` · `space_search.py` · cvebase |
| 30 | 数字取证 | 补齐（原先缺专卡） | Skill `残忆` · `host-ir-check` · `case-review` |
| 31 | SOC运营 | 补齐（原先缺专卡） | 本模块上游全文 |
| 32 | 身份与访问管理 | 有 | `托印·越权.md` · `宗门·认族.md` · GVA/JWT 专卡 |
| 33 | 容器安全 | 有 | `群瓮·特权.md` · `瓮中逃.md` · WolfStack / etcd |
| 34 | API安全 | 有且更强 | `万我·信门.md` · `李代桃僵·星念.md` · 芋道/Qzino 加密 API |
| 35 | 密码学与PKI | 部分 | JS/AES 签名专卡；PKI/TLS 基线用本模块上游卡 |
| 36 | 零信任架构 | 有 | Skill `行器·敲门` · `c2_zt_probe.py` · `行器·敲门.md` |
| 37 | 端点安全 | 补齐（原先缺专卡） | 本模块上游全文 |
| 38 | 勒索软件防御 | 补齐（原先缺专卡） | 本模块上游全文 |
| 39 | 安全治理与合规 | 补齐（原先缺专卡） | 本模块上游全文 |

## 00 大爱仙尊业务（上游没有、本库更强）

| 主题 | 走 |
|------|-----|
| 假支付 / 彩虹易支付 / USDT 归属 | `payment-callback-forgery` |
| 白标盘口 / 芋道 TMA / Qzino | `gambling-family-router` · `yudao-appapi-pentest` |
| TG 云控 / Fernet / 号库 / 社工 | `tg-cloud-panel` · `tg-account-library` · `tg-social-engage` |
| Spring Actuator / Gateway | `spring-actuator-cloud-takeover` |
| GVA / 发卡 / PocketBase | 对应专用 Skill |

## 195 张逐条

| ID | 技能 | 本库 | 文件 |
|----|------|------|------|
| 01-001 | 被动信息搜集/OSINT | 专卡 | `01-风闻/skills/被动信息搜集-PassiveRecon.md` |
| 01-002 | 主动信息搜集 | 知识卡 | `01-风闻/skills/主动信息搜集-ActiveRecon.md` |
| 01-003 | DNS枚举 | 知识卡 | `01-风闻/skills/DNS枚举-DNSEnumeration.md` |
| 01-004 | 子域名探测 | 知识卡 | `01-风闻/skills/子域名探测-SubdomainDiscovery.md` |
| 01-005 | 网络空间搜索引擎 | 知识卡 | `01-风闻/skills/网络空间搜索引擎-OSINT-SearchEngine.md` |
| 01-006 | 社会工程学信息 | 知识卡 | `01-风闻/skills/社会工程学信息-SocialEngineeringInfo.md` |
| 01-007 | 目标技术栈识别 | 知识卡 | `01-风闻/skills/目标技术栈识别-TechStackFingerprint.md` |
| 02-001 | Web漏洞扫描 | 知识卡 | `02-巡伤/skills/Web漏洞扫描-WebVulnScan.md` |
| 02-002 | 网络漏洞扫描 | 知识卡 | `02-巡伤/skills/网络漏洞扫描-NetworkVulnScan.md` |
| 02-003 | 数据库安全评估 | 知识卡 | `02-巡伤/skills/数据库安全评估-DatabaseAssessment.md` |
| 02-004 | 配置审计扫描 | 知识卡 | `02-巡伤/skills/配置审计扫描-ConfigAuditScan.md` |
| 02-005 | 漏洞扫描器自动化 | 知识卡 | `02-巡伤/skills/漏洞扫描器自动化-VulnScannerAutomation.md` |
| 02-006 | AI代理漏洞扫描 | 知识卡 | `02-巡伤/skills/AI代理漏洞扫描-AIAgentVulnScan.md` |
| 03-001 | Web漏洞利用 | 知识卡 | `03-祭杀/skills/Web漏洞利用-WebExploitation.md` |
| 03-002 | SQL注入利用 | 知识卡 | `03-祭杀/skills/SQL注入利用-SQLInjection.md` |
| 03-003 | XSS跨站脚本 | 专卡 | `03-祭杀/skills/XSS跨站脚本-XSSExploitation.md` |
| 03-004 | 文件包含利用 | 知识卡 | `03-祭杀/skills/文件包含利用-FileInclusion.md` |
| 03-005 | 命令注入 | 专卡 | `03-祭杀/skills/命令注入-CommandInjection.md` |
| 03-006 | SSRF服务端请求伪造 | 专卡 | `03-祭杀/skills/SSRF服务端请求伪造-SSRF.md` |
| 03-007 | 认证绕过 | 专卡 | `03-祭杀/skills/认证绕过-AuthBypass.md` |
| 03-008 | Metasploit框架利用 | 知识卡 | `03-祭杀/skills/Metasploit框架利用-Metasploit.md` |
| 03-009 | AI代理漏洞利用 | 知识卡 | `03-祭杀/skills/AI代理漏洞利用-AIAgentExploitation.md` |
| 04-001 | Linux提权 | 知识卡 | `04-反客/skills/Linux提权-LinuxPrivEsc.md` |
| 04-002 | Windows提权 | 专卡 | `04-反客/skills/Windows提权-WindowsPrivEsc.md` |
| 04-003 | 内核漏洞与服务配置错误提权 | 知识卡 | `04-反客/skills/内核漏洞与服务配置错误提权-KernelServicePrivEsc.md` |
| 04-004 | 凭证窃取与利用 | 知识卡 | `04-反客/skills/凭证窃取与利用-CredentialTheft.md` |
| 05-001 | 信息收集与数据窃取 | 知识卡 | `05-后手/skills/信息收集与数据窃取-InfoGatheringDataExfil.md` |
| 05-002 | 凭证转储与哈希传递 | 知识卡 | `05-后手/skills/凭证转储与哈希传递-CredentialDumpingPtH.md` |
| 05-003 | 远程控制与交互式Shell | 知识卡 | `05-后手/skills/远程控制与交互式Shell-RemoteControlShell.md` |
| 05-004 | 键盘记录与屏幕捕获 | 知识卡 | `05-后手/skills/键盘记录与屏幕捕获-KeyloggingScreenCapture.md` |
| 06-001 | 横向移动 | 专卡 | `06-纵横/skills/横向移动-LateralMovement.md` |
| 06-002 | 内网代理与隧道 | 知识卡 | `06-纵横/skills/内网代理与隧道-InternalProxyTunnel.md` |
| 06-003 | PsExec与WMI远程执行 | 知识卡 | `06-纵横/skills/PsExec与WMI远程执行-PsExecWMI.md` |
| 07-001 | 持久化 | 知识卡 | `07-驻/skills/持久化-Persistence.md` |
| 07-002 | 启动项与登录自动执行 | 知识卡 | `07-驻/skills/启动项与登录自动执行-BootLogonAutostart.md` |
| 07-003 | 账户创建与凭证持久化 | 知识卡 | `07-驻/skills/账户持久化-AccountPersistence.md` |
| 07-004 | Office应用程序持久化 | 知识卡 | `07-驻/skills/Office应用程序持久化-OfficePersistence.md` |
| 07-005 | Bootkit与固件持久化 | 知识卡 | `07-驻/skills/Bootkit与固件持久化-BootkitFirmwarePersistence.md` |
| 08-001 | 痕迹清除与反取证 | 知识卡 | `08-隐鳞/skills/痕迹清除-CoveringTracks.md` |
| 08-002 | 进程注入与代码注入 | 知识卡 | `08-隐鳞/skills/进程注入与代码注入-ProcessInjection.md` |
| 08-003 | 代码混淆与反分析 | 知识卡 | `08-隐鳞/skills/代码混淆与反分析-ObfuscationAntiAnalysis.md` |
| 08-004 | AMSI绕过与EDR规避 | 知识卡 | `08-隐鳞/skills/AMSI绕过与EDR规避-AMSIByPassEDREvasion.md` |
| 09-001 | 渗透测试报告编写 | 知识卡 | `09-呈文/skills/报告编写-PentestReport.md` |
| 09-002 | 漏洞评级与CVSS评分 | 知识卡 | `09-呈文/skills/漏洞评级与CVSS-VulnRatingCVSS.md` |
| 09-003 | Markdown安全报告模板 | 知识卡 | `09-呈文/skills/安全报告模板-Markdown.md` |
| 09-004 | HTML安全报告模板 | 知识卡 | `09-呈文/skills/安全报告模板-HTML.md` |
| 09-005 | Word/PDF安全报告模板 | 专卡 | `09-呈文/skills/安全报告模板-Word.md` |
| 10-001 | Android安全测试 | 知识卡 | `10-掌器/skills/Android安全测试-AndroidSecurityTest.md` |
| 10-002 | iOS安全测试 | 知识卡 | `10-掌器/skills/iOS安全测试-iOSSecurityTest.md` |
| 11-001 | Wi-Fi安全审计 | 专卡 | `11-无线/skills/WiFi安全审计-WiFiSecurityAudit.md` |
| 12-001 | PHP代码审计 | 知识卡 | `12-文审/skills/PHP代码审计-PHPCodeAudit.md` |
| 12-002 | Java代码审计 | 知识卡 | `12-文审/skills/Java代码审计-JavaCodeAudit.md` |
| 12-003 | JavaScript代码审计 | 知识卡 | `12-文审/skills/JavaScript代码审计-JSCodeAudit.md` |
| 12-004 | Python代码审计 | 知识卡 | `12-文审/skills/Python代码审计-PythonCodeAudit.md` |
| 12-005 | C代码审计 | 知识卡 | `12-文审/skills/C代码审计-CCodeAudit.md` |
| 12-006 | C++代码审计 | 专卡 | `12-文审/skills/C++代码审计-CPPCodeAudit.md` |
| 12-007 | Rust代码审计 | 知识卡 | `12-文审/skills/Rust代码审计-RustCodeAudit.md` |
| 12-008 | Go代码审计 | 知识卡 | `12-文审/skills/Go代码审计-GoCodeAudit.md` |
| 12-009 | AI Agent代码审计 | 专卡 | `12-文审/skills/AI Agent代码审计-AIAgentCodeAudit.md` |
| 13-001 | 静态逆向分析 | 知识卡 | `13-逆骨/skills/静态逆向分析-StaticReverseAnalysis.md` |
| 13-002 | 动态调试分析 | 知识卡 | `13-逆骨/skills/动态调试分析-DynamicDebugAnalysis.md` |
| 13-003 | 恶意软件分析 | 知识卡 | `13-逆骨/skills/恶意软件分析-MalwareAnalysis.md` |
| 14-001 | 等级保护合规审计 | 知识卡 | `14-器审/skills/等级保护合规审计-ClassifiedProtectionAudit.md` |
| 14-002 | 配置安全审计 | 知识卡 | `14-器审/skills/配置安全审计-ConfigSecurityAudit.md` |
| 14-003 | 安全架构审计 | 知识卡 | `14-器审/skills/安全架构审计-SecurityArchitectureAudit.md` |
| 14-004 | 云安全审计 | 知识卡 | `14-器审/skills/云安全审计-CloudSecurityAudit.md` |
| 14-005 | 容器安全审计 | 知识卡 | `14-器审/skills/容器安全审计-ContainerSecurityAudit.md` |
| 14-006 | 网络安全合规评估 | 知识卡 | `14-器审/skills/网络安全合规评估-NetworkComplianceAssessment.md` |
| 14-007 | AI Agent安全审计 | 专卡 | `14-器审/skills/AI Agent安全审计-AIAgentSecurityAudit.md` |
| 15-001 | 事件分类与优先级评估 | 知识卡 | `15-祸应/skills/事件分类与优先级评估-IncidentTriage.md` |
| 15-002 | 日志收集与分析 | 知识卡 | `15-祸应/skills/日志收集与分析-LogCollectionAnalysis.md` |
| 15-003 | 网络流量分析 | 知识卡 | `15-祸应/skills/网络流量分析-NetworkTrafficAnalysis.md` |
| 15-004 | 事件遏制与清除 | 知识卡 | `15-祸应/skills/事件遏制与清除-ContainmentEradication.md` |
| 15-005 | 云环境应急响应 | 知识卡 | `15-祸应/skills/云环境应急响应-CloudIncidentResponse.md` |
| 15-006 | 事件复盘与报告 | 知识卡 | `15-祸应/skills/事件复盘与报告-LessonsLearnedReporting.md` |
| 15-007 | AI安全应急响应 | 知识卡 | `15-祸应/skills/AI安全应急响应-AISecurityIncidentResponse.md` |
| 16-001 | LLM提示注入与安全防护 | 知识卡 | `16-大灵/skills/LLM提示注入与安全防护-PromptInjectionDefense.md` |
| 16-002 | LLM数据泄露与隐私保护 | 知识卡 | `16-大灵/skills/LLM数据泄露与隐私保护-DataLeakagePrivacy.md` |
| 16-003 | AI供应链安全 | 知识卡 | `16-大灵/skills/AI供应链安全-AISupplyChainSecurity.md` |
| 16-004 | 大模型红队测试 | 知识卡 | `16-大灵/skills/大模型红队测试-LLMRedTeaming.md` |
| 16-005 | AI Agent权限与访问控制 | 专卡 | `16-大灵/skills/AI Agent权限与访问控制-AgentAuthorization.md` |
| 16-006 | 模型对抗攻击与防御 | 知识卡 | `16-大灵/skills/模型对抗攻击与防御-AdversarialAttackDefense.md` |
| 16-007 | 模型输出安全与幻觉检测 | 知识卡 | `16-大灵/skills/模型输出安全与幻觉检测-OutputSafetyHallucination.md` |
| 16-008 | AI应用安全配置审计 | 知识卡 | `16-大灵/skills/AI应用安全配置审计-AIAppSecurityConfig.md` |
| 16-009 | 联邦学习安全 | 知识卡 | `16-大灵/skills/联邦学习安全-FederatedLearningSecurity.md` |
| 16-010 | 多模态AI安全 | 知识卡 | `16-大灵/skills/多模态AI安全-MultimodalAISecurity.md` |
| 17-001 | AWS安全评估 | 知识卡 | `17-云府/skills/AWS安全评估-AWSSecurityAssessment.md` |
| 17-002 | Azure安全评估 | 知识卡 | `17-云府/skills/Azure安全评估-AzureSecurityAssessment.md` |
| 17-003 | GCP安全评估 | 知识卡 | `17-云府/skills/GCP安全评估-GCPSecurityAssessment.md` |
| 17-004 | 云IAM权限与访问控制审计 | 知识卡 | `17-云府/skills/云IAM权限与访问控制审计-CloudIAMAudit.md` |
| 17-005 | 云存储安全配置审计 | 知识卡 | `17-云府/skills/云存储安全配置审计-CloudStorageSecurity.md` |
| 17-006 | 云网络与WAF安全 | 知识卡 | `17-云府/skills/云网络与WAF安全-CloudNetworkWAF.md` |
| 17-007 | 无服务器架构安全 | 知识卡 | `17-云府/skills/无服务器架构安全-ServerlessSecurity.md` |
| 17-008 | 多云安全策略评估 | 知识卡 | `17-云府/skills/多云安全策略评估-MultiCloudSecurity.md` |
| 18-001 | CI/CD管道安全审计 | 专卡 | `18-工坊/skills/CI-CD管道安全审计-CICDPipelineSecurity.md` |
| 18-002 | IaC安全扫描 | 知识卡 | `18-工坊/skills/IaC安全扫描-InfrastructureAsCodeSecurity.md` |
| 18-003 | SAST静态应用安全测试 | 知识卡 | `18-工坊/skills/SAST静态应用安全测试-SAST.md` |
| 18-004 | DAST动态应用安全测试 | 知识卡 | `18-工坊/skills/DAST动态应用安全测试-DAST.md` |
| 18-005 | 软件供应链安全 | 知识卡 | `18-工坊/skills/软件供应链安全-SoftwareSupplyChainSecurity.md` |
| 18-006 | 安全需求与威胁建模 | 知识卡 | `18-工坊/skills/安全需求与威胁建模-ThreatModeling.md` |
| 19-001 | SCADA系统安全评估 | 知识卡 | `19-工控/skills/SCADA系统安全评估-SCADASecurityAssessment.md` |
| 19-002 | PLC与RTU安全测试 | 知识卡 | `19-工控/skills/PLC与RTU安全测试-PLC-RTU-SecurityTesting.md` |
| 19-003 | 工控网络协议安全 | 知识卡 | `19-工控/skills/工控网络协议安全-ICS-NetworkProtocolSecurity.md` |
| 19-004 | 工控安全合规审计（IEC 62443） | 知识卡 | `19-工控/skills/工控安全合规审计-IEC62443-Audit.md` |
| 19-005 | 工控安全应急预案 | 知识卡 | `19-工控/skills/工控安全应急预案-ICS-IncidentResponse.md` |
| 19-006 | 工业防火墙与网络分段 | 知识卡 | `19-工控/skills/工业防火墙与网络分段-Industrial-Firewall-Segmentation.md` |
| 20-001 | 智能合约安全审计 | 知识卡 | `20-巧契/skills/智能合约安全审计-SmartContractAudit.md` |
| 20-002 | DeFi协议安全评估 | 知识卡 | `20-巧契/skills/DeFi协议安全评估-DeFiSecurityAssessment.md` |
| 20-003 | 共识机制安全分析 | 知识卡 | `20-巧契/skills/共识机制安全分析-ConsensusSecurityAnalysis.md` |
| 20-004 | Web3前端与钱包安全 | 知识卡 | `20-巧契/skills/Web3前端与钱包安全-Web3WalletSecurity.md` |
| 20-005 | 区块链节点安全加固 | 知识卡 | `20-巧契/skills/区块链节点安全加固-BlockchainNodeHardening.md` |
| 20-006 | MEV与跨链桥安全 | 知识卡 | `20-巧契/skills/MEV与跨链桥安全-MEV-CrossChainBridgeSecurity.md` |
| 21-001 | 固件逆向与分析 | 知识卡 | `21-杂器/skills/固件逆向与分析-FirmwareReverseEngineering.md` |
| 21-002 | BLE/Zigbee/Z-Wave无线安全测试 | 专卡 | `21-杂器/skills/BLE-Zigbee-Z-Wave无线安全测试-WirelessProtocolSecurity.md` |
| 21-003 | 物联网通信协议安全 | 知识卡 | `21-杂器/skills/物联网通信协议安全-IoTCommunicationSecurity.md` |
| 21-004 | 嵌入式设备硬件安全测试 | 知识卡 | `21-杂器/skills/嵌入式设备硬件安全测试-EmbeddedHardwareSecurity.md` |
| 21-005 | 物联网平台与云安全 | 知识卡 | `21-杂器/skills/物联网平台与云安全-IoTPlatformCloudSecurity.md` |
| 21-006 | 智能家居与车联网安全 | 知识卡 | `21-杂器/skills/智能家居与车联网安全-SmartHomeConnectedVehicleSecurity.md` |
| 22-001 | DLP数据防泄漏策略 | 知识卡 | `22-密卷/skills/DLP数据防泄漏策略-DataLossPrevention.md` |
| 22-002 | 数据分类与分级保护 | 知识卡 | `22-密卷/skills/数据分类与分级保护-DataClassificationGrading.md` |
| 22-003 | 数据库安全与加密 | 知识卡 | `22-密卷/skills/数据库安全与加密-DatabaseSecurityEncryption.md` |
| 22-004 | 数据脱敏与匿名化 | 知识卡 | `22-密卷/skills/数据脱敏与匿名化-DataMaskingAnonymization.md` |
| 22-005 | GDPR/个保法合规评估 | 知识卡 | `22-密卷/skills/GDPR-个保法合规评估-PrivacyCompliance.md` |
| 22-006 | 隐私影响评估（PIA） | 知识卡 | `22-密卷/skills/隐私影响评估-PIA-PrivacyImpactAssessment.md` |
| 23-001 | 钓鱼邮件模拟 | 知识卡 | `23-人事/skills/钓鱼邮件模拟-PhishingSimulation.md` |
| 23-002 | 电话诈骗与Vishing测试 | 知识卡 | `23-人事/skills/电话诈骗与Vishing测试-VishingTesting.md` |
| 23-003 | 物理渗透与社会工程 | 知识卡 | `23-人事/skills/物理渗透与社会工程-PhysicalSocialEngineering.md` |
| 23-004 | 钓鱼基础设施搭建 | 知识卡 | `23-人事/skills/钓鱼基础设施搭建-PhishingInfrastructure.md` |
| 23-005 | 员工安全意识评估 | 知识卡 | `23-人事/skills/员工安全意识评估-SecurityAwarenessAssessment.md` |
| 24-001 | 红队评估方法论 | 知识卡 | `24-红衣/skills/红队评估方法论-RedTeamAssessment.md` |
| 24-002 | 蓝队防御与检测 | 知识卡 | `24-红衣/skills/蓝队防御与检测-BlueTeamDefense.md` |
| 24-003 | 紫队协作评估 | 知识卡 | `24-红衣/skills/紫队协作评估-PurpleTeamExercise.md` |
| 24-004 | BAS攻击模拟平台 | 知识卡 | `24-红衣/skills/BAS攻击模拟平台-BreachAttackSimulation.md` |
| 24-005 | 闭环防御改进 | 知识卡 | `24-红衣/skills/闭环防御改进-DefenseImprovementCycle.md` |
| 25-001 | SBOM生成与验证 | 知识卡 | `25-供链/skills/SBOM生成与验证-SBOMGeneration.md` |
| 25-002 | 软件依赖与开源合规审计 | 知识卡 | `25-供链/skills/软件依赖与开源合规审计-DependencyLicenseCompliance.md` |
| 25-003 | 代码签名与供应链完整性 | 知识卡 | `25-供链/skills/代码签名与供应链完整性-CodeSigningIntegrity.md` |
| 25-004 | 第三方供应商风险评估 | 知识卡 | `25-供链/skills/第三方供应商风险评估-ThirdPartyVendorRisk.md` |
| 25-005 | 供应链攻击检测与响应 | 知识卡 | `25-供链/skills/供应链攻击检测与响应-SupplyChainAttackResponse.md` |
| 26-001 | 漏洞情报与CVE查询 | 知识卡 | `26-伤门/skills/漏洞情报与CVE查询-VulnerabilityIntelligence.md` |
| 26-002 | 漏洞验证与PoC测试 | 知识卡 | `26-伤门/skills/漏洞验证与PoC测试-VulnerabilityVerification.md` |
| 26-003 | 漏洞优先级与风险评估 | 知识卡 | `26-伤门/skills/漏洞优先级与风险评估-VulnerabilityPrioritization.md` |
| 26-004 | 漏洞修复与补丁管理 | 知识卡 | `26-伤门/skills/漏洞修复与补丁管理-VulnerabilityRemediation.md` |
| 26-005 | 漏洞生命周期闭环管理 | 知识卡 | `26-伤门/skills/漏洞生命周期闭环管理-VulnerabilityLifecycle.md` |
| 26-006 | 漏洞奖励计划与安全众测 | 知识卡 | `26-伤门/skills/漏洞奖励计划与安全众测-BugBountyCrowdsourcedTesting.md` |
| 27-001 | Windows安全加固与基线检查 | 知识卡 | `27-宿主/skills/Windows安全加固与基线检查-WindowsHardeningBaseline.md` |
| 27-002 | Windows攻击与横向移动技术 | 知识卡 | `27-宿主/skills/Windows攻击与横向移动技术-WindowsAttackLateralMovement.md` |
| 27-003 | Linux安全加固与基线检查 | 知识卡 | `27-宿主/skills/Linux安全加固与基线检查-LinuxHardeningBaseline.md` |
| 27-004 | Linux攻击与权限维持技术 | 知识卡 | `27-宿主/skills/Linux攻击与权限维持技术-LinuxAttackPersistence.md` |
| 27-005 | macOS安全评估与加固 | 知识卡 | `27-宿主/skills/macOS安全评估与加固-macOSSecurityHardening.md` |
| 27-006 | 国产操作系统安全加固 | 知识卡 | `27-宿主/skills/国产操作系统安全加固-DomesticOSSecurity.md` |
| 28-001 | 威胁狩猎方法论与假设驱动 | 知识卡 | `28-猎/skills/威胁狩猎方法论-ThreatHuntingMethodology.md` |
| 28-002 | 基于Sigma规则的检测工程 | 知识卡 | `28-猎/skills/Sigma规则检测工程-SigmaRuleEngineering.md` |
| 28-003 | 基于ATT&CK的威胁狩猎 | 知识卡 | `28-猎/skills/ATT&CK威胁狩猎-MITREAttackHunting.md` |
| 28-004 | 网络流量与日志异常检测 | 知识卡 | `28-猎/skills/网络流量与日志异常检测-TrafficLogAnomalyDetection.md` |
| 29-001 | 威胁情报馈入与TAXII/STIX管理 | 知识卡 | `29-耳报/skills/威胁情报馈入与TAXII-STIX管理-ThreatIntelFeedsTAXIISTIX.md` |
| 29-002 | MISP平台部署与威胁情报共享 | 知识卡 | `29-耳报/skills/MISP部署与威胁情报共享-MISPDeploymentIntelSharing.md` |
| 29-003 | APT组织分析与归因 | 知识卡 | `29-耳报/skills/APT组织分析与归因-APTGroupAnalysisAttribution.md` |
| 29-004 | 威胁情报驱动安全运营 | 知识卡 | `29-耳报/skills/威胁情报驱动安全运营-ThreatIntelDrivenSOC.md` |
| 30-001 | 磁盘镜像与证据获取 | 知识卡 | `30-残忆/skills/磁盘镜像与证据获取-DiskImagingEvidenceAcquisition.md` |
| 30-002 | 内存取证分析(Volatility) | 知识卡 | `30-残忆/skills/内存取证分析-Volatility-MemoryForensicsVolatility.md` |
| 30-003 | Windows数字取证分析 | 知识卡 | `30-残忆/skills/Windows数字取证分析-WindowsDigitalForensics.md` |
| 30-004 | Linux数字取证分析 | 知识卡 | `30-残忆/skills/Linux数字取证分析-LinuxDigitalForensics.md` |
| 30-005 | 浏览器与邮件取证 | 知识卡 | `30-残忆/skills/浏览器与邮件取证-BrowserEmailForensics.md` |
| 31-001 | SIEM告警规则与关联分析 | 知识卡 | `31-监天/skills/SIEM告警规则与关联分析-SIEMAlertCorrelation.md` |
| 31-002 | SOC事件分级与响应流程 | 知识卡 | `31-监天/skills/SOC事件分级与响应流程-SOCTriageResponse.md` |
| 31-003 | 安全自动化与编排(SOAR) | 知识卡 | `31-监天/skills/安全自动化与编排-SOAR-SecurityAutomationOrchestration.md` |
| 31-004 | SOC指标与运营效能度量 | 知识卡 | `31-监天/skills/SOC指标与运营效能度量-SOCMetricsKPIs.md` |
| 32-001 | 企业IAM策略与架构 | 知识卡 | `32-印绶/skills/企业IAM策略与架构-EnterpriseIAMStrategy.md` |
| 32-002 | PAM特权账号管理 | 知识卡 | `32-印绶/skills/PAM特权账号管理-PrivilegedAccessManagement.md` |
| 32-003 | 云IAM与联邦认证 | 知识卡 | `32-印绶/skills/云IAM与联邦认证-CloudIAMFederation.md` |
| 32-004 | AD域安全与攻击路径分析 | 知识卡 | `32-印绶/skills/AD域安全与攻击路径分析-ADSecurityAttackPathAnalysis.md` |
| 33-001 | 容器镜像安全与漏洞扫描 | 知识卡 | `33-瓮/skills/容器镜像安全与漏洞扫描-ContainerImageSecurityScanning.md` |
| 33-002 | Kubernetes RBAC与安全策略 | 知识卡 | `33-瓮/skills/Kubernetes RBAC与安全策略-KubernetesRBACSecurityPolicy.md` |
| 33-003 | 容器运行时安全(Falco) | 知识卡 | `33-瓮/skills/容器运行时安全-Falco-ContainerRuntimeSecurityFalco.md` |
| 33-004 | 容器逃逸检测与防御 | 知识卡 | `33-瓮/skills/容器逃逸检测与防御-ContainerEscapeDetectionDefense.md` |
| 34-001 | OWASP API安全测试 | 知识卡 | `34-信门/skills/OWASP API安全测试-OWASPAPISecurityTesting.md` |
| 34-002 | API认证与授权安全 | 知识卡 | `34-信门/skills/API认证与授权安全-APIAuthAuthorizationSecurity.md` |
| 34-003 | GraphQL与微服务API安全 | 知识卡 | `34-信门/skills/GraphQL与微服务API安全-GraphQLMicroserviceAPISecurity.md` |
| 35-001 | TLS/SSL安全配置与审计 | 专卡 | `35-钱庄/skills/TLS-SSL安全配置与审计-TLSSSLSecurityConfigurationAudit.md` |
| 35-002 | PKI架构与证书安全管理 | 知识卡 | `35-钱庄/skills/PKI架构与证书安全管理-PKIArchitectureCertificateManagement.md` |
| 35-003 | 加密算法与密钥管理 | 知识卡 | `35-钱庄/skills/加密算法与密钥管理-EncryptionAlgorithmsKeyManagement.md` |
| 36-001 | 零信任架构设计与实施 | 知识卡 | `36-敲门/skills/零信任架构设计与实施-ZeroTrustArchitectureDesign.md` |
| 36-002 | 微隔离与软件定义边界(SDP) | 知识卡 | `36-敲门/skills/微隔离与软件定义边界-SDP-MicrosegmentationSDP.md` |
| 36-003 | ZTNA解决方案与IAM集成 | 知识卡 | `36-敲门/skills/ZTNA解决方案与IAM集成-ZTNASolutionsIAMIntegration.md` |
| 37-001 | EDR部署与检测规则 | 知识卡 | `37-端/skills/EDR部署与检测规则-EDRDeploymentDetectionRules.md` |
| 37-002 | 文件less恶意软件与LOLBins检测 | 知识卡 | `37-端/skills/文件less恶意软件与LOLBins检测-FilelessMalwareLOLBinsDetection.md` |
| 37-003 | 端点加固与合规基线 | 知识卡 | `37-端/skills/端点加固与合规基线-EndpointHardeningComplianceBaseline.md` |
| 37-004 | 移动设备安全与MDM | 知识卡 | `37-端/skills/移动设备安全与MDM-MobileDeviceSecurityMDM.md` |
| 38-001 | 勒索软件攻击链分析与检测 | 知识卡 | `38-疫/skills/勒索软件攻击链分析与检测-RansomwareAttackChainAnalysisDetection.md` |
| 38-002 | 勒索软件应急响应与恢复 | 知识卡 | `38-疫/skills/勒索软件应急响应与恢复-RansomwareIncidentResponseRecovery.md` |
| 38-003 | 反勒索软件加固与备份策略 | 知识卡 | `38-疫/skills/反勒索软件加固与备份策略-AntiRansomwareHardeningBackup.md` |
| 39-001 | 安全框架与合规审计 | 知识卡 | `39-律道/skills/安全框架与合规审计-SecurityFrameworkComplianceAudit.md` |
| 39-002 | 风险管理与安全度量 | 知识卡 | `39-律道/skills/风险管理与安全度量-RiskManagementSecurityMetrics.md` |
| 39-003 | 安全策略体系与安全意识 | 知识卡 | `39-律道/skills/安全策略体系与安全意识-SecurityPolicyAwareness.md` |
