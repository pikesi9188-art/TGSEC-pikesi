#!/usr/bin/env python3
"""
social_engineer_agent.py — 博彩站社工身份动态生成器（授权范围内）

核心思路：
  没有固定身份。根据目标分析 → 自动匹配最适合的身份和话术。
  每个目标的需求不同，能给对方带来价值的身份也不同。

工作流程：
  1. analyze  — 分析目标（网站/TG群/APK），判断对方缺什么
  2. suggest  — 基于分析结果，推荐 3-5 个可用身份（按成功率排序）
  3. script   — 生成指定身份的完整对话脚本
  4. adapt    — 给定当前对话内容，生成下一句回应

身份库覆盖（27 种）：
  支付/资金类    6 种
  推广/流量类    5 种
  技术服务类     6 种
  内容/供应链类  5 种
  VIP/资源类     5 种

用法：
  # 分析目标，推荐身份
  python3 炼蛊房/social_engineer_agent.py analyze -d target.com

  # 列出所有身份
  python3 炼蛊房/social_engineer_agent.py list

  # 生成指定身份的完整对话脚本
  python3 炼蛊房/social_engineer_agent.py script --id usdt_exchanger --target target.com

  # 给定当前对话，生成下一句
  python3 炼蛊房/social_engineer_agent.py adapt \
    --id tech_vendor \
    --history "对方:你们做什么的" \
    --goal "获取代理后台链接"

  # 完整流程：分析 + 推荐 + 出脚本
  python3 炼蛊房/social_engineer_agent.py run -d target.com --goal agent_url

依赖：pip install requests
"""

from __future__ import annotations

import argparse
import random
import re
import sys

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════
#  身份库（Identity Database）
#  每种身份包含：
#    need_match    — 目标需要什么时适用（用于自动匹配）
#    ask_for       — 自然能要到什么
#    credibility   — 可信度 1-5
#    intro         — 自我介绍话术
#    hook          — 勾子（为什么对方要和你谈）
#    goals         — 对话目标字典
# ══════════════════════════════════════════════════════════════════

IDENTITIES = {

    # ───────────── 支付 / 资金类 ─────────────

    "usdt_exchanger": {
        "name": "USDT 大额兑换商",
        "category": "支付",
        "need_match": ["usdt", "payment", "充值", "提现", "支付", "tether"],
        "ask_for": ["代理后台URL", "API对接文档", "注册链接", "测试账号"],
        "credibility": 5,
        "intro_variants": [
            "我们团队专门做东南亚方向 USDT 大额兑换，日均流水 5-15 万 U",
            "做跨境 OTC 的，主要对接菲律宾越南方向，每天 800-2000 笔",
            "我们在做 USDT 兑换业务，资金在链上跑，不走传统支付，日流水稳定",
        ],
        "hook": "我们量大稳定，现在在选合适的平台长期合作，对方返佣好就可以谈",
        "objection_handlers": {
            "需要资质": "我们做的是民间兑换，不走正规公司渠道，一般直接 USDT 结算就行",
            "需要先充值": "充值没问题，但我们财务习惯先看后台界面确认功能，你们有演示账号吗",
            "我们不对外合作": "理解，那有没有推荐的平台，我去找他们聊，你们这边如果以后有需求也可以联系我",
        },
        "goal_scripts": {
            "agent_url": [
                "那我们谈好了，合作的话我这边财务需要一个代理后台链接，方便看实时数据",
                "我们团队有专门做对账的，你能发一下代理后台的注册链接吗，我让他们先熟悉一下界面",
                "三七分没问题，后台链接你发我，我今天就让团队注册进去看看",
            ],
            "api_doc": [
                "我们这边对接方式比较灵活，你们有没有 API 文档，我评估一下技术对接可行性",
                "我们 IT 那边需要看下接口格式，有没有 swagger 或者 postman 文档",
            ],
            "tech_stack": [
                "我们之前对接过几个平台，有的用 PHP 有的用 Java，你们这套是自研的吗",
                "为了我们 IT 评估对接工作量，后台是用什么技术栈？子账号是独立入口还是主账号下级",
            ],
        },
    },

    "payment_channel": {
        "name": "跨境支付渠道商",
        "category": "支付",
        "need_match": ["payment", "支付", "收款", "通道", "channel"],
        "ask_for": ["API文档", "回调地址格式", "测试环境", "对接联系人"],
        "credibility": 4,
        "intro_variants": [
            "我们是做东南亚跨境收款的，主要帮博彩/电商平台对接当地支付通道",
            "我们公司做 payment gateway，覆盖菲律宾 GCash、越南 Momo、泰国 PromptPay",
            "我们在做博彩平台支付聚合方案，已经接了十几家，想了解你们这边有没有合作意向",
        ],
        "hook": "我们能接入的支付方式对方没有，可以帮他们覆盖更多用户充值渠道",
        "goal_scripts": {
            "api_doc": [
                "对接的话我们需要你们的充值/提现回调接口文档，你们有技术文档可以发我看看吗",
                "我让 IT 跟你们技术对接，能给个 API 文档或者对接 QQ/微信吗",
            ],
            "tech_stack": [
                "我们以前对接过用 RSA 签名的也有用 MD5 的，你们这套用的什么签名方式",
                "你们充值接口是 REST 还是有特定的 SDK，方便我们评估工作量",
            ],
        },
    },

    "crypto_otc": {
        "name": "加密货币 OTC 做市商",
        "category": "支付",
        "need_match": ["crypto", "btc", "eth", "usdt", "区块链", "链上"],
        "ask_for": ["钱包地址策略", "出入金流程", "代理后台"],
        "credibility": 4,
        "intro_variants": [
            "我们做加密货币 OTC，主要做 USDT/BTC 大额兑换，日成交量 50-100 万 U",
            "我们是专业做市商，专门给博彩/灰产平台提供链上出入金解决方案",
        ],
        "hook": "我们有大量 USDT 需要出入，对方能解决我们资金归集问题",
        "goal_scripts": {
            "agent_url": [
                "我们要在你们平台上做大额资金测试，能开个代理账号方便操作吗",
                "我们做市量大，需要一个代理等级的账号，有没有对应入口",
            ],
        },
    },

    "risk_mgmt": {
        "name": "风控 / 反欺诈服务商",
        "category": "支付",
        "need_match": ["风控", "欺诈", "反洗钱", "黑名单", "risk"],
        "ask_for": ["API测试环境", "数据格式文档", "对接技术方案"],
        "credibility": 3,
        "intro_variants": [
            "我们做博彩行业风控 SaaS，帮平台识别套利/刷流水/洗钱账号，已接了 20+ 家平台",
            "我们提供玩家行为分析服务，帮平台降低欺诈率，想了解下你们目前风控是怎么做的",
        ],
        "hook": "帮对方降低欺诈损失，有利益驱动",
        "goal_scripts": {
            "api_doc": [
                "我们需要对接你们的用户行为数据 API，方便我们风控模型训练，有接口文档吗",
            ],
        },
    },

    "settlement_service": {
        "name": "结算清算服务",
        "category": "支付",
        "need_match": ["结算", "清算", "对账", "settlement"],
        "ask_for": ["对账接口", "结算报表格式", "代理后台"],
        "credibility": 3,
        "intro_variants": [
            "我们做博彩平台对账和结算外包，帮平台做日/月结算清算工作",
        ],
        "hook": "帮对方省去对账人力成本",
        "goal_scripts": {
            "agent_url": [
                "对账需要访问代理后台的报表功能，你们代理后台链接是什么，我们财务先看看格式",
            ],
        },
    },

    # ───────────── 推广 / 流量类 ─────────────

    "affiliate_team": {
        "name": "大型代理推广团队",
        "category": "推广",
        "need_match": ["推广", "代理", "affiliate", "返佣", "招商", "拉新"],
        "ask_for": ["代理后台URL", "返佣政策", "推广素材", "邀请码"],
        "credibility": 5,
        "intro_variants": [
            "我们在东南亚有一个推广团队，主要做 TG 群拉新，每个月能带几百个真实充值用户",
            "我们团队专门做博彩推广，下面有 30+ 个子代理，在找返佣合适的平台长期合作",
            "我们做代理的，主要在越南菲律宾方向，目前在对比几家平台的返佣政策",
        ],
        "hook": "能带来真实用户和流水，是对方最想要的",
        "goal_scripts": {
            "agent_url": [
                "那我去你们代理后台注册一下，能发我注册链接吗",
                "返佣按流水算的话，你们代理后台在哪里注册，发我链接",
                "我团队下面的子代理也要单独注册，你们代理后台支持多级吗，先发注册链接我看看",
            ],
            "tech_stack": [
                "我们之前合作的平台有的代理后台很难用，你们这个是自研的吗，界面好不好操作",
                "你们代理后台数据更新是实时的还是 T+1，我们那边子代理比较在意这个",
            ],
        },
    },

    "traffic_partner": {
        "name": "流量合作方（SEO/投流）",
        "category": "推广",
        "need_match": ["seo", "投流", "广告", "流量", "traffic"],
        "ask_for": ["落地页URL", "API对接", "素材资源"],
        "credibility": 3,
        "intro_variants": [
            "我们做博彩行业 SEO 和 Google/Facebook 投流，能稳定带来自然流量",
            "我们团队在做博彩流量分发，想聊一下 CPA/CPL 合作模式",
        ],
        "hook": "便宜且精准的流量是对方永远需要的",
        "goal_scripts": {
            "agent_url": [
                "我们做的是 CPA 模式，需要一个带追踪码的代理链接，你们代理后台能生成吗",
            ],
        },
    },

    "kol_influencer": {
        "name": "KOL / 网红推广",
        "category": "推广",
        "need_match": ["kol", "网红", "直播", "主播", "tiktok", "youtube"],
        "ask_for": ["专属推广链接", "返佣比例", "合作素材"],
        "credibility": 4,
        "intro_variants": [
            "我是做博彩内容的 KOL，TG 频道有 2 万粉，YouTube 有 5 万订阅，想谈推广合作",
            "我在菲律宾有个直播渠道，专门做博彩类内容，在找长期合作平台",
        ],
        "hook": "有现成受众，转化率高",
        "goal_scripts": {
            "agent_url": [
                "合作的话我需要一个专属推广链接，你们代理后台能生成带追踪的邀请链接吗",
            ],
        },
    },

    "overseas_agent": {
        "name": "海外本地化代理",
        "category": "推广",
        "need_match": ["overseas", "海外", "本地化", "localization"],
        "ask_for": ["本地化资源", "代理后台", "多语言支持"],
        "credibility": 4,
        "intro_variants": [
            "我们在菲律宾本地有团队，主要做用户服务和本地推广，能覆盖 Cebu/Manila 两个区域",
            "我们做越南本地推广，团队在 HCM，每月能稳定带 200-500 个活跃用户",
        ],
        "hook": "本地化推广效率远高于线上广告",
        "goal_scripts": {
            "agent_url": [
                "我们这边有专门的对接人，你先发我代理后台链接，我让对接人注册进去",
            ],
        },
    },

    "player_community": {
        "name": "玩家社区管理员",
        "category": "推广",
        "need_match": ["community", "社区", "群", "论坛"],
        "ask_for": ["推广政策", "邀请链接"],
        "credibility": 3,
        "intro_variants": [
            "我管理了几个博彩玩家群，总共 8000+ 人，在帮几个平台做推广，想了解你们返佣怎么算",
        ],
        "hook": "已有高质量用户群体",
        "goal_scripts": {
            "agent_url": [
                "我现在管理的几个群都是真实玩家，你发我代理注册链接，我直接在群里推",
            ],
        },
    },

    # ───────────── 技术服务类 ─────────────

    "tech_vendor": {
        "name": "技术外包 / 系统集成商",
        "category": "技术",
        "need_match": ["tech", "api", "系统", "开发", "集成", "sdk"],
        "ask_for": ["API文档", "技术方案", "测试环境", "对接账号"],
        "credibility": 4,
        "intro_variants": [
            "我们公司专门给博彩平台做技术外包，帮平台做 API 对接和系统集成",
            "我们是技术服务商，给十几家博彩平台提供数据分析和系统维护",
            "我们做博彩行业技术咨询，想了解下你们系统架构，评估一下有没有合作空间",
        ],
        "hook": "帮对方解决技术问题，省开发成本",
        "goal_scripts": {
            "api_doc": [
                "评估合作的话需要看一下你们 API 文档，你们有没有 swagger 或者接口说明",
                "我们 IT 那边需要了解你们接口格式，有没有技术文档可以先看看",
            ],
            "agent_url": [
                "我们需要一个测试账号来验证接口，代理级别就行，你们代理后台在哪里注册",
            ],
            "tech_stack": [
                "我问一下你们后端用的什么框架，PHP 还是 Java，方便我们评估对接工作量",
                "你们这套是自研的还是买的框架，问是因为我们以前接过几套，熟悉的框架对接会快很多",
            ],
        },
    },

    "sms_provider": {
        "name": "短信 / 验证码服务商",
        "category": "技术",
        "need_match": ["sms", "短信", "验证码", "otp", "notify"],
        "ask_for": ["对接方式", "API接口", "测试环境"],
        "credibility": 4,
        "intro_variants": [
            "我们做东南亚方向短信服务，覆盖菲律宾/越南/泰国，比国内通道便宜 40%",
            "我们是短信聚合平台，专门做博彩行业短信验证码，不限内容，稳定",
        ],
        "hook": "降低验证码成本，提升到达率",
        "goal_scripts": {
            "api_doc": [
                "我们对接一般都是标准 HTTP 接口，你们现在用的是哪家短信，想评估替换成本",
                "我们需要你们这边提供一个测试号码，我们这边发一条测试看到达率",
            ],
        },
    },

    "data_analytics": {
        "name": "数据分析 / BI 服务商",
        "category": "技术",
        "need_match": ["data", "数据", "分析", "bi", "报表", "analytics"],
        "ask_for": ["数据接口", "报表需求", "API访问权限"],
        "credibility": 3,
        "intro_variants": [
            "我们做博彩平台数据分析，帮平台做玩家行为分析和留存优化，已经服务了 15 家平台",
            "我们提供 BI 报表工具，专门针对博彩行业定制，能帮你们看到更细的运营数据",
        ],
        "hook": "帮对方提高运营效率和玩家留存",
        "goal_scripts": {
            "api_doc": [
                "对接数据的话我们需要只读的数据接口，你们有没有数据导出或者 API 查询接口",
            ],
        },
    },

    "cs_system": {
        "name": "客服系统供应商",
        "category": "技术",
        "need_match": ["客服", "support", "cs", "livechat", "聊天"],
        "ask_for": ["集成方式", "测试账号", "SDK文档"],
        "credibility": 3,
        "intro_variants": [
            "我们做博彩行业客服系统，支持 TG/WhatsApp/在线聊天三合一，十几家平台在用",
        ],
        "hook": "解决多渠道客服整合问题",
        "goal_scripts": {
            "tech_stack": [
                "集成的话需要了解你们前端用的什么框架，Vue 还是 React，方便评估嵌入方式",
            ],
        },
    },

    "security_audit": {
        "name": "安全审计 / 等保咨询",
        "category": "技术",
        "need_match": ["security", "安全", "audit", "合规", "渗透"],
        "ask_for": ["系统架构文档", "API文档", "测试环境"],
        "credibility": 2,
        "intro_variants": [
            "我们做海外博彩平台安全合规咨询，帮平台做渗透测试和安全加固",
        ],
        "hook": "降低被攻击风险（需要对方有安全意识）",
        "goal_scripts": {
            "api_doc": [
                "安全评估需要你们提供系统架构文档和 API 清单，方便我们制定测试方案",
            ],
        },
    },

    "hosting_provider": {
        "name": "服务器 / CDN 服务商",
        "category": "技术",
        "need_match": ["server", "hosting", "cdn", "服务器", "云"],
        "ask_for": ["当前架构", "服务器规模", "迁移需求"],
        "credibility": 3,
        "intro_variants": [
            "我们做博彩行业专用服务器租用，香港/新加坡节点，抗 DDoS，比 AWS 便宜",
            "我们是 CDN 服务商，专门服务博彩平台，绕过地区封锁，速度有保障",
        ],
        "hook": "降低服务器成本，提升稳定性",
        "goal_scripts": {
            "tech_stack": [
                "你们现在用的是什么服务器，自建还是云，用哪家",
                "我们有博彩行业专用机房，防 DDoS 性能更好，你们目前流量大概多少",
            ],
        },
    },

    # ───────────── 内容 / 供应链类 ─────────────

    "game_provider": {
        "name": "游戏内容供应商",
        "category": "内容",
        "need_match": ["game", "游戏", "slot", "live", "casino", "电子"],
        "ask_for": ["对接API", "游戏分成", "测试账号"],
        "credibility": 4,
        "intro_variants": [
            "我们代理了几款东南亚热门老虎机游戏，在找博彩平台对接分成合作",
            "我们是游戏聚合 API 供应商，一个接口接入 200+ 款游戏，想了解你们接入需求",
            "我们有独家真人荷官直播内容，在东南亚市场很受欢迎，想和你们聊分成合作",
        ],
        "hook": "丰富平台游戏内容，吸引更多玩家",
        "goal_scripts": {
            "api_doc": [
                "对接游戏的话需要你们的游戏对接 API 文档，能发我看看吗",
                "我们一般走 seamless 钱包对接模式，你们后台支持吗，有技术文档吗",
            ],
            "tech_stack": [
                "你们游戏后台是自研的还是用的什么框架，问是因为对接复杂度不一样",
            ],
        },
    },

    "live_streaming": {
        "name": "直播 / 荷官服务",
        "category": "内容",
        "need_match": ["live", "直播", "荷官", "dealer", "streaming"],
        "ask_for": ["直播接入方式", "技术规格", "合作条款"],
        "credibility": 3,
        "intro_variants": [
            "我们做东南亚真人荷官直播，已经在给 5 家平台供货，想了解你们有没有接入需求",
        ],
        "hook": "提升用户粘性和时长",
        "goal_scripts": {
            "tech_stack": [
                "直播接入需要了解你们播放器用的什么协议，RTMP 还是 HLS，方便我们评估兼容性",
            ],
        },
    },

    "lottery_data": {
        "name": "彩票数据供应商",
        "category": "内容",
        "need_match": ["lottery", "彩票", "开奖", "走势"],
        "ask_for": ["数据接入方式", "API对接"],
        "credibility": 3,
        "intro_variants": [
            "我们做彩票开奖数据服务，覆盖越南/泰国/印尼本地彩种，实时推送",
        ],
        "hook": "提供稳定可靠的开奖数据源",
        "goal_scripts": {
            "api_doc": [
                "对接数据的话你们这边用什么方式接入，REST 还是 WebSocket，有技术文档吗",
            ],
        },
    },

    "sports_data": {
        "name": "体育数据供应商",
        "category": "内容",
        "need_match": ["sports", "体育", "赔率", "足球", "basketball", "odds"],
        "ask_for": ["赔率接入API", "数据格式", "测试环境"],
        "credibility": 4,
        "intro_variants": [
            "我们做体育赔率数据服务，覆盖 5000+ 赛事，实时更新，想了解你们的接入需求",
        ],
        "hook": "更全面的赛事覆盖，提升体育投注用户",
        "goal_scripts": {
            "api_doc": [
                "你们体育这块的赔率接口是自研的还是外接的，如果是外接的方便透露是哪家吗",
            ],
        },
    },

    "vip_referral": {
        "name": "VIP 高净值玩家介绍",
        "category": "VIP",
        "need_match": ["vip", "高净值", "大客", "whale"],
        "ask_for": ["VIP待遇", "专属通道", "大额充值流程"],
        "credibility": 5,
        "intro_variants": [
            "我手上有几个东南亚 VIP 玩家，日均流水几十万，在帮他们物色合适的平台",
            "我在帮几个高净值客户找平台，他们要求要有独立的入款通道和高返水",
            "我代理了几个大客，每个月充值都在 50 万 U 以上，在对比几个平台的 VIP 条件",
        ],
        "hook": "大额流水是每个平台都想要的",
        "goal_scripts": {
            "agent_url": [
                "我先帮客户注册看看平台，你们 VIP 的入款通道是走代理账号管理吗，发我代理后台链接",
            ],
            "tech_stack": [
                "我客户要求大额入款要快速到账，你们入款是自动到账还是人工审核",
                "大额入款你们是专人对接还是走普通通道，有没有独立的 USDT 入款地址",
            ],
        },
    },

    "high_roller": {
        "name": "澳门/新加坡赌场中介",
        "category": "VIP",
        "need_match": ["junket", "赌场", "casino", "vip"],
        "ask_for": ["VIP服务", "大额专属通道"],
        "credibility": 4,
        "intro_variants": [
            "我们做赌场中介的，手上有几个澳门那边的老客户，最近想转线上，帮他们找平台",
        ],
        "hook": "传统赌场大客转线上，消费力强",
        "goal_scripts": {
            "agent_url": [
                "我客户要先试玩，你们有没有 VIP 试玩账号，或者我先用代理账号帮他管理",
            ],
        },
    },

    "financial_advisor": {
        "name": "资产配置顾问（高净值客户经理）",
        "category": "VIP",
        "need_match": ["investment", "资产", "理财", "配置"],
        "ask_for": ["平台稳定性证明", "合规资质", "大额测试"],
        "credibility": 3,
        "intro_variants": [
            "我服务几个私人客户，他们有闲置资金想做博彩投资，在帮他们评估平台",
        ],
        "hook": "稳定大额资金注入",
        "goal_scripts": {
            "tech_stack": [
                "我需要了解一下你们平台的资金安全机制，出金是 T+0 还是 T+1，最大单笔限额多少",
            ],
        },
    },

    "investor": {
        "name": "潜在投资人 / 股权合作",
        "category": "VIP",
        "need_match": ["invest", "投资", "入股", "合作"],
        "ask_for": ["运营数据", "技术架构", "估值"],
        "credibility": 3,
        "intro_variants": [
            "我们在看东南亚博彩行业的投资机会，想了解你们这边的运营情况和技术方案",
        ],
        "hook": "资本注入，每个平台都感兴趣",
        "goal_scripts": {
            "tech_stack": [
                "做投资尽调需要了解你们技术架构，是自研还是外购系统，DAU 大概多少",
                "你们系统是微服务还是单体架构，日活用户规模大概多少，服务器成本大致在什么量级",
            ],
        },
    },

    "compliance_consultant": {
        "name": "合规 / 牌照咨询",
        "category": "VIP",
        "need_match": ["license", "牌照", "合规", "监管", "compliance"],
        "ask_for": ["运营结构", "牌照情况", "合规需求"],
        "credibility": 3,
        "intro_variants": [
            "我们做博彩行业合规咨询，帮平台拿菲律宾 PAGCOR / 库拉索牌照，也帮做 AML 合规方案",
        ],
        "hook": "帮对方降低监管风险",
        "goal_scripts": {
            "tech_stack": [
                "合规审计需要了解你们系统架构，数据存储在哪个国家，有没有 KYC 流程",
            ],
        },
    },
}


# ══════════════════════════════════════════════════════════════════
#  目标分析器
# ══════════════════════════════════════════════════════════════════

def analyze_target(domain: str, keywords: list[str] = None) -> dict:
    """
    分析目标网站，判断适合用哪种身份接近。
    返回：目标特征 + 推荐身份排行
    """
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    sess.verify = False

    features = {
        "domain": domain,
        "has_payment": False,
        "has_agent": False,
        "has_game": False,
        "has_sports": False,
        "has_live": False,
        "has_api": False,
        "tech_stack_hints": [],
        "keywords_found": [],
        "tg_found": [],
        "extra_keywords": keywords or [],
    }

    # 抓首页分析关键词
    for scheme in ["https", "http"]:
        try:
            r = sess.get(f"{scheme}://{domain}", timeout=10, allow_redirects=True)
            body = r.text.lower()

            payment_kw = ["usdt", "payment", "充值", "提现", "存款", "取款", "支付"]
            agent_kw = ["代理", "affiliate", "partner", "推广", "返佣", "佣金"]
            game_kw = ["slot", "老虎机", "电子", "jackpot", "游戏", "game"]
            sports_kw = ["sports", "体育", "足球", "篮球", "赔率", "odds"]
            live_kw = ["live", "直播", "真人", "荷官", "dealer"]

            features["has_payment"] = any(k in body for k in payment_kw)
            features["has_agent"] = any(k in body for k in agent_kw)
            features["has_game"] = any(k in body for k in game_kw)
            features["has_sports"] = any(k in body for k in sports_kw)
            features["has_live"] = any(k in body for k in live_kw)

            # 技术栈提示
            if "laravel" in body or "x-powered-by: php" in str(r.headers).lower():
                features["tech_stack_hints"].append("PHP/Laravel")
            if "x-powered-by: express" in str(r.headers).lower():
                features["tech_stack_hints"].append("Node/Express")
            if "x-frame-options" in r.headers:
                features["tech_stack_hints"].append("有安全 header")
            if "__vue" in body or 'id="app"' in body:
                features["tech_stack_hints"].append("Vue.js")

            # TG 联系方式
            tg_matches = re.findall(r't\.me/([A-Za-z0-9_]+)', body)
            features["tg_found"] = list(set(tg_matches))[:5]

            # 关键词摘录
            for kw_list in [payment_kw, agent_kw, game_kw, sports_kw, live_kw]:
                features["keywords_found"].extend([k for k in kw_list if k in body])
            features["keywords_found"] = list(set(features["keywords_found"]))[:15]

            break
        except Exception:
            continue

    return features


def rank_identities(features: dict, goal: str = "agent_url") -> list[dict]:
    """
    根据目标特征，对身份库打分排序。
    goal: agent_url / api_doc / tech_stack
    """
    all_kw = (features.get("keywords_found", []) +
              features.get("extra_keywords", []) +
              [features["domain"]])
    kw_str = " ".join(all_kw).lower()

    scored = []
    for iid, identity in IDENTITIES.items():
        score = 0

        # 关键词匹配
        for kw in identity["need_match"]:
            if kw in kw_str:
                score += 2

        # 功能匹配加分
        if features.get("has_payment") and identity["category"] == "支付":
            score += 3
        if features.get("has_agent") and identity["category"] == "推广":
            score += 3
        if features.get("has_game") and identity["category"] == "内容":
            score += 2
        if features.get("has_sports") and "sports_data" == iid:
            score += 3
        if features.get("has_live") and "live_streaming" == iid:
            score += 3

        # 可信度加权
        score += identity["credibility"]

        # goal 支持加分
        if goal in identity.get("goal_scripts", {}):
            score += 2

        scored.append({
            "id": iid,
            "name": identity["name"],
            "category": identity["category"],
            "score": score,
            "credibility": identity["credibility"],
            "ask_for": identity["ask_for"],
            "hook": identity["hook"],
        })

    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[:8]


# ══════════════════════════════════════════════════════════════════
#  脚本生成器
# ══════════════════════════════════════════════════════════════════

def generate_script(identity_id: str, target: str = "目标平台",
                    goal: str = "agent_url", rounds: int = 5) -> dict:
    """生成完整多轮对话脚本"""
    identity = IDENTITIES.get(identity_id)
    if not identity:
        return {"error": f"未知身份: {identity_id}"}

    intro = random.choice(identity["intro_variants"])
    goal_lines = list(identity.get("goal_scripts", {}).get(goal, [
        "能发我一下后台链接吗，我让团队今天先进去注册看看"
    ]))

    # 第 2 轮：把 hook（价值主张）转化成对话用语
    hook_as_dialog = {
        "能带来真实用户和流水，是对方最想要的": "我们这边下面有几十个推广账号，能带真实充值用户，主要做 TG 群和线下渠道",
        "大额流水是每个平台都想要的": "我客户每个月充值量稳定，最少也在 50 万 U，在找一个出入金稳定的长期平台",
        "帮对方解决技术问题，省开发成本": "我们帮十几家平台做过对接，有现成的模块，接入周期比自研快 70%",
        "帮对方提高运营效率和玩家留存": "我们接入后平均帮平台把留存率提升了 15-20%，有几家平台的数据可以参考",
        "降低验证码成本，提升到达率": "我们东南亚方向的到达率在 97% 以上，比国内通道稳定很多，价格也低 30%",
    }.get(identity["hook"], identity["hook"])

    # 第 4 轮：深化信任，制造对方参与感
    trust_builders = [
        "我们之前合作的几个平台都跑了半年以上，我可以让他们帮我背书，你要不要联系一下他们",
        "我们这边流量稳定，上个月数据我可以截图给你，你看了觉得合适我们就推进",
        "我现在在对比你们和另外两家，你们返佣如果有优势我今天就定下来",
    ]

    # 第 5 轮：最终推进要链接
    closers = [
        "行，那我现在就让团队去注册，后台链接你直接发我",
        "可以，合作没问题，发我注册链接，我今天内让人跑起来",
        "我们就选你们了，后台入口发过来，我安排财务对接",
    ]

    conversation = [
        {
            "round": 1,
            "我": intro,
            "预期对方": "你们是做什么的 / 表示有兴趣 / 先了解一下",
            "note": "开场建立身份",
        },
        {
            "round": 2,
            "我": hook_as_dialog,
            "预期对方": "你们量多少 / 怎么合作 / 我们这边是怎么算佣金的",
            "note": "建立价值，让对方产生兴趣",
        },
        {
            "round": 3,
            "我": random.choice(goal_lines),
            "预期对方": "好的我发你 / 你先充值 / 要你们资质 / 我们的政策是...",
            "note": f"首次推进核心目标：{goal}",
        },
        {
            "round": 4,
            "我": random.choice(trust_builders),
            "预期对方": "可以 / 我们这边检查一下 / 好的等我确认",
            "note": "处理犹豫，加深信任",
        },
        {
            "round": 5,
            "我": random.choice(closers),
            "预期对方": "发出链接 / 安排对接",
            "note": "最终收口，拿到目标",
        },
    ]

    if rounds < 5:
        conversation = conversation[:rounds]

    return {
        "identity_id": identity_id,
        "identity_name": identity["name"],
        "target": target,
        "goal": goal,
        "conversation": conversation,
        "objection_handlers": identity.get("objection_handlers", {}),
        "adapt_prompts": [
            f"对方问量有多少 → 报可信数字：{random.randint(5,15)} 万 U/天 或 {random.randint(800,2000)} 笔/天",
            "对方要求先充值 → 推说财务要先审核后台界面，问能不能先看演示账号",
            "对方迟迟不给链接 → 制造紧迫感：我们今天还要看另外两家，你们能不能先发给我",
            "对方要加微信 → 说用 TG 方便，工作号在这里，继续在 TG 聊",
            "对方突然冷淡 → 换个角度切入：我们量变大了最近，佣金多给你们一点怎么样",
            "对方说已有合作了 → 不冲突，我们是补充合作，分流量到你们这边",
        ],
        "urgency_phrases": [
            "我今天要定下来，在对比几家",
            "我们老板催了，这周要启动",
            "现在有另一家也在等，你快点确认一下",
            "年底冲量期间，这个合作最好这两天搞定",
        ],
        "all_intros": identity["intro_variants"],
    }


def adapt_response(identity_id: str, last_message: str, goal: str = "agent_url") -> list[str]:
    """根据对方最新消息，生成最合适的下一句回应（覆盖 20+ 场景）"""
    identity = IDENTITIES.get(identity_id)
    if not identity:
        return [f"未知身份: {identity_id}"]

    msg_lower = last_message.lower()
    handlers = identity.get("objection_handlers", {})

    # ── 场景 1: 对方问量/规模
    if any(w in msg_lower for w in ["多少量", "流水", "多少笔", "规模", "每天", "每月"]):
        return [
            f"我们现在稳定在 {random.randint(5,15)} 万 U/天，高峰期能到 20 万",
            f"日均 {random.randint(800,2000)} 笔，周一到周五比较稳定",
            "量这个不好说，波动比较大，月均能有 200-300 万 U 吧",
        ]

    # ── 场景 2: 要资质/营业执照/公司注册
    if any(w in msg_lower for w in ["资质", "营业执照", "公司", "注册号", "税务"]):
        base = handlers.get("需要资质", "我们是个人团队，直接 USDT 结算，不走公司")
        return [
            base,
            "一般做这块的都是个人业务，你们平台这边接受 U 结算的吗",
            "资质后面可以补，先把业务跑起来，你发我个注册链接先",
        ]

    # ── 场景 3: 要求先充值/测试金/打款验证
    if any(w in msg_lower for w in ["充值", "先打款", "测试金", "验证一下", "押金"]):
        base = handlers.get("需要先充值", "充值之前财务需要先看一下后台界面，能先发链接吗")
        return [
            base,
            "我们不先充值，流程是先看后台功能，财务审核通过才开始跑量",
            "测试金这边没问题，但你先发代理后台链接，让我看看界面可不可以",
        ]

    # ── 场景 4: 对方拒绝/冷淡/说没兴趣
    if any(w in msg_lower for w in ["不合作", "没兴趣", "不需要", "不做", "不谈", "算了", "暂时不"]):
        return [
            "好的，那不打扰了，你这边以后有合适的项目可以联系我",
            "没关系，你有认识做这块的平台可以介绍吗，我们给介绍费",
            "理解，那我去看看其他家，如果以后有需要的话找我",
        ]

    # ── 场景 5: 对方给了链接 / 发过来了
    if any(w in msg_lower for w in ["后台", "链接", "注册", "http", "https", "login", "agent"]):
        goal_lines = list(identity.get("goal_scripts", {}).get(goal, []))
        return (goal_lines + ["收到，我让财务今天去注册，有问题再联系你"])[:3]

    # ── 场景 6: 讨论佣金/分成/返佣
    if any(w in msg_lower for w in ["三七", "四六", "二八", "返佣", "比例", "分成", "点位", "佣金"]):
        next_goal = list(identity.get("goal_scripts", {}).get(goal, []))
        return (next_goal[:1] if next_goal else []) + [
            "返佣比例可以接受，那下一步发我代理后台链接吧",
            "好，那就按这个比例来，你发我注册链接，我这边安排",
        ]

    # ── 场景 7: 对方在问你们渠道/来源/怎么拉流量
    if any(w in msg_lower for w in ["渠道", "来源", "流量", "怎么拉", "哪里来", "推广方式"]):
        return [
            "我们主要是 TG 群+线下，在东南亚有几个活跃的华人圈",
            "渠道多元，有直客也有下级代理，主要集中在马来和泰国方向",
            "我们不做广告，全靠口碑和老客介绍，质量比买流量好很多",
        ]

    # ── 场景 8: 对方要加微信/QQ/其他联系方式
    if any(w in msg_lower for w in ["微信", "wechat", "qq", "加一下", "加你", "联系方式", "电话"]):
        return [
            "用 TG 就行，工作都在这里，微信容易被封，不方便",
            "TG 这边我比较活跃，微信基本不用了，有事直接这里聊",
            "加微信不方便，TG 就好，我这个账号一直在线",
        ]

    # ── 场景 9: 对方说已经有合作了/不差这个
    if any(w in msg_lower for w in ["已经有", "已有合作", "不缺", "现在有了", "合作了"]):
        return [
            "没问题，不冲突，我们是补量的，不占你们现有渠道份额",
            "我们可以作为备用，流量多的时候分过来，你们也不亏",
            "了解，那能不能把你们后台发我，我先了解一下平台，说不定以后有机会",
        ]

    # ── 场景 10: 对方说要等/要问上级/要汇报
    if any(w in msg_lower for w in ["等一下", "问一下", "汇报", "确认", "回复你", "等我"]):
        return [
            "好的，不急，我这边等你消息",
            "没问题，你确认好了通知我，我这边在等",
            "好，你问完了发我，顺便把后台链接一起发过来方便我了解",
        ]

    # ── 场景 11: 对方问你的 TG/身份/怎么证明
    if any(w in msg_lower for w in ["谁介绍", "哪里来的", "你是谁", "证明", "认识谁", "信任"]):
        credibility_map = {
            1: "我是自己找过来的，看你们平台不错，想谈合作",
            3: "我在几个群里看到你们的，有几个做这块的朋友也提过你们",
            5: "我们是行业内做了几年的，同行都知道，你可以问一下圈子里的人",
        }
        cred = identity.get("credibility", 3)
        base = credibility_map.get(min(cred, 5), credibility_map[3])
        return [
            base,
            "我是通过内部渠道找到你们的，一般不对外介绍，你放心",
            "没有特别的介绍人，就是看你们业务方向合适，直接过来谈",
        ]

    # ── 场景 12: 对方给出条件 / 报价
    if any(w in msg_lower for w in ["条件", "要求", "政策", "我们这边是", "规定"]):
        return [
            "条件可以接受，那下一步发我后台链接，我让财务今天进去看看",
            "好，按你说的来，发我注册入口，我这边安排操作",
            "明白，我们就按这个来，你发我代理后台，我注册一个先",
        ]

    # ── 场景 13: 对方问你做了多久/经验如何
    if any(w in msg_lower for w in ["多久", "几年", "经验", "做过哪些", "以前"]):
        return [
            f"这个方向做了 {random.randint(3,6)} 年了，见过很多平台",
            "做这块时间不短了，合法合规的我都做过，也踩过坑，现在比较谨慎",
            "从 2020 年开始就在做了，各种类型的平台都合作过",
        ]

    # ── 场景 14: 对方说在忙/稍后联系
    if any(w in msg_lower for w in ["忙", "待会", "明天", "改天", "稍后", "晚点"]):
        return [
            "好，不打扰，我明天再来找你",
            "没问题，那你方便的时候发我一下后台链接",
            "行，我等你，有空了咱们再聊",
        ]

    # ── 场景 15: 对方说平台在维护/暂时没开放
    if any(w in msg_lower for w in ["维护", "暂停", "下线", "没开放", "内测"]):
        return [
            "了解，那你们什么时候开放，我先了解一下你们后台结构",
            "维护期间也可以先发我注册链接，我注册好等开放了直接跑",
            "好，你什么时候完工了通知我，顺便把代理链接发过来",
        ]

    # ── 默认：通用推进
    return [
        "明白，那我们这边继续聊，你们代理后台注册链接能发我一下吗",
        "好，我这边跟团队确认一下，先发我后台链接，让财务看看界面",
        "我需要一个能看数据的账号，你们代理后台在哪注册",
    ]


# ══════════════════════════════════════════════════════════════════
#  命令入口
# ══════════════════════════════════════════════════════════════════

def cmd_list(args: argparse.Namespace) -> int:
    """列出所有可用身份"""
    cats = {}
    for iid, identity in IDENTITIES.items():
        cat = identity["category"]
        cats.setdefault(cat, []).append((iid, identity))

    print(f"\n可用身份库（共 {len(IDENTITIES)} 种）\n")
    for cat, items in cats.items():
        print(f"  ── {cat} ──")
        for iid, identity in items:
            stars = "★" * identity["credibility"]
            ask = " / ".join(identity["ask_for"][:2])
            print(f"  {iid:<22} {stars:<5}  {identity['name']}  → 能要到: {ask}")
        print()
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    """分析目标，推荐最适合的身份"""
    domain = args.domain
    goal = args.goal

    print(f"\n[*] 分析目标: {domain}  目标: {goal}")
    kw = [k.strip() for k in args.keywords.split(",")] if args.keywords else []
    features = analyze_target(domain, kw)

    print("\n  特征识别:")
    print(f"    有支付功能: {'是' if features['has_payment'] else '否'}")
    print(f"    有代理体系: {'是' if features['has_agent'] else '否'}")
    print(f"    有游戏内容: {'是' if features['has_game'] else '否'}")
    print(f"    有体育投注: {'是' if features['has_sports'] else '否'}")
    print(f"    有真人直播: {'是' if features['has_live'] else '否'}")
    print(f"    TG 联系方式: {features['tg_found'] or '未发现'}")
    print(f"    技术栈提示: {features['tech_stack_hints'] or '未知'}")

    ranked = rank_identities(features, goal)
    print(f"\n  推荐身份排行（按目标 {goal} 匹配度）:\n")
    for i, item in enumerate(ranked[:5], 1):
        stars = "★" * item["credibility"]
        print(f"  {i}. [{item['id']}]")
        print(f"     {item['name']}  {stars}  分类: {item['category']}")
        print(f"     价值主张: {item['hook']}")
        print(f"     能要到: {', '.join(item['ask_for'])}")
        print()

    print("  快速生成脚本:")
    print(f"    python3 {__file__} script --id {ranked[0]['id']} --target {domain} --goal {goal}")

    return 0


def cmd_script(args: argparse.Namespace) -> int:
    """生成指定身份的完整对话脚本"""
    rounds = getattr(args, "rounds", 5)
    script = generate_script(args.id, args.target, args.goal, rounds=rounds)
    if "error" in script:
        print(f"[!] {script['error']}")
        print(f"    可用 ID: {', '.join(IDENTITIES.keys())}")
        return 1

    identity = IDENTITIES[args.id]
    print(f"\n{'='*65}")
    print(f"  社工对话脚本  —  {script['identity_name']}")
    print(f"  目标: {args.target}  目标: {args.goal}  轮次: {rounds}")
    print(f"{'='*65}")

    for turn in script["conversation"]:
        print(f"\n  [第 {turn['round']} 轮]  {turn['note']}")
        print(f"  我   → {turn['我']}")
        print(f"  预期 → {turn['预期对方']}")

    if script["objection_handlers"]:
        print("\n  异议处理:")
        for obj, resp in script["objection_handlers"].items():
            print(f"    [{obj}]")
            print(f"      {resp}")

    print("\n  临机应变提示:")
    for tip in script["adapt_prompts"]:
        print(f"    · {tip}")

    print("\n  制造紧迫感（对方拖延时用）:")
    for phrase in script.get("urgency_phrases", []):
        print(f"    · {phrase}")

    print("\n  开场话术变体（随机选一个）:")
    for i, v in enumerate(identity["intro_variants"], 1):
        print(f"    {i}. {v}")

    return 0


def cmd_urgency(args: argparse.Namespace) -> int:
    """生成催促/紧迫感话术（当对方迟迟不给链接/不推进时）"""
    urgency_bank = [
        # 竞争压力型
        "我今天还要看另外两家，你们这边能不能快点确认",
        "我们老板催了，这周要定下来，不然预算给别的项目了",
        "另一家已经在谈了，你们今天不确认我就过去了",
        "现在有三家在竞争，你们平台我最先联系的，给你们优先",
        # 时间压力型
        "年底冲量季节，现在晚一周就少跑一周，发我链接吧",
        "我这边资金今天到位了，今晚就可以开始，你快点发",
        "我团队今天下午空档，你发链接我让他们直接去注册",
        # 假装要走型
        "算了，我去找 XX 平台了，他们已经发我链接了",
        "你们响应太慢了，我对接其他家了，拜拜",  # 然后等对方挽留
        # 内部审批借口型
        "我老板明天要看，今天你把链接发我，我准备材料",
        "财务说今天要对账，你把代理链接发过来我现在操作",
    ]

    identity_id = getattr(args, "id", None)
    if identity_id:
        identity = IDENTITIES.get(identity_id, {})
        extra = identity.get("objection_handlers", {})
        print(f"\n[{identity.get('name', identity_id)}] 催促话术:\n")
    else:
        print("\n通用催促话术（对方不推进时用）:\n")
        extra = {}

    for phrase in urgency_bank:
        print(f"  · {phrase}")

    if extra:
        print("\n  身份专用异议话术:")
        for obj, resp in extra.items():
            print(f"  [{obj}] → {resp}")

    return 0


def cmd_adapt(args: argparse.Namespace) -> int:
    """根据对方最新消息，生成下一句回应"""
    responses = adapt_response(args.id, args.history, args.goal)
    identity = IDENTITIES.get(args.id, {})
    print(f"\n  [{identity.get('name', args.id)}] 对方说: 「{args.history}」")
    print("  建议回应（选一个）:\n")
    for i, r in enumerate(responses, 1):
        print(f"  {i}. {r}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """完整流程：分析 → 推荐 → 生成脚本"""
    domain = args.domain
    goal = args.goal
    kw = [k.strip() for k in args.keywords.split(",")] if args.keywords else []

    print(f"\n[*] 完整社工方案生成: {domain}")
    features = analyze_target(domain, kw)
    ranked = rank_identities(features, goal)

    if not ranked:
        print("[-] 无法推荐身份")
        return 1

    top = ranked[0]
    print(f"\n[推荐] 最佳身份: {top['name']}  (id: {top['id']})")
    script = generate_script(top["id"], domain, goal)

    print(f"\n{'='*65}")
    print("  对话脚本")
    print(f"{'='*65}")
    for turn in script["conversation"]:
        print(f"\n  我: {turn['我']}")
        print(f"  （{turn['note']}）")

    print(f"\n{'='*65}")
    print("  异议处理 & 应变提示")
    print(f"{'='*65}")
    for obj, resp in script.get("objection_handlers", {}).items():
        print(f"  Q: {obj}\n  A: {resp}\n")
    for tip in script.get("adapt_prompts", []):
        print(f"  · {tip}")

    if features["tg_found"]:
        print(f"\n  TG 接触点: {' | '.join('https://t.me/' + t for t in features['tg_found'])}")

    return 0


def main():
    ap = argparse.ArgumentParser(
        description="social_engineer_agent — 博彩站社工身份动态生成器（授权范围内）"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="列出所有可用身份").set_defaults(func=cmd_list)

    p = sub.add_parser("analyze", help="分析目标，推荐最佳身份")
    p.add_argument("-d", "--domain", required=True)
    p.add_argument("--goal", default="agent_url",
                   help="目标: agent_url/api_doc/tech_stack（默认 agent_url）")
    p.add_argument("--keywords", default="", help="补充关键词（逗号分隔）")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("script", help="生成指定身份的完整对话脚本")
    p.add_argument("--id", required=True, help="身份 ID（见 list 命令）")
    p.add_argument("--target", default="目标平台", help="目标名称")
    p.add_argument("--goal", default="agent_url")
    p.add_argument("--rounds", type=int, default=5, help="生成轮次（默认 5）")
    p.set_defaults(func=cmd_script)

    p = sub.add_parser("adapt", help="根据对方消息，生成下一句回应")
    p.add_argument("--id", required=True, help="当前使用的身份 ID")
    p.add_argument("--history", required=True, help="对方最新消息")
    p.add_argument("--goal", default="agent_url")
    p.set_defaults(func=cmd_adapt)

    p = sub.add_parser("urgency", help="生成催促/紧迫感话术（对方不给链接时）")
    p.add_argument("--id", default=None, help="可选：当前身份 ID（加载专用异议话术）")
    p.set_defaults(func=cmd_urgency)

    p = sub.add_parser("run", help="完整流程：分析目标 → 推荐身份 → 生成脚本")
    p.add_argument("-d", "--domain", required=True)
    p.add_argument("--goal", default="agent_url")
    p.add_argument("--keywords", default="")
    p.set_defaults(func=cmd_run)

    args = ap.parse_args()
    sys.exit(args.func(args) or 0)


if __name__ == "__main__":
    main()
