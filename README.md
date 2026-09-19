# 企业客服 Agent 身份与信任安全验证靶场

以真实 OAuth 授权服务（Keycloak）与真实大模型（DeepSeek）驱动的客服/退款双 Agent 业务为场景，
验证 Agent 身份认证、任务授权、委托审批、凭据盗用与提示注入防护的可运行靶场。

> 投递阅读入口：[`docs/00-投递包导读.md`](docs/00-投递包导读.md)（一页介绍 → 视频 → 验证报告 → 本文）
> 新手全景导读（不读代码看懂全项目）：[`小白导读-项目全景图.html`](小白导读-项目全景图.html)

## 组成

| 组件 | 端口 | 说明 |
| --- | --- | --- |
| backend | 8000 | 可信后台：用户登录、任务授权创建、审批、演示 UI（http://127.0.0.1:8000） |
| agent_customer | 8100 | 客服 Agent：DeepSeek 工具调用循环，订单查询/资料检索/消息发送 |
| agent_refund | 8200 | 退款 Agent：受限子任务内执行模拟退款 |
| tools | 8300 | 受保护工具服务：JWT 验签、scope、任务授权、对象归属、出站控制 |
| Keycloak | 8080 | OAuth 授权服务，realm `agent-range`，client_credentials 流程（RFC 6749 §4.4） |

业务主线：客服查询订单 → 用户确认敏感参数创建任务授权 → Agent 以自身客户端凭据取令牌 →
携带令牌+任务凭据调用工具 → 委托退款 Agent → 审批人批准 → 受限执行 → 全程审计。

## 环境要求

- Windows + PowerShell 5（脚本基于本机端口管理）
- JDK 17（运行 `auth-server\` 下 Keycloak 26.7.4 独立进程，需自行安装；
  `start-keycloak.ps1` 默认在 `C:\Program Files\Java\jdk*` 查找，其余路径需改脚本）
- Python 3.11+（`python -m venv .venv` 后 `pip install -r requirements.txt`）
- DeepSeek API Key（真实模型实验用；缺失时自动回退固定解析模式，页面明确标注）

## 快速启动

```powershell
# 1) 配置私密环境变量（首次）：复制 .env.example 为 .env 并填写
#    DEEPSEEK_API_KEY / KC_ADMIN_PASSWORD（Agent 客户端密钥留 changeme 即可，下一步自动生成）
copy .env.example .env

# 2) 首次启动 Keycloak（bootstrap 管理员来自 .env 的 KC_ADMIN_*）
powershell -ExecutionPolicy Bypass -File scripts\start-keycloak.ps1

# 3) 初始化 realm（幂等可重跑）：创建 realm/客户端/scope，
#    .env 中客户端密钥为占位符时自动生成随机密钥写回
.venv\Scripts\python.exe scripts\setup_keycloak.py

# 4) 启动四服务（幂等：Keycloak 已运行自动跳过）
powershell -ExecutionPolicy Bypass -File scripts\start-all.ps1

# 5) 打开演示 UI
start http://127.0.0.1:8000
```

测试账号（虚构数据）：`alice / alice123`、`bob / bob123`（两组数据权限）、审批人 `carol / carol123`。

首次启动会自动生成 `INTERNAL_API_KEY` 追加到 `.env`（服务间内部通道认证，勿分发）。

## OAuth 客户端注册与初始化

由 `scripts\setup_keycloak.py` 幂等完成，可重复运行：

- realm `agent-range`，两个独立客户端：`customer-service-agent`（scope：order.read / docs.read / message.send）、
  `refund-agent`（scope：refund.execute）
- 客户端认证方式 `client_secret_basic`；签发 RS256 短期 JWT（300 秒，audience `tools-service`，
  经客户端协议映射注入）
- 工具服务通过 JWKS（`/realms/agent-range/protocol/openid-connect/certs`）在线验签，
  校验 iss / aud / exp / 签名算法，并叠加应用侧 Agent 准入状态在线核验

可信配置（issuer / audience / scope 映射）均由 `.env` 注入，样例见 `.env.example`；
**样例不含任何真实密钥**，`.env` 已被 `.gitignore` 排除。

## 验收脚本（可重复运行）

```powershell
.venv\Scripts\python.exe scripts\verify_deepseek.py        # 环境自检：DeepSeek API 连通（列模型+一次最小请求）
.venv\Scripts\python.exe scripts\verify_oauth_minimal.py    # 阶段0：OAuth 组件行为 V1-V7
.venv\Scripts\python.exe scripts\verify_auth_phase1.py      # 阶段1：AUTH-01~10/12/13 固定回放
.venv\Scripts\python.exe scripts\verify_auth_phase2.py      # 阶段2：委托链/审批/幂等/CRED-01~04
.venv\Scripts\python.exe scripts\verify_risk_phase3.py      # 阶段3：RISK-01/03/04 固定回放+真实模型批次
# 常用参数：--no-llm 仅固定回放；--smoke 模型批次各1次；--runs N 自定义批次次数
# 单案例复现（逐步输出操作过程与判定，不覆盖报告）：--case AUTH-08 / --case RISK-01-F / --case R1-RISK --runs 1；--list 查看全部可用编号
```

报告输出至 `reports\`：`component-behavior.md`、`auth-phase1.md`、`auth-phase2.md`、`risk-phase3.md`。
逐用例复现步骤与预期输出见 [docs/08-验证复现手册.md](docs/08-验证复现手册.md)。

阶段 1/2 脚本运行期间自动锁定固定解析模式（`agent_mode=fixed`），退出时恢复，避免模型波动影响回归。

## 运维

```powershell
powershell -ExecutionPolicy Bypass -File scripts\stop-all.ps1                 # 停四服务（-IncludeKeycloak 同时停 8080）
powershell -ExecutionPolicy Bypass -File scripts\reset-data.ps1               # 重置实验数据（保留 Keycloak 配置）
```

- 日志：`data\logs\*.log`
- 出站证据：`data\experiments\outbound_evidence.jsonl`（模型请求与消息发送的实际出站记录）
- 实验配置开关（默认全防护）：`http://127.0.0.1:8100/api/experiment/config` 与 `:8300`（仅 UI 内实验面板或内部密钥通道可改）

## 目录结构

```
agent-security-range/
├── auth-server/          # Keycloak 26.7.4（Maven Central 发行包，JDK17 运行）
├── services/
│   ├── backend/          # FastAPI：任务授权/审批/会话 + static/ 演示 UI
│   ├── agent_customer/   # 客服 Agent 服务
│   ├── agent_refund/     # 退款 Agent 服务
│   └── tools/            # 工具服务（受保护资源）
├── shared/               # 公共运行时：JWT 客户端、任务凭据、LLM 出站适配层、实验配置
├── scripts/              # 启停/重置/初始化/验收脚本
├── docs/                 # 投递文档（导读/一页介绍/视频脚本/方案/报告总览/演示步骤/贡献说明）
├── reports/              # 各阶段验收报告
└── data/                 # SQLite 数据、日志、实验证据（运行时生成）
```

## 已知边界（如实声明）

- 传输保护未完成：本地演示使用回环 HTTP（127.0.0.1），未配置 TLS；不能视为生产接入形态
- OIDC 用户登录未实现：用户使用本地账号会话，与 Agent 的 OAuth 客户端认证相互独立
- RISK-02/05/06（跨部门串话、存储运维泄露、委托上下文最小化）为第二阶段范围，本版未实现
- 提示过滤与脱敏有覆盖范围（当前为虚构手机号标记字段），不能宣称防住所有变体
- 模型实验结论仅代表本次样例、配置与运行范围内的观察（deepseek-flash，temperature=0，各场景 10 次）
