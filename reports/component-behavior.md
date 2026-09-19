# OAuth 组件行为记录（阶段 0 验证）

- 日期: 2026-09-17T00:46:58
- 组件: Keycloak 独立进程（非 Docker），来源 Maven Central keycloak-quarkus-dist
- 流程: client_credentials（RFC 6749 4.4），客户端认证 client_secret_basic
- 端点: issuer=http://127.0.0.1:8080/realms/agent-range, token=http://127.0.0.1:8080/realms/agent-range/protocol/openid-connect/token, jwks=http://127.0.0.1:8080/realms/agent-range/protocol/openid-connect/certs
- audience: tools-service（客户端协议映射注入）

| 编号 | 验证项 | 结果 | 关键观察 |
| --- | --- | --- | --- |
| V1 | 服务与端点发现 | PASS | Keycloak 版本: 26.7.4<br>issuer: http://127.0.0.1:8080/realms/agent-range<br>token_endpoint: http://127.0.0.1:8080/realms/agent-range/protocol/openid-connect/token<br>jwks_uri: http://127.0.0.1:8080/realms/agent-range/protocol/openid-connect/certs |
| V2 | 两个 Agent 客户端凭据取令牌 | PASS | customer-service-agent: HTTP 200, token_type=Bearer, expires_in=300, 请求scope='order.read docs.read'<br>refund-agent: HTTP 200, token_type=Bearer, expires_in=300, 请求scope='refund.execute' |
| V3 | JWKS 验签 + iss/aud 校验 | PASS | customer-service-agent: 验签通过 alg=RS256 typ=JWT | sub=2f9600f4-995… azp=customer-service-agent | scope='email profile docs.read order.read' | aud=['tools-service', 'account'] | 有效期=300s<br>refund-agent: 验签通过 alg=RS256 typ=JWT | sub=22fa13af-2ec… azp=refund-agent | scope='email profile refund.execute' | aud=['tools-service', 'account'] | 有效期=300s |
| V4 | 错误客户端密钥申请令牌 | PASS | HTTP 401, error=unauthorized_client, error_description=Invalid client or Invalid client credentials |
| V5 | 超范围 scope 请求行为 | PASS | HTTP 400<br>error=invalid_scope, error_description=Invalid scopes: order.read refund.execute<br>结论: 组件采用【拒绝】方式 |
| V6 | 令牌过期行为 | PASS | realm 寿命临时调为 5s 后取令牌: exp-iat=5s<br>等待 7s 后验签: ExpiredSignatureError（过期拒绝）<br>realm 令牌寿命已恢复 300s |
| V7 | 客户端停用行为 | PASS | 停用后新令牌申请: HTTP 401（预期 401 invalid_client）<br>停用前签发的未过期令牌: 验签仍通过（签名层不感知停用状态）<br>含义: 撤销必须依赖应用侧在线状态检查，仅靠验签无法感知 —— 支撑需求稿 6.6 的设计<br>重新启用后取令牌: HTTP 200 |

## 对靶场设计的影响

1. 超范围 scope 的实际处理方式以 V5 记录为准，AUTH-06 验收预期据此固定。
2. 停用客户端后旧令牌验签仍通过（V7），证实需求稿 6.6 的结论：撤销需要应用侧在线状态检查，工具服务执行前必须查询应用授权状态。
3. JWKS 地址来自固定可信配置（issuer 派生），不接受令牌内 URL；PyJWKClient 自带密钥缓存，验签失败即拒绝。
4. 本记录为实际运行观察，非组件文档转述；后续 AUTH 实验的失败预期均以本文件为依据。